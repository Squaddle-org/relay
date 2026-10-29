package api

import (
	"crypto/ecdsa"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/squaddle-org/relay/internal/store"
	"github.com/squaddle-org/relay/internal/webpush"
)

// postPushRegister is `POST /v1/push`.
func postPushRegister(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		device := DeviceKeyFromContext(r.Context())
		var body struct {
			Endpoint string `json:"endpoint"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Endpoint == "" {
			writeError(w, http.StatusBadRequest, "invalid", "missing endpoint")
			return
		}
		if err := st.PutPushEndpoint(device, body.Endpoint); err != nil {
			writeError(w, http.StatusInternalServerError, "invalid", "store error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// deletePushRegister is `DELETE /v1/push`.
func deletePushRegister(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		device := DeviceKeyFromContext(r.Context())
		if err := st.DeletePushEndpoint(device); err != nil {
			writeError(w, http.StatusInternalServerError, "invalid", "store error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// getVapidPublicKey is `GET /v1/push/vapid` - unauthenticated, like `/healthz` (relay-api.yaml,
// ADR-0013). `vapidPub` is "" when the relay was started without a VAPID key (push disabled);
// callers get a 404 rather than an empty/misleading key in that case.
func getVapidPublicKey(vapidPub string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if vapidPub == "" {
			writeError(w, http.StatusNotFound, "not_found", "push is not configured on this relay")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"publicKey": vapidPub})
	}
}

// roomRefBase32 is PROTOCOL.md §3.1's display convention ("base32 (RFC 4648, lowercase, no
// padding)") - used by ws.go's WS fanout event, kept here since this is where it's always lived.
func roomRefBase32(roomID []byte) string {
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(roomID))
}

// pushNotifier is PROTOCOL.md §6: on new ops/log entries, sends a genuinely empty-body Web Push
// (RFC 8030) wake-up, VAPID-authenticated (RFC 8292, ADR-0013), to every current member device's
// registered endpoint, debounced 30s per (endpoint, room). `vapidKey` nil means push wasn't
// configured at startup (`-vapid-private-key-file` unset) - `notify` becomes a silent no-op in
// that case, same as having zero registered endpoints; this is a deliberately permissive
// default (plenty of self-hosted relays won't care about push at all), not an error.
type pushNotifier struct {
	client   *http.Client
	vapidKey *ecdsa.PrivateKey
	vapidPub string

	mu   sync.Mutex
	last map[string]time.Time // key: endpoint + "\x00" + string(roomID)

	jwtMu    sync.Mutex
	jwtCache map[string]cachedJWT // keyed by aud (the push endpoint's origin)
}

type cachedJWT struct {
	token string
	exp   time.Time
}

// vapidJWTTTL is comfortably under RFC 8292's own 24h ceiling; cached per-aud and re-signed once
// it's within a minute of expiry, so a busy relay isn't signing a fresh JWT on every single push.
const vapidJWTTTL = 12 * time.Hour

// vapidContactURI is the `sub` claim (RFC 8292 §2) - a contact a push service operator can use
// if this sender needs to be reached about abusive traffic.
const vapidContactURI = "mailto:security@squaddle.org"

func newPushNotifier(vapidKey *ecdsa.PrivateKey) *pushNotifier {
	n := &pushNotifier{
		client:   &http.Client{Timeout: 5 * time.Second},
		vapidKey: vapidKey,
		last:     map[string]time.Time{},
		jwtCache: map[string]cachedJWT{},
	}
	if vapidKey != nil {
		n.vapidPub = webpush.PublicKeyBase64URL(&vapidKey.PublicKey)
	}
	return n
}

// notify debounces per (endpoint, room) - cursor is accepted for the caller's convenience
// (postLog/postOps already have it to hand) but never leaves this process: the push itself
// carries no room id, no cursor, nothing (§6 - a content-free wake-up by design).
func (n *pushNotifier) notify(st *store.Store, roomID []byte, cursor int64) {
	if n.vapidKey == nil {
		return
	}
	endpoints, err := st.ListPushEndpointsForRoom(roomID)
	if err != nil || len(endpoints) == 0 {
		return
	}
	now := time.Now()
	roomKey := string(roomID)
	for _, endpoint := range endpoints {
		key := endpoint + "\x00" + roomKey
		n.mu.Lock()
		last, seen := n.last[key]
		if seen && now.Sub(last) < 30*time.Second {
			n.mu.Unlock()
			continue
		}
		n.last[key] = now
		n.mu.Unlock()
		go n.send(endpoint)
	}
}

func (n *pushNotifier) jwtFor(aud string, now time.Time) (string, error) {
	n.jwtMu.Lock()
	defer n.jwtMu.Unlock()
	if cached, ok := n.jwtCache[aud]; ok && now.Before(cached.exp.Add(-1*time.Minute)) {
		return cached.token, nil
	}
	token, err := webpush.SignJWT(n.vapidKey, aud, vapidContactURI, now, vapidJWTTTL)
	if err != nil {
		return "", err
	}
	n.jwtCache[aud] = cachedJWT{token: token, exp: now.Add(vapidJWTTTL)}
	return token, nil
}

func (n *pushNotifier) send(endpoint string) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return
	}
	aud := parsed.Scheme + "://" + parsed.Host
	token, err := n.jwtFor(aud, time.Now())
	if err != nil {
		return
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, http.NoBody)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", fmt.Sprintf("vapid t=%s, k=%s", token, n.vapidPub))
	req.Header.Set("TTL", strconv.Itoa(60)) // RFC 8030 §5.2 - how long the push service may hold this before giving up
	req.ContentLength = 0
	resp, err := n.client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}
