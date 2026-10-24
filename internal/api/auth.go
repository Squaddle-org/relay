package api

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/squaddle-org/relay/internal/proto"
)

const authWindow = 60 * time.Second

type ctxKey int

const deviceKeyCtxKey ctxKey = iota

// DeviceKeyFromContext returns the Ed25519 device public key the request-auth middleware
// verified for this request. Only meaningful on routes wrapped with requestAuth.
func DeviceKeyFromContext(ctx context.Context) []byte {
	k, _ := ctx.Value(deviceKeyCtxKey).([]byte)
	return k
}

// replayCache rejects a signature seen more than once within the auth window (PROTOCOL.md §5:
// "replays within the window (nonce cache keyed by sig)"). Swept lazily on each check - request
// volume per relay process is low enough that a full map scan per request is fine; a background
// sweep goroutine isn't needed at this scale.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newReplayCache() *replayCache { return &replayCache{seen: map[string]time.Time{}} }

func (c *replayCache) checkAndRemember(sig []byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, t := range c.seen {
		if now.Sub(t) > authWindow {
			delete(c.seen, k)
		}
	}
	key := string(sig)
	if _, exists := c.seen[key]; exists {
		return false
	}
	c.seen[key] = now
	return true
}

// requestAuth is PROTOCOL.md §5: verifies the Authorization header against the device public
// key *named in that header itself* - self-certifying, so no store lookup is needed to validate
// the signature (deliberately: PUT /users/{user}/devices/{device} must work for a device that
// isn't registered yet). This only proves "a real device key signed this exact HTTP request,
// recently, once" - it is a transport-level anti-tamper/anti-replay check, not a business
// authorization decision. Handlers that need to know whether that device/user may actually
// perform the requested action (e.g. is this user a room admin) check that separately against
// the store - the signed structures in the body (DeviceCert, LogEntry, DeviceRevoke) carry their
// own, independent authorization.
func requestAuth(replay *replayCache, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deviceB64, ts, sigB64, ok := parseAuthHeader(r.Header.Get("Authorization"))
		if !ok {
			writeError(w, http.StatusUnauthorized, "bad_signature", "missing or malformed Authorization header")
			return
		}
		device, err := base64.RawURLEncoding.DecodeString(deviceB64)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "bad_signature", "bad device key encoding")
			return
		}
		sig, err := base64.RawURLEncoding.DecodeString(sigB64)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "bad_signature", "bad signature encoding")
			return
		}
		tsUnix, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "bad_signature", "bad timestamp")
			return
		}
		now := time.Now()
		if absInt64(now.Unix()-tsUnix) > int64(authWindow.Seconds()) {
			writeError(w, http.StatusUnauthorized, "bad_signature", "timestamp outside the 60s window")
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", "cannot read body")
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(strings.NewReader(string(body)))

		reqLine := r.Method + "\n" + r.URL.RequestURI() + "\n" + ts + "\n"
		signingInput := proto.SigningInput("req", append([]byte(reqLine), proto.Blake2b256(body)...))

		if !proto.Ed25519Verify(device, signingInput, sig) {
			writeError(w, http.StatusUnauthorized, "bad_signature", "signature does not verify")
			return
		}
		if !replay.checkAndRemember(sig, now) {
			writeError(w, http.StatusUnauthorized, "bad_signature", "replayed request")
			return
		}

		next(w, r.WithContext(context.WithValue(r.Context(), deviceKeyCtxKey, device)))
	}
}

// parseAuthHeader parses "SQDL1 device=<b64>, ts=<unix>, sig=<b64>" (PROTOCOL.md §5).
func parseAuthHeader(h string) (device, ts, sig string, ok bool) {
	const prefix = "SQDL1 "
	if !strings.HasPrefix(h, prefix) {
		return "", "", "", false
	}
	vals := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(h, prefix), ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			return "", "", "", false
		}
		vals[kv[0]] = kv[1]
	}
	device, ok1 := vals["device"]
	ts, ok2 := vals["ts"]
	sig, ok3 := vals["sig"]
	if !ok1 || !ok2 || !ok3 {
		return "", "", "", false
	}
	return device, ts, sig, true
}

func absInt64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
