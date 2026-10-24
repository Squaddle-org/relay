package api

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/squaddle-org/relay/internal/store"
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

// pushPayload is PROTOCOL.md §6: `{"r":"<b32 roomId>","c":<cursor>}` - no content, no author.
type pushPayload struct {
	Room   string `json:"r"`
	Cursor int64  `json:"c"`
}

// roomRefBase32 is PROTOCOL.md §3.1's display convention ("base32 (RFC 4648, lowercase, no
// padding)"), reused here since §6's wake-up payload names the room the same way external refs
// do.
func roomRefBase32(roomID []byte) string {
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(roomID))
}

// pushNotifier is PROTOCOL.md §6: on new ops/log entries, POST a content-free wake-up to every
// current member device's registered UnifiedPush endpoint, debounced 30s per (endpoint, room).
type pushNotifier struct {
	client *http.Client
	mu     sync.Mutex
	last   map[string]time.Time // key: endpoint + "\x00" + string(roomID)
}

func newPushNotifier() *pushNotifier {
	return &pushNotifier{client: &http.Client{Timeout: 5 * time.Second}, last: map[string]time.Time{}}
}

func (n *pushNotifier) notify(st *store.Store, roomID []byte, cursor int64) {
	endpoints, err := st.ListPushEndpointsForRoom(roomID)
	if err != nil || len(endpoints) == 0 {
		return
	}
	payload, err := json.Marshal(pushPayload{Room: roomRefBase32(roomID), Cursor: cursor})
	if err != nil {
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
		go n.send(endpoint, payload)
	}
}

func (n *pushNotifier) send(endpoint string, payload []byte) {
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}
