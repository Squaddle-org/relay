package api

import (
	"context"
	"encoding/base32"
	"net/http"
	"strings"
	"sync"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/squaddle-org/relay/internal/store"
)

// decodeRoomRefBase32 is the reverse of roomRefBase32 (push.go) - the WS subscribe message names
// rooms the same way the push wake-up and PROTOCOL.md §3.1's RoomRef display convention do.
func decodeRoomRefBase32(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(s))
}

// wsClient is one connected, possibly multi-room-subscribed WebSocket client.
type wsClient struct {
	send chan wsEvent
}

// wsEvent is PROTOCOL.md §6's shape reused for live push: `{"r":"<b32 roomId>","c":<cursor>,
// "k":"ops|log"}`.
type wsEvent struct {
	Room   string `json:"r"`
	Cursor int64  `json:"c"`
	Kind   string `json:"k"`
}

// wsHub is a simple in-process pub/sub: one hub per relay process, rooms keyed by raw room id
// bytes, fanning out to every subscribed connection. No cross-process coordination - fine for a
// single relay instance (ADR-0010's StatefulSet is single-replica: "SQLite. Scale-out = later").
type wsHub struct {
	mu   sync.Mutex
	subs map[string]map[*wsClient]bool // string(roomID) -> subscribed clients
}

func newWsHub() *wsHub { return &wsHub{subs: map[string]map[*wsClient]bool{}} }

func (h *wsHub) subscribe(roomID []byte, c *wsClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := string(roomID)
	if h.subs[key] == nil {
		h.subs[key] = map[*wsClient]bool{}
	}
	h.subs[key][c] = true
}

func (h *wsHub) unsubscribeAll(c *wsClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for key, set := range h.subs {
		delete(set, c)
		if len(set) == 0 {
			delete(h.subs, key)
		}
	}
}

// broadcast fans an event out to every client subscribed to roomID. A slow client's buffered
// channel filling up drops the event for that client rather than blocking every other
// broadcast - a missed live wake-up is harmless, the client's regular GET /log or /ops poll (or
// UnifiedPush) still catches up.
func (h *wsHub) broadcast(roomID []byte, cursor int64, kind string) {
	h.mu.Lock()
	set := h.subs[string(roomID)]
	clients := make([]*wsClient, 0, len(set))
	for c := range set {
		clients = append(clients, c)
	}
	h.mu.Unlock()
	if len(clients) == 0 {
		return
	}
	ev := wsEvent{Room: roomRefBase32(roomID), Cursor: cursor, Kind: kind}
	for _, c := range clients {
		select {
		case c.send <- ev:
		default:
		}
	}
}

// serveWS is `GET /v1/ws`. Authenticated (requestAuth, like every other non-`security: []`
// route) at the upgrade request; each subsequent `{"sub":[...]}` message is checked per-room
// against the caller's *current* membership (§5: "member/admin/owner, not pending, not
// removed") - unknown rooms or rooms the caller isn't an active member of are silently skipped,
// not an error, since a client might legitimately race a `join` against opening the socket.
func serveWS(st *store.Store, hub *wsHub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		device := DeviceKeyFromContext(r.Context())
		cert, err := st.GetDeviceCert(device)
		if err != nil {
			writeError(w, http.StatusForbidden, "forbidden", "device not registered")
			return
		}

		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		// Deliberately not r.Context(): the connection should outlive the HTTP handler's own
		// request context semantics (see the coder/websocket README's own warning about
		// r.Context() + http.Hijacker). The loops below exit on their own once the connection
		// closes (Read/Write start erroring), which triggers conn.CloseNow() via defer either way.
		ctx := context.Background()

		client := &wsClient{send: make(chan wsEvent, 16)}
		// LIFO: done closes first (stops the writer promptly), then unsubscribeAll removes this
		// client from the hub. client.send itself is never closed - a broadcast that already
		// grabbed this client from the hub's snapshot before unsubscribeAll ran might still send
		// on it after done closes; since nothing drains it anymore that's a harmless buffered (or
		// dropped-via-default, once full) send, never a send-on-closed-channel panic.
		defer hub.unsubscribeAll(client)
		done := make(chan struct{})
		defer close(done)

		go func() {
			for {
				select {
				case ev := <-client.send:
					if wsjson.Write(ctx, conn, ev) != nil {
						return
					}
				case <-done:
					return
				}
			}
		}()

		for {
			var msg struct {
				Sub []string `json:"sub"`
			}
			if err := wsjson.Read(ctx, conn, &msg); err != nil {
				return
			}
			for _, s := range msg.Sub {
				roomID, err := decodeRoomRefBase32(s)
				if err != nil {
					continue
				}
				state, err := st.GetMembershipState(roomID)
				if err != nil {
					continue
				}
				role, has := state.RoleOf(cert.User)
				if !isActiveMember(role, has) {
					continue
				}
				hub.subscribe(roomID, client)
			}
		}
	}
}
