package api

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/squaddle-org/relay/internal/proto"
)

// authHeader builds a PROTOCOL.md §5 Authorization header value for (method, path, body) at the
// given timestamp - shared by the WS upgrade request and the plain-HTTP POST in this file, both
// of which need to hit a *real* httptest.Server (coder/websocket needs a real listener, not
// httptest.NewRecorder), unlike signedRequest's httptest.NewRequest used everywhere else.
func authHeader(devicePriv ed25519.PrivateKey, devicePub ed25519.PublicKey, method, path string, body []byte, at time.Time) string {
	ts := strconv.FormatInt(at.Unix(), 10)
	reqLine := method + "\n" + path + "\n" + ts + "\n"
	signingInput := proto.SigningInput("req", append([]byte(reqLine), proto.Blake2b256(body)...))
	sig := ed25519.Sign(devicePriv, signingInput)
	return fmt.Sprintf("SQDL1 device=%s, ts=%s, sig=%s", b64(devicePub), ts, b64(sig))
}

func TestWSSubscribeAndFanout(t *testing.T) {
	h, _ := newTestRouter(t)
	server := httptest.NewServer(h)
	defer server.Close()

	clock := newTestClock()
	owner := newTestActor(t, 20, "Owner Phone")
	member := newTestActor(t, 21, "Member Phone")
	roomID := setUpRoomWithOwnerAndMember(t, h, clock, owner, member)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/ws"
	wsHeader := authHeader(member.devicePriv, member.devicePub, http.MethodGet, "/v1/ws", nil, clock.next())
	conn, _, err := websocket.Dial(context.Background(), wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{wsHeader}},
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := wsjson.Write(ctx, conn, map[string]any{"sub": []string{roomRefBase32(roomID)}}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // let the server process the subscribe before we trigger a broadcast

	// Recompute the chain head the same way setUpRoomWithOwnerAndMember built it (genesis ->
	// inviteCreate -> join), since this test's HTTP POST goes through the real httptest.Server
	// rather than through h.ServeHTTP, so it can't reuse any in-flight state from the setup call.
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i + 80)
	}
	genesis := owner.buildEntry(t, roomID, 0, nil, proto.EntryGenesis, map[uint64]any{0: nonce, 1: "relay.squaddle.org", 2: make([]byte, 48)})
	inviteID := make([]byte, 16)
	for i := range inviteID {
		inviteID[i] = byte(i + 90)
	}
	inviteCreate := owner.buildEntry(t, roomID, 1, genesis.EntryHash(), proto.EntryInviteCreate, map[uint64]any{0: inviteID, 3: false, 4: "member"})
	join := member.buildEntry(t, roomID, 2, inviteCreate.EntryHash(), proto.EntryJoin, map[uint64]any{0: inviteID})

	settings := owner.buildEntry(t, roomID, 3, join.EntryHash(), proto.EntryRoomSettings, map[uint64]any{})
	settingsCbor, err := settings.FullCbor()
	if err != nil {
		t.Fatalf("FullCbor: %v", err)
	}
	logPath := "/v1/rooms/" + b64(roomID) + "/log"
	httpReq, err := http.NewRequest(http.MethodPost, server.URL+logPath, strings.NewReader(string(settingsCbor)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	httpReq.Header.Set("Authorization", authHeader(owner.devicePriv, owner.devicePub, http.MethodPost, logPath, settingsCbor, clock.next()))
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("POST log: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST log: got %d", resp.StatusCode)
	}

	var ev map[string]any
	readCtx, readCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readCancel()
	if err := wsjson.Read(readCtx, conn, &ev); err != nil {
		t.Fatalf("reading fanout event: %v", err)
	}
	if ev["r"] != roomRefBase32(roomID) || ev["k"] != "log" {
		t.Fatalf("fanout event = %+v, want r=%s k=log", ev, roomRefBase32(roomID))
	}
}
