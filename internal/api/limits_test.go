package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/squaddle-org/relay/internal/limits"
	"github.com/squaddle-org/relay/internal/membership"
	"github.com/squaddle-org/relay/internal/proto"
	"github.com/squaddle-org/relay/internal/store"
)

func newTestRouterWithPolicy(t *testing.T, policy *limits.Policy) (http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), st, policy), st
}

func TestGetLimitsUnlimitedBySelfHostedDefault(t *testing.T) {
	h, st := newTestRouterWithPolicy(t, limits.NewPolicy("none", ""))
	owner := newTestActor(t, 40, "Owner Phone")
	member := newTestActor(t, 41, "Member Phone")
	roomID := setUpRoomWithOwnerAndMember(t, h, owner, member)
	_ = st

	limitsTarget := "/v1/rooms/" + b64(roomID) + "/limits"
	req, _ := signedRequest(t, member.devicePriv, member.devicePub, http.MethodGet, limitsTarget, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET limits: got %d, body %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body["tier"] != "unlimited" {
		t.Fatalf("tier = %v, want unlimited", body["tier"])
	}
}

func TestGetLimitsFreeTierWhenHosted(t *testing.T) {
	h, _ := newTestRouterWithPolicy(t, limits.NewPolicy("hosted", ""))
	owner := newTestActor(t, 42, "Owner Phone")
	member := newTestActor(t, 43, "Member Phone")
	roomID := setUpRoomWithOwnerAndMember(t, h, owner, member)

	limitsTarget := "/v1/rooms/" + b64(roomID) + "/limits"
	req, _ := signedRequest(t, member.devicePriv, member.devicePub, http.MethodGet, limitsTarget, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET limits: got %d, body %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body["tier"] != "free" || body["maxMembers"] != float64(20) {
		t.Fatalf("got %+v, want tier=free maxMembers=20", body)
	}
}

func TestJoinRejectedWithRoomFullWhenHosted(t *testing.T) {
	h, st := newTestRouterWithPolicy(t, limits.NewPolicy("hosted", ""))
	owner := newTestActor(t, 44, "Owner Phone")

	// Register the owner's device and create the room ourselves (not via
	// setUpRoomWithOwnerAndMember, since we need to drive maxMembers down to a size this test can
	// actually exhaust without joining 20 real members).
	cbor, err := owner.cert.FullCbor()
	if err != nil {
		t.Fatalf("FullCbor: %v", err)
	}
	target := fmt.Sprintf("/v1/users/%s/devices/%s", b64(owner.userPub), b64(owner.devicePub))
	req, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPut, target, cbor)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PUT device: got %d", rec.Code)
	}

	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i + 60)
	}
	roomID := membership.RoomID(owner.userPub, nonce)
	genesis := owner.buildEntry(t, roomID, 0, nil, proto.EntryGenesis, map[uint64]any{0: nonce, 1: "relay.squaddle.org", 2: make([]byte, 48)})
	genesisCbor, _ := genesis.FullCbor()
	req2, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPost, "/v1/rooms", genesisCbor)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("POST /rooms: got %d, body %s", rec2.Code, rec2.Body.String())
	}

	// The free tier's maxMembers is 20 and the owner already counts as one - join 19 more members
	// (open invite, no approval) to hit the limit exactly, then a 20th attempt must 409 room_full.
	inviteID := make([]byte, 16)
	for i := range inviteID {
		inviteID[i] = byte(i + 70)
	}
	inviteCreate := owner.buildEntry(t, roomID, 1, genesis.EntryHash(), proto.EntryInviteCreate, map[uint64]any{0: inviteID, 3: false, 4: "member"})
	inviteCreateCbor, _ := inviteCreate.FullCbor()
	logTarget := "/v1/rooms/" + b64(roomID) + "/log"
	req3, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPost, logTarget, inviteCreateCbor)
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusCreated {
		t.Fatalf("POST inviteCreate: got %d, body %s", rec3.Code, rec3.Body.String())
	}

	prev := inviteCreate.EntryHash()
	index := uint64(2)
	for i := 0; i < 19; i++ {
		m := newTestActor(t, byte(100+i), "Member Phone")
		join := m.buildEntry(t, roomID, index, prev, proto.EntryJoin, map[uint64]any{0: inviteID})
		joinCbor, _ := join.FullCbor()
		req, _ := signedRequest(t, m.devicePriv, m.devicePub, http.MethodPost, logTarget, joinCbor)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("join #%d: got %d, body %s", i, rec.Code, rec.Body.String())
		}
		prev = join.EntryHash()
		index++
	}

	rl, err := limits.Resolve(st, roomID, limits.NewPolicy("hosted", ""), 0)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	t.Logf("resolved limits: %+v", rl)

	overflow := newTestActor(t, 200, "Overflow Phone")
	joinOverflow := overflow.buildEntry(t, roomID, index, prev, proto.EntryJoin, map[uint64]any{0: inviteID})
	joinOverflowCbor, _ := joinOverflow.FullCbor()
	reqOverflow, _ := signedRequest(t, overflow.devicePriv, overflow.devicePub, http.MethodPost, logTarget, joinOverflowCbor)
	recOverflow := httptest.NewRecorder()
	h.ServeHTTP(recOverflow, reqOverflow)
	if recOverflow.Code != http.StatusConflict {
		t.Fatalf("20th join: got %d, body %s, want 409 room_full", recOverflow.Code, recOverflow.Body.String())
	}
	var errBody apiError
	if err := json.Unmarshal(recOverflow.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("decoding error body: %v", err)
	}
	if errBody.Code != "room_full" {
		t.Fatalf("error code = %q, want room_full", errBody.Code)
	}
}

func TestVoucherEntitlementRedemption(t *testing.T) {
	h, st := newTestRouterWithPolicy(t, limits.NewPolicy("hosted", ""))
	owner := newTestActor(t, 45, "Owner Phone")
	member := newTestActor(t, 46, "Member Phone")
	roomID := setUpRoomWithOwnerAndMember(t, h, owner, member)

	code := "test-voucher-code-1"
	codeHash := proto.Blake2b256([]byte(code))
	if err := st.MintVoucher(codeHash, "boosted", intPtr(30)); err != nil {
		t.Fatalf("MintVoucher: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"room": b64(roomID), "provider": "voucher", "token": code})
	req, _ := signedRequest(t, member.devicePriv, member.devicePub, http.MethodPost, "/v1/entitlements", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST entitlements: got %d, body %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp["tier"] != "boosted" {
		t.Fatalf("tier = %v, want boosted", resp["tier"])
	}

	// Redeeming the same voucher again must fail.
	req2, _ := signedRequest(t, member.devicePriv, member.devicePub, http.MethodPost, "/v1/entitlements", body)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("re-redeeming voucher: got %d, want 400 invalid_entitlement", rec2.Code)
	}

	// The room's limits now reflect the boost.
	limitsTarget := "/v1/rooms/" + b64(roomID) + "/limits"
	req3, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodGet, limitsTarget, nil)
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	var limitsBody map[string]any
	if err := json.Unmarshal(rec3.Body.Bytes(), &limitsBody); err != nil {
		t.Fatalf("decoding limits: %v", err)
	}
	if limitsBody["tier"] != "boosted" {
		t.Fatalf("tier = %v, want boosted after redemption", limitsBody["tier"])
	}
}

func intPtr(n int) *int { return &n }
