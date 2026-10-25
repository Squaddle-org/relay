package api

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/squaddle-org/relay/internal/membership"
	"github.com/squaddle-org/relay/internal/proto"
)

func (a testActor) buildOp(t *testing.T, room []byte, epoch, seq, lamport uint64) proto.OpEnvelope {
	t.Helper()
	nonce := make([]byte, 24)
	ct := []byte("opaque-ciphertext")
	e := proto.OpEnvelope{V: 1, Room: room, Epoch: epoch, Author: a.userPub, Device: a.devicePub, Seq: seq, Lamport: lamport, Nonce: nonce, Ct: ct}
	unsigned, err := proto.EncodeCanonical(struct {
		V       uint64 `cbor:"0,keyasint"`
		Room    []byte `cbor:"1,keyasint"`
		Epoch   uint64 `cbor:"2,keyasint"`
		Author  []byte `cbor:"3,keyasint"`
		Device  []byte `cbor:"4,keyasint"`
		Seq     uint64 `cbor:"5,keyasint"`
		Lamport uint64 `cbor:"6,keyasint"`
		Nonce   []byte `cbor:"7,keyasint"`
		Ct      []byte `cbor:"8,keyasint"`
	}{e.V, e.Room, e.Epoch, e.Author, e.Device, e.Seq, e.Lamport, e.Nonce, e.Ct})
	if err != nil {
		t.Fatalf("encoding unsigned op: %v", err)
	}
	e.Sig = ed25519.Sign(a.devicePriv, proto.SigningInput(proto.OpEnvelopeDomain, unsigned))
	if !e.Verify() {
		t.Fatalf("test bug: constructed op does not verify")
	}
	return e
}

func (a testActor) buildSnapshot(t *testing.T, room []byte, epoch, coversUpTo uint64) proto.Snapshot {
	t.Helper()
	nonce := make([]byte, 24)
	ct := []byte("opaque-ciphertext")
	s := proto.Snapshot{V: 1, Room: room, Epoch: epoch, CoversUpTo: coversUpTo, Nonce: nonce, Ct: ct, Author: a.userPub, Device: a.devicePub}
	unsigned, err := proto.EncodeCanonical(struct {
		V          uint64 `cbor:"0,keyasint"`
		Room       []byte `cbor:"1,keyasint"`
		Epoch      uint64 `cbor:"2,keyasint"`
		CoversUpTo uint64 `cbor:"3,keyasint"`
		Nonce      []byte `cbor:"4,keyasint"`
		Ct         []byte `cbor:"5,keyasint"`
		Author     []byte `cbor:"6,keyasint"`
		Device     []byte `cbor:"7,keyasint"`
	}{s.V, s.Room, s.Epoch, s.CoversUpTo, s.Nonce, s.Ct, s.Author, s.Device})
	if err != nil {
		t.Fatalf("encoding unsigned snapshot: %v", err)
	}
	s.Sig = ed25519.Sign(a.devicePriv, proto.SigningInput(proto.SnapshotDomain, unsigned))
	if !s.Verify() {
		t.Fatalf("test bug: constructed snapshot does not verify")
	}
	return s
}

// setUpRoomWithOwnerAndMember registers both actors' devices, creates a room owned by owner,
// and (via inviteCreate+join) makes member a room member - the shared setup every content-plane
// test needs before it can exercise ops/snapshots/push.
func setUpRoomWithOwnerAndMember(t *testing.T, h http.Handler, owner, member testActor) (roomID []byte) {
	t.Helper()
	for _, a := range []testActor{owner, member} {
		cbor, err := a.cert.FullCbor()
		if err != nil {
			t.Fatalf("FullCbor: %v", err)
		}
		target := fmt.Sprintf("/v1/users/%s/devices/%s", b64(a.userPub), b64(a.devicePub))
		req, _ := signedRequest(t, a.devicePriv, a.devicePub, http.MethodPut, target, cbor)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("PUT device: got %d", rec.Code)
		}
	}

	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i + 80)
	}
	roomID = membership.RoomID(owner.userPub, nonce)
	genesis := owner.buildEntry(t, roomID, 0, nil, proto.EntryGenesis, map[uint64]any{
		0: nonce, 1: "relay.squaddle.org", 2: make([]byte, 48),
	})
	genesisCbor, _ := genesis.FullCbor()
	req, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPost, "/v1/rooms", genesisCbor)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /rooms: got %d, body %s", rec.Code, rec.Body.String())
	}

	inviteID := make([]byte, 16)
	for i := range inviteID {
		inviteID[i] = byte(i + 90)
	}
	inviteCreate := owner.buildEntry(t, roomID, 1, genesis.EntryHash(), proto.EntryInviteCreate, map[uint64]any{
		0: inviteID, 3: false, 4: "member",
	})
	inviteCreateCbor, _ := inviteCreate.FullCbor()
	logTarget := "/v1/rooms/" + b64(roomID) + "/log"
	req2, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPost, logTarget, inviteCreateCbor)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("POST inviteCreate: got %d, body %s", rec2.Code, rec2.Body.String())
	}

	join := member.buildEntry(t, roomID, 2, inviteCreate.EntryHash(), proto.EntryJoin, map[uint64]any{0: inviteID})
	joinCbor, _ := join.FullCbor()
	req3, _ := signedRequest(t, member.devicePriv, member.devicePub, http.MethodPost, logTarget, joinCbor)
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusCreated {
		t.Fatalf("POST join: got %d, body %s", rec3.Code, rec3.Body.String())
	}
	return roomID
}

func TestOpsPostAndGetRoundTrip(t *testing.T) {
	h, _ := newTestRouter(t)
	owner := newTestActor(t, 10, "Owner Phone")
	member := newTestActor(t, 11, "Member Phone")
	roomID := setUpRoomWithOwnerAndMember(t, h, owner, member)

	op := member.buildOp(t, roomID, 0, 1, 1)
	opCbor, err := proto.EncodeCanonical([]proto.OpEnvelope{op})
	if err != nil {
		t.Fatalf("encoding batch: %v", err)
	}
	opsTarget := "/v1/rooms/" + b64(roomID) + "/ops"
	req, _ := signedRequest(t, member.devicePriv, member.devicePub, http.MethodPost, opsTarget, opCbor)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST ops: got %d, body %s", rec.Code, rec.Body.String())
	}

	reqGet, _ := signedRequest(t, member.devicePriv, member.devicePub, http.MethodGet, opsTarget, nil)
	recGet := httptest.NewRecorder()
	h.ServeHTTP(recGet, reqGet)
	if recGet.Code != http.StatusOK {
		t.Fatalf("GET ops: got %d, body %s", recGet.Code, recGet.Body.String())
	}
	if recGet.Body.Len() == 0 {
		t.Fatalf("GET ops: empty body")
	}
}

func TestOpsPostRejectsWrongEpochAndNonMember(t *testing.T) {
	h, _ := newTestRouter(t)
	owner := newTestActor(t, 12, "Owner Phone")
	member := newTestActor(t, 13, "Member Phone")
	stranger := newTestActor(t, 14, "Stranger Phone")
	roomID := setUpRoomWithOwnerAndMember(t, h, owner, member)
	opsTarget := "/v1/rooms/" + b64(roomID) + "/ops"

	wrongEpoch := member.buildOp(t, roomID, 7, 1, 1)
	wrongEpochCbor, _ := proto.EncodeCanonical([]proto.OpEnvelope{wrongEpoch})
	req, _ := signedRequest(t, member.devicePriv, member.devicePub, http.MethodPost, opsTarget, wrongEpochCbor)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("wrong epoch: got %d, want 409", rec.Code)
	}

	// Stranger's device was never registered, so even a self-consistent, correctly-epoched op
	// from them must be rejected (unregistered device cert -> cannot resolve to a member).
	strangerOp := stranger.buildOp(t, roomID, 0, 1, 1)
	strangerCbor, _ := proto.EncodeCanonical([]proto.OpEnvelope{strangerOp})
	req2, _ := signedRequest(t, stranger.devicePriv, stranger.devicePub, http.MethodPost, opsTarget, strangerCbor)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("non-member: got %d, want 403", rec2.Code)
	}
}

func TestOpsPostRejectsWhileRotationPending(t *testing.T) {
	h, _ := newTestRouter(t)
	owner := newTestActor(t, 15, "Owner Phone")
	member := newTestActor(t, 16, "Member Phone")
	roomID := setUpRoomWithOwnerAndMember(t, h, owner, member)
	logTarget := "/v1/rooms/" + b64(roomID) + "/log"

	// owner removes member at index 3 (0 genesis, 1 inviteCreate, 2 join) - this sets
	// rotationPending (ADR-0012), which must block new ops until the next epochRotate.
	// Recompute the chain locally (mirrors setUpRoomWithOwnerAndMember's own construction) to get
	// the current head hash for the next entry's `prev`.
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

	remove := owner.buildEntry(t, roomID, 3, join.EntryHash(), proto.EntryRemove, map[uint64]any{0: member.userPub})
	removeCbor, _ := remove.FullCbor()
	req, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPost, logTarget, removeCbor)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST remove: got %d, body %s", rec.Code, rec.Body.String())
	}

	op := owner.buildOp(t, roomID, 0, 1, 1)
	opCbor, _ := proto.EncodeCanonical([]proto.OpEnvelope{op})
	opsTarget := "/v1/rooms/" + b64(roomID) + "/ops"
	req2, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPost, opsTarget, opCbor)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("ops while rotationPending: got %d, want 409, body %s", rec2.Code, rec2.Body.String())
	}
}

func TestSnapshotPostAndGetLatest(t *testing.T) {
	h, _ := newTestRouter(t)
	owner := newTestActor(t, 17, "Owner Phone")
	member := newTestActor(t, 18, "Member Phone")
	roomID := setUpRoomWithOwnerAndMember(t, h, owner, member)
	snapshotTarget := "/v1/rooms/" + b64(roomID) + "/snapshots"

	snapshot := owner.buildSnapshot(t, roomID, 0, 42)
	snapshotCbor, err := snapshot.FullCbor()
	if err != nil {
		t.Fatalf("FullCbor: %v", err)
	}
	req, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPost, snapshotTarget, snapshotCbor)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST snapshot: got %d, body %s", rec.Code, rec.Body.String())
	}

	latestTarget := snapshotTarget + "/latest"
	reqGet, _ := signedRequest(t, member.devicePriv, member.devicePub, http.MethodGet, latestTarget, nil)
	recGet := httptest.NewRecorder()
	h.ServeHTTP(recGet, reqGet)
	if recGet.Code != http.StatusOK || !bytes.Equal(recGet.Body.Bytes(), snapshotCbor) {
		t.Fatalf("GET latest snapshot: got %d %q", recGet.Code, recGet.Body.Bytes())
	}
}

// TestSnapshotPostRejectsBadSignature confirms postSnapshot now actually validates the envelope
// (PROTOCOL.md §4.4 field numbers) instead of storing opaque bytes unchecked.
func TestSnapshotPostRejectsBadSignature(t *testing.T) {
	h, _ := newTestRouter(t)
	owner := newTestActor(t, 117, "Owner Phone")
	member := newTestActor(t, 118, "Member Phone")
	roomID := setUpRoomWithOwnerAndMember(t, h, owner, member)
	snapshotTarget := "/v1/rooms/" + b64(roomID) + "/snapshots"

	snapshot := owner.buildSnapshot(t, roomID, 0, 1)
	snapshot.Sig[0] ^= 0xff
	tampered, err := snapshot.FullCbor()
	if err != nil {
		t.Fatalf("FullCbor: %v", err)
	}
	req, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPost, snapshotTarget, tampered)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST tampered snapshot: got %d, want 400, body %s", rec.Code, rec.Body.String())
	}
}

func TestPushRegisterAndUnregister(t *testing.T) {
	h, _ := newTestRouter(t)
	owner := newTestActor(t, 19, "Owner Phone")
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

	body := []byte(`{"endpoint":"https://push.example/abc"}`)
	reqPush, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPost, "/v1/push", body)
	recPush := httptest.NewRecorder()
	h.ServeHTTP(recPush, reqPush)
	if recPush.Code != http.StatusNoContent {
		t.Fatalf("POST push: got %d, body %s", recPush.Code, recPush.Body.String())
	}

	reqDel, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodDelete, "/v1/push", nil)
	recDel := httptest.NewRecorder()
	h.ServeHTTP(recDel, reqDel)
	if recDel.Code != http.StatusNoContent {
		t.Fatalf("DELETE push: got %d", recDel.Code)
	}
}
