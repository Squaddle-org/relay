package store

import (
	"crypto/ed25519"
	"testing"

	"github.com/squaddle-org/relay/internal/membership"
	"github.com/squaddle-org/relay/internal/proto"
)

// testActor is a minimal self-contained signer, mirroring the pattern core's own
// MembershipStateTest.Actor and the Go membership package's test vectors use.
type testActor struct {
	userPub, userPriv     []byte
	devicePub, devicePriv []byte
	cert                  proto.DeviceCert
}

func newTestActor(t *testing.T, seedByte byte, label string) testActor {
	t.Helper()
	userSeed := make([]byte, 32)
	for i := range userSeed {
		userSeed[i] = seedByte
	}
	userPriv := ed25519.NewKeyFromSeed(userSeed)
	userPub := userPriv.Public().(ed25519.PublicKey)

	deviceSeed := make([]byte, 32)
	for i := range deviceSeed {
		deviceSeed[i] = seedByte + 1
	}
	devicePriv := ed25519.NewKeyFromSeed(deviceSeed)
	devicePub := devicePriv.Public().(ed25519.PublicKey)

	cert := proto.DeviceCert{V: 1, User: userPub, UserBox: userPub, Device: devicePub, Label: label, IssuedAt: 1_700_000_000}
	unsigned, err := proto.EncodeCanonical(struct {
		V        uint64 `cbor:"0,keyasint"`
		User     []byte `cbor:"1,keyasint"`
		UserBox  []byte `cbor:"2,keyasint"`
		Device   []byte `cbor:"3,keyasint"`
		Label    string `cbor:"4,keyasint"`
		IssuedAt uint64 `cbor:"5,keyasint"`
	}{cert.V, cert.User, cert.UserBox, cert.Device, cert.Label, cert.IssuedAt})
	if err != nil {
		t.Fatalf("encoding unsigned cert: %v", err)
	}
	cert.Sig = ed25519.Sign(userPriv, proto.SigningInput(proto.DeviceCertDomain, unsigned))
	if !cert.Verify() {
		t.Fatalf("test bug: constructed cert does not verify")
	}
	return testActor{userPub, userPriv, devicePub, devicePriv, cert}
}

func (a testActor) buildEntry(t *testing.T, room []byte, index uint64, prev []byte, typ uint64, body map[uint64]any) proto.LogEntry {
	t.Helper()
	e := proto.LogEntry{V: 1, Room: room, Index: index, Prev: prev, Author: a.userPub, Cert: a.cert, Type: typ, Body: body, Ts: 1_700_000_000 + index}
	unsigned, err := proto.EncodeCanonical(struct {
		V      uint64           `cbor:"0,keyasint"`
		Room   []byte           `cbor:"1,keyasint"`
		Index  uint64           `cbor:"2,keyasint"`
		Prev   []byte           `cbor:"3,keyasint,omitempty"`
		Author []byte           `cbor:"4,keyasint"`
		Cert   proto.DeviceCert `cbor:"5,keyasint"`
		Type   uint64           `cbor:"6,keyasint"`
		Body   map[uint64]any   `cbor:"7,keyasint"`
		Ts     uint64           `cbor:"8,keyasint"`
	}{e.V, e.Room, e.Index, e.Prev, e.Author, e.Cert, e.Type, e.Body, e.Ts})
	if err != nil {
		t.Fatalf("encoding unsigned entry: %v", err)
	}
	e.Sig = ed25519.Sign(a.devicePriv, proto.SigningInput(proto.LogEntryDomain, unsigned))
	if !e.Verify() {
		t.Fatalf("test bug: constructed entry does not verify")
	}
	return e
}

func TestCreateRoomAndAppendLogEntry(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	owner := newTestActor(t, 1, "Owner Phone")
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i + 40)
	}
	roomID := membership.RoomID(owner.userPub, nonce)
	genesis := owner.buildEntry(t, roomID, 0, nil, proto.EntryGenesis, map[uint64]any{
		0: nonce, 1: "relay.squaddle.org", 2: make([]byte, 48),
	})

	state, err := s.CreateRoom(genesis, 1_700_000_500)
	if err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}
	if role, ok := state.RoleOf(owner.userPub); !ok || role != membership.RoleOwner {
		t.Fatalf("owner role after genesis = %v, %v", role, ok)
	}

	if _, err := s.CreateRoom(genesis, 1_700_000_500); !isRoomExists(err) {
		t.Fatalf("second CreateRoom with same room id: got %v, want ErrRoomExists", err)
	}

	settings := owner.buildEntry(t, roomID, 1, state.HeadHash(), proto.EntryRoomSettings, map[uint64]any{})
	state2, err := s.AppendLogEntry(roomID, settings, 1_700_000_600)
	if err != nil {
		t.Fatalf("AppendLogEntry: %v", err)
	}
	if state2.NextIndex() != 2 {
		t.Fatalf("nextIndex after second entry = %d, want 2", state2.NextIndex())
	}

	entries, err := s.GetLogEntriesFrom(roomID, 0)
	if err != nil {
		t.Fatalf("GetLogEntriesFrom: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("GetLogEntriesFrom returned %d entries, want 2", len(entries))
	}

	// Drop the cache and confirm the state rebuilds identically by replaying the stored log.
	s.mu.Lock()
	delete(s.states, hexKey(roomID))
	s.mu.Unlock()
	rebuilt, err := s.GetMembershipState(roomID)
	if err != nil {
		t.Fatalf("GetMembershipState after cache drop: %v", err)
	}
	if rebuilt.NextIndex() != 2 || rebuilt.Epoch() != state2.Epoch() {
		t.Fatalf("rebuilt state diverges from cached state")
	}
}

func isRoomExists(err error) bool { return err == ErrRoomExists }

func TestDeviceCertRoundTrip(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	actor := newTestActor(t, 5, "Pixel 8")
	if err := s.PutDeviceCert(actor.cert); err != nil {
		t.Fatalf("PutDeviceCert: %v", err)
	}
	got, err := s.GetDeviceCert(actor.devicePub)
	if err != nil {
		t.Fatalf("GetDeviceCert: %v", err)
	}
	if !got.Verify() {
		t.Fatalf("stored-then-loaded cert does not verify")
	}

	if err := s.RevokeDevice(actor.devicePub, 1_700_000_000); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if _, err := s.GetDeviceCert(actor.devicePub); err != ErrDeviceNotFound {
		t.Fatalf("GetDeviceCert after revoke: got %v, want ErrDeviceNotFound", err)
	}
}

func TestInviteEnvelopeRoundTrip(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	owner := newTestActor(t, 9, "Owner Phone")
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i + 60)
	}
	roomID := membership.RoomID(owner.userPub, nonce)
	genesis := owner.buildEntry(t, roomID, 0, nil, proto.EntryGenesis, map[uint64]any{
		0: nonce, 1: "relay.squaddle.org", 2: make([]byte, 48),
	})
	if _, err := s.CreateRoom(genesis, 1_700_000_500); err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}

	inviteID := make([]byte, 16)
	for i := range inviteID {
		inviteID[i] = byte(i + 100)
	}
	envelope := []byte("fake-envelope-bytes")

	if _, err := s.GetInviteEnvelope(roomID, inviteID); err != ErrEnvelopeNotFound {
		t.Fatalf("GetInviteEnvelope before Put: got %v, want ErrEnvelopeNotFound", err)
	}
	if err := s.PutInviteEnvelope(roomID, inviteID, envelope); err != nil {
		t.Fatalf("PutInviteEnvelope: %v", err)
	}
	got, err := s.GetInviteEnvelope(roomID, inviteID)
	if err != nil || string(got) != string(envelope) {
		t.Fatalf("GetInviteEnvelope = %q, %v, want %q, nil", got, err, envelope)
	}
	if err := s.DeleteInviteEnvelope(roomID, inviteID); err != nil {
		t.Fatalf("DeleteInviteEnvelope: %v", err)
	}
	if _, err := s.GetInviteEnvelope(roomID, inviteID); err != ErrEnvelopeNotFound {
		t.Fatalf("GetInviteEnvelope after Delete: got %v, want ErrEnvelopeNotFound", err)
	}
}
