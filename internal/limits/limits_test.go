package limits

import (
	"crypto/ed25519"
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/squaddle-org/relay/internal/membership"
	"github.com/squaddle-org/relay/internal/proto"
	"github.com/squaddle-org/relay/internal/store"
)

func newActor(seedByte byte) (userPub ed25519.PublicKey, userPriv ed25519.PrivateKey, devicePub ed25519.PublicKey, devicePriv ed25519.PrivateKey, cert proto.DeviceCert) {
	userSeed := make([]byte, 32)
	for i := range userSeed {
		userSeed[i] = seedByte
	}
	userPriv = ed25519.NewKeyFromSeed(userSeed)
	userPub = userPriv.Public().(ed25519.PublicKey)

	deviceSeed := make([]byte, 32)
	for i := range deviceSeed {
		deviceSeed[i] = seedByte + 1
	}
	devicePriv = ed25519.NewKeyFromSeed(deviceSeed)
	devicePub = devicePriv.Public().(ed25519.PublicKey)

	cert = proto.DeviceCert{V: 1, User: userPub, UserBox: userPub, Device: devicePub, Label: "test", IssuedAt: 1_700_000_000}
	unsigned, _ := proto.EncodeCanonical(struct {
		V        uint64 `cbor:"0,keyasint"`
		User     []byte `cbor:"1,keyasint"`
		UserBox  []byte `cbor:"2,keyasint"`
		Device   []byte `cbor:"3,keyasint"`
		Label    string `cbor:"4,keyasint"`
		IssuedAt uint64 `cbor:"5,keyasint"`
	}{cert.V, cert.User, cert.UserBox, cert.Device, cert.Label, cert.IssuedAt})
	cert.Sig = ed25519.Sign(userPriv, proto.SigningInput(proto.DeviceCertDomain, unsigned))
	return
}

func buildEntry(devicePriv ed25519.PrivateKey, cert proto.DeviceCert, author []byte, room []byte, index uint64, prev []byte, typ uint64, body map[uint64]any) proto.LogEntry {
	e := proto.LogEntry{V: 1, Room: room, Index: index, Prev: prev, Author: author, Cert: cert, Type: typ, Body: body, Ts: 1_700_000_000 + index}
	unsigned, _ := proto.EncodeCanonical(struct {
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
	e.Sig = ed25519.Sign(devicePriv, proto.SigningInput(proto.LogEntryDomain, unsigned))
	return e
}

func TestResolveUnlimitedWhenNotHosted(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	policy := NewPolicy("none", "")
	rl, err := Resolve(st, make([]byte, 32), policy, time.Now().Unix())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if rl.Tier != TierUnlimited {
		t.Fatalf("tier = %s, want unlimited", rl.Tier)
	}
}

func TestResolveFreeThenUnlimitedOwnerAllowlist(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	ownerPub, ownerPriv, _, devicePriv, cert := newActor(1)
	nonce := make([]byte, 16)
	roomID := membership.RoomID(ownerPub, nonce)
	genesis := buildEntry(devicePriv, cert, ownerPub, roomID, 0, nil, proto.EntryGenesis, map[uint64]any{0: nonce, 1: "relay.squaddle.org", 2: make([]byte, 48)})
	if _, err := st.CreateRoom(genesis, 1_700_000_500); err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}
	_ = ownerPriv

	hosted := NewPolicy("hosted", "")
	rl, err := Resolve(st, roomID, hosted, time.Now().Unix())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if rl.Tier != TierFree || rl.MaxMembers == nil || *rl.MaxMembers != 20 {
		t.Fatalf("got %+v, want free tier with maxMembers=20", rl)
	}

	ownerRef := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(ownerPub))
	allowlisted := NewPolicy("hosted", ownerRef)
	rl2, err := Resolve(st, roomID, allowlisted, time.Now().Unix())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if rl2.Tier != TierUnlimited {
		t.Fatalf("tier = %s, want unlimited for an allowlisted owner", rl2.Tier)
	}
}

func TestResolveBoostedFromVoucher(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	ownerPub, _, _, devicePriv, cert := newActor(2)
	nonce := make([]byte, 16)
	roomID := membership.RoomID(ownerPub, nonce)
	genesis := buildEntry(devicePriv, cert, ownerPub, roomID, 0, nil, proto.EntryGenesis, map[uint64]any{0: nonce, 1: "relay.squaddle.org", 2: make([]byte, 48)})
	if _, err := st.CreateRoom(genesis, 1_700_000_500); err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}

	now := time.Now().Unix()
	until := now + 86400
	if err := st.PutEntitlement(roomID, "voucher", "ref-1", "boosted", &until); err != nil {
		t.Fatalf("PutEntitlement: %v", err)
	}

	hosted := NewPolicy("hosted", "")
	rl, err := Resolve(st, roomID, hosted, now)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if rl.Tier != TierBoosted || rl.MaxMembers == nil || *rl.MaxMembers != 100 {
		t.Fatalf("got %+v, want boosted tier with maxMembers=100", rl)
	}
}
