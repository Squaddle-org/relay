package retention

import (
	"crypto/ed25519"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/squaddle-org/relay/internal/limits"
	"github.com/squaddle-org/relay/internal/membership"
	"github.com/squaddle-org/relay/internal/proto"
	"github.com/squaddle-org/relay/internal/store"
)

func newActor(seedByte byte) (userPub ed25519.PublicKey, devicePriv ed25519.PrivateKey, cert proto.DeviceCert) {
	userSeed := make([]byte, 32)
	for i := range userSeed {
		userSeed[i] = seedByte
	}
	userPriv := ed25519.NewKeyFromSeed(userSeed)
	userPub = userPriv.Public().(ed25519.PublicKey)

	deviceSeed := make([]byte, 32)
	for i := range deviceSeed {
		deviceSeed[i] = seedByte + 1
	}
	devicePriv = ed25519.NewKeyFromSeed(deviceSeed)
	devicePub := devicePriv.Public().(ed25519.PublicKey)

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

func buildGenesis(devicePriv ed25519.PrivateKey, cert proto.DeviceCert, author, room, nonce []byte) proto.LogEntry {
	e := proto.LogEntry{V: 1, Room: room, Index: 0, Author: author, Cert: cert, Type: proto.EntryGenesis, Body: map[uint64]any{0: nonce, 1: "relay.squaddle.org", 2: make([]byte, 48)}, Ts: 1_700_000_000}
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

// backdate directly rewrites a row's timestamp column - the public Store API only ever writes
// "now" (unixepoch()), so tests that need an aged snapshot/op reach around it via a second raw
// connection to the same on-disk file.
func backdate(t *testing.T, dbPath, table string, id []byte, column string, when time.Time) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("opening raw db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE `+table+` SET `+column+` = ? WHERE room_id = ?`, when.Unix(), id); err != nil {
		t.Fatalf("backdating %s.%s: %v", table, column, err)
	}
}

func setUpRoomWithOneOp(t *testing.T, dbPath string) (st *store.Store, room []byte) {
	t.Helper()
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ownerPub, devicePriv, cert := newActor(10)
	nonce := make([]byte, 16)
	room = membership.RoomID(ownerPub, nonce)
	genesis := buildGenesis(devicePriv, cert, ownerPub, room, nonce)
	if _, err := st.CreateRoom(genesis, 1_700_000_500); err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}
	return st, room
}

func TestRunPrunesOpCoveredBySnapshotOlderThanRetention(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, room := setUpRoomWithOneOp(t, dbPath)
	defer st.Close()

	cursor1, err := st.AppendOp(room, make([]byte, 32), make([]byte, 32), 1, 0, []byte("op1"))
	if err != nil {
		t.Fatalf("AppendOp 1: %v", err)
	}
	cursor2, err := st.AppendOp(room, append(make([]byte, 31), 1), make([]byte, 32), 2, 0, []byte("op2"))
	if err != nil {
		t.Fatalf("AppendOp 2: %v", err)
	}

	if err := st.PutSnapshot(room, cursor1, []byte("snapshot")); err != nil {
		t.Fatalf("PutSnapshot: %v", err)
	}

	now := time.Now()
	backdate(t, dbPath, "snapshots", room, "created_at", now.Add(-31*24*time.Hour))
	backdate(t, dbPath, "ops", room, "received_at", now.Add(-100*24*time.Hour))
	// backdate updates every row matching room_id - op2 isn't covered by the snapshot (cursor2 >
	// coversUpTo=cursor1) so it must survive pruning even though it's also "old" here.

	policy := limits.NewPolicy("hosted", "")
	pruned, err := Run(st, policy, now)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("pruned = %d, want 1", pruned)
	}

	ops, err := st.GetOpsAfter(room, 0, 10)
	if err != nil {
		t.Fatalf("GetOpsAfter: %v", err)
	}
	if len(ops) != 1 || ops[0].Cursor != cursor2 {
		t.Fatalf("remaining ops = %+v, want only cursor %d", ops, cursor2)
	}
}

func TestRunSkipsRoomsWithoutASnapshot(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, room := setUpRoomWithOneOp(t, dbPath)
	defer st.Close()

	if _, err := st.AppendOp(room, make([]byte, 32), make([]byte, 32), 1, 0, []byte("op1")); err != nil {
		t.Fatalf("AppendOp: %v", err)
	}

	policy := limits.NewPolicy("hosted", "")
	pruned, err := Run(st, policy, time.Now())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pruned != 0 {
		t.Fatalf("pruned = %d, want 0 (no snapshot yet)", pruned)
	}
}

func TestRunRespectsSnapshotMinAgeFloor(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, room := setUpRoomWithOneOp(t, dbPath)
	defer st.Close()

	cursor1, err := st.AppendOp(room, make([]byte, 32), make([]byte, 32), 1, 0, []byte("op1"))
	if err != nil {
		t.Fatalf("AppendOp: %v", err)
	}
	if err := st.PutSnapshot(room, cursor1, []byte("snapshot")); err != nil {
		t.Fatalf("PutSnapshot: %v", err)
	}

	now := time.Now()
	// snapshot is fresh (just created) and the op is very old - §4.4's 30-day floor must still
	// block pruning regardless of how old the op itself is.
	backdate(t, dbPath, "ops", room, "received_at", now.Add(-200*24*time.Hour))

	policy := limits.NewPolicy("hosted", "")
	pruned, err := Run(st, policy, now)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pruned != 0 {
		t.Fatalf("pruned = %d, want 0 (snapshot younger than the 30-day floor)", pruned)
	}
}

func TestRunNeverPrunesWhenSelfHosted(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, room := setUpRoomWithOneOp(t, dbPath)
	defer st.Close()

	cursor1, err := st.AppendOp(room, make([]byte, 32), make([]byte, 32), 1, 0, []byte("op1"))
	if err != nil {
		t.Fatalf("AppendOp: %v", err)
	}
	if err := st.PutSnapshot(room, cursor1, []byte("snapshot")); err != nil {
		t.Fatalf("PutSnapshot: %v", err)
	}

	now := time.Now()
	backdate(t, dbPath, "snapshots", room, "created_at", now.Add(-365*24*time.Hour))
	backdate(t, dbPath, "ops", room, "received_at", now.Add(-365*24*time.Hour))

	policy := limits.NewPolicy("none", "") // self-hosted default: always unlimited
	pruned, err := Run(st, policy, now)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pruned != 0 {
		t.Fatalf("pruned = %d, want 0 (self-hosted/-limits=none is always unlimited retention)", pruned)
	}
}
