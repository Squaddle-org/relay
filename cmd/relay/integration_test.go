package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/squaddle-org/relay/internal/api"
	"github.com/squaddle-org/relay/internal/limits"
	"github.com/squaddle-org/relay/internal/membership"
	"github.com/squaddle-org/relay/internal/proto"
	"github.com/squaddle-org/relay/internal/store"
)

// integrationActor is a minimal self-contained simulated client: its own identity, device key,
// and the signing helpers needed to build every signed structure a real client would. Duplicated
// (not shared) from the same pattern used in internal/api/internal/limits's own tests - Go
// doesn't let packages import each other's _test.go files, and a real end-to-end test belongs at
// this top level (cmd/relay), driving the actual binary's wiring (store.Open + api.NewRouter),
// not any single internal package's test helpers.
type integrationActor struct {
	userPub    ed25519.PublicKey
	userPriv   ed25519.PrivateKey
	devicePub  ed25519.PublicKey
	devicePriv ed25519.PrivateKey
	cert       proto.DeviceCert
}

func newIntegrationActor(t *testing.T, seedByte byte, label string) integrationActor {
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
	return integrationActor{userPub, userPriv, devicePub, devicePriv, cert}
}

func (a integrationActor) buildEntry(t *testing.T, room []byte, index uint64, prev []byte, typ uint64, body map[uint64]any) proto.LogEntry {
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

func (a integrationActor) buildOp(t *testing.T, room []byte, epoch, seq, lamport uint64) proto.OpEnvelope {
	t.Helper()
	e := proto.OpEnvelope{V: 1, Room: room, Epoch: epoch, Author: a.userPub, Device: a.devicePub, Seq: seq, Lamport: lamport, Nonce: make([]byte, 24), Ct: []byte("opaque-ciphertext")}
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

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func authHeaderFor(devicePriv ed25519.PrivateKey, devicePub ed25519.PublicKey, method, pathAndQuery string, body []byte, at time.Time) string {
	ts := strconv.FormatInt(at.Unix(), 10)
	reqLine := method + "\n" + pathAndQuery + "\n" + ts + "\n"
	signingInput := proto.SigningInput("req", append([]byte(reqLine), proto.Blake2b256(body)...))
	sig := ed25519.Sign(devicePriv, signingInput)
	return fmt.Sprintf("SQDL1 device=%s, ts=%s, sig=%s", b64(devicePub), ts, b64(sig))
}

// doSigned issues a real HTTP request (over the loopback network, via httptest.Server - not
// h.ServeHTTP) signed per PROTOCOL.md §5.
func doSigned(t *testing.T, baseURL string, a integrationActor, method, path string, body []byte, at time.Time) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, baseURL+path, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", authHeaderFor(a.devicePriv, a.devicePub, method, path, body, at))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// TestTwoSimulatedClientsAgainstRealRelayHTTP is the full M2 integration test: an httptest.Server
// wrapping the actual api.NewRouter + a real, temp-file-backed SQLite store (store.Open against
// a file, not :memory: - exercising the exact same code path cmd/relay's own main() uses, just
// without spawning a second OS process) drives genesis -> inviteCreate (requiresApproval) -> join
// -> approve -> an ops round trip, with every request a real, independently-signed HTTP call
// from two distinct simulated identities.
func TestTwoSimulatedClientsAgainstRealRelayHTTP(t *testing.T) {
	dbFile, err := os.CreateTemp(t.TempDir(), "relay-integration-*.db")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	dbFile.Close()

	st, err := store.Open(dbFile.Name())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	policy := limits.NewPolicy("none", "")
	server := httptest.NewServer(api.NewRouter(logger, st, policy))
	defer server.Close()

	clock := &struct {
		base time.Time
		n    int
	}{base: time.Now()}
	next := func() time.Time {
		clock.n++
		return clock.base.Add(time.Duration(clock.n) * time.Second)
	}

	owner := newIntegrationActor(t, 1, "Owner Phone")
	joiner := newIntegrationActor(t, 2, "Joiner Phone")

	// 1. Both devices register.
	for _, a := range []integrationActor{owner, joiner} {
		cbor, err := a.cert.FullCbor()
		if err != nil {
			t.Fatalf("FullCbor: %v", err)
		}
		path := "/v1/users/" + b64(a.userPub) + "/devices/" + b64(a.devicePub)
		resp := doSigned(t, server.URL, a, http.MethodPut, path, cbor, next())
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("PUT device: got %d", resp.StatusCode)
		}
		resp.Body.Close()
	}

	// 2. Owner creates the room (genesis).
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i + 10)
	}
	roomID := membership.RoomID(owner.userPub, nonce)
	genesis := owner.buildEntry(t, roomID, 0, nil, proto.EntryGenesis, map[uint64]any{0: nonce, 1: "relay.squaddle.org", 2: make([]byte, 48)})
	genesisCbor, err := genesis.FullCbor()
	if err != nil {
		t.Fatalf("FullCbor: %v", err)
	}
	resp := doSigned(t, server.URL, owner, http.MethodPost, "/v1/rooms", genesisCbor, next())
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /rooms: got %d, body %s", resp.StatusCode, b)
	}
	resp.Body.Close()

	// 3. Owner creates an approval-required invite.
	inviteID := make([]byte, 16)
	for i := range inviteID {
		inviteID[i] = byte(i + 20)
	}
	inviteCreate := owner.buildEntry(t, roomID, 1, genesis.EntryHash(), proto.EntryInviteCreate, map[uint64]any{0: inviteID, 3: true, 4: "member"})
	inviteCreateCbor, err := inviteCreate.FullCbor()
	if err != nil {
		t.Fatalf("FullCbor: %v", err)
	}
	logPath := "/v1/rooms/" + b64(roomID) + "/log"
	resp = doSigned(t, server.URL, owner, http.MethodPost, logPath, inviteCreateCbor, next())
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST inviteCreate: got %d, body %s", resp.StatusCode, b)
	}
	resp.Body.Close()

	// 4. Joiner joins -> pending (approval required).
	join := joiner.buildEntry(t, roomID, 2, inviteCreate.EntryHash(), proto.EntryJoin, map[uint64]any{0: inviteID})
	joinCbor, err := join.FullCbor()
	if err != nil {
		t.Fatalf("FullCbor: %v", err)
	}
	resp = doSigned(t, server.URL, joiner, http.MethodPost, logPath, joinCbor, next())
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST join: got %d, body %s", resp.StatusCode, b)
	}
	resp.Body.Close()

	// 5. Owner approves the joiner -> member.
	approve := owner.buildEntry(t, roomID, 3, join.EntryHash(), proto.EntryApprove, map[uint64]any{0: joiner.userPub, 1: make([]byte, 48)})
	approveCbor, err := approve.FullCbor()
	if err != nil {
		t.Fatalf("FullCbor: %v", err)
	}
	resp = doSigned(t, server.URL, owner, http.MethodPost, logPath, approveCbor, next())
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST approve: got %d, body %s", resp.StatusCode, b)
	}
	resp.Body.Close()

	// 6. The now-member joiner posts an op...
	op := joiner.buildOp(t, roomID, 0, 1, 1)
	opBatch, err := proto.EncodeCanonical([]proto.OpEnvelope{op})
	if err != nil {
		t.Fatalf("encoding batch: %v", err)
	}
	opsPath := "/v1/rooms/" + b64(roomID) + "/ops"
	resp = doSigned(t, server.URL, joiner, http.MethodPost, opsPath, opBatch, next())
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST ops: got %d, body %s", resp.StatusCode, b)
	}
	var postResp struct {
		Cursors []int64 `json:"cursors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&postResp); err != nil {
		t.Fatalf("decoding POST ops response: %v", err)
	}
	resp.Body.Close()
	if len(postResp.Cursors) != 1 {
		t.Fatalf("POST ops cursors = %v, want exactly 1", postResp.Cursors)
	}

	// ...and the owner can read it back.
	resp = doSigned(t, server.URL, owner, http.MethodGet, opsPath, nil, next())
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET ops: got %d, body %s", resp.StatusCode, b)
	}
	opsBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("reading GET ops body: %v", err)
	}
	if len(opsBody) == 0 {
		t.Fatalf("GET ops: empty body")
	}

	// Sanity: a non-member device can still register and hit a signed endpoint, but a stale/
	// unauthorized entry still gets rejected by the real state machine - the integration test
	// should see a real reject, not just real accepts.
	badEntry := joiner.buildEntry(t, roomID, 4, approve.EntryHash(), proto.EntryTransferOwner, map[uint64]any{0: joiner.userPub})
	badCbor, err := badEntry.FullCbor()
	if err != nil {
		t.Fatalf("FullCbor: %v", err)
	}
	resp = doSigned(t, server.URL, joiner, http.MethodPost, logPath, badCbor, next())
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unauthorized transferOwner: got %d, body %s, want 403", resp.StatusCode, b)
	}
	resp.Body.Close()
}
