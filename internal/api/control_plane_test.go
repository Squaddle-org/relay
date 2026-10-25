package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/squaddle-org/relay/internal/limits"
	"github.com/squaddle-org/relay/internal/membership"
	"github.com/squaddle-org/relay/internal/proto"
	"github.com/squaddle-org/relay/internal/store"
)

// testActor mirrors the pattern used in internal/store's own tests and core's own
// MembershipStateTest.Actor - duplicated here (not shared) since Go doesn't let packages import
// each other's _test.go files, and it's small enough not to need a shared internal testutil
// package for three call sites.
type testActor struct {
	userPub    ed25519.PublicKey
	userPriv   ed25519.PrivateKey
	devicePub  ed25519.PublicKey
	devicePriv ed25519.PrivateKey
	cert       proto.DeviceCert
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

// signedRequest builds an httptest request with a valid PROTOCOL.md §5 Authorization header,
// signed by devicePriv/devicePub, at the current time with a fresh random nonce. Returns the
// header string too, so a caller testing replay rejection can reuse the exact same header
// (device+ts+nonce+sig) on a second, independent *http.Request (the first one's Body is consumed
// by the server and can't be resent).
func signedRequest(t *testing.T, devicePriv ed25519.PrivateKey, devicePub ed25519.PublicKey, method, target string, body []byte) (*http.Request, string) {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand nonce: %v", err)
	}
	reqLine := method + "\n" + req.URL.RequestURI() + "\n" + ts + "\n"
	signingInput := proto.SigningInput("req", append(append([]byte(reqLine), nonce...), proto.Blake2b256(body)...))
	sig := ed25519.Sign(devicePriv, signingInput)
	header := fmt.Sprintf("SQDL1 device=%s, ts=%s, nonce=%s, sig=%s",
		base64.RawURLEncoding.EncodeToString(devicePub), ts, base64.RawURLEncoding.EncodeToString(nonce), base64.RawURLEncoding.EncodeToString(sig))
	req.Header.Set("Authorization", header)
	return req, header
}

func newTestRouter(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	policy := limits.NewPolicy("none", "") // unlimited, same as every test assumed before limits existed
	return NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), st, policy), st
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestPutDeviceThenList(t *testing.T) {
	h, _ := newTestRouter(t)
	owner := newTestActor(t, 1, "Owner Phone")
	certCbor, err := owner.cert.FullCbor()
	if err != nil {
		t.Fatalf("FullCbor: %v", err)
	}

	target := fmt.Sprintf("/v1/users/%s/devices/%s", b64(owner.userPub), b64(owner.devicePub))
	req, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPut, target, certCbor)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PUT device: got %d, body %s", rec.Code, rec.Body.String())
	}

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/v1/users/"+b64(owner.userPub)+"/devices", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("GET devices: got %d", rec2.Code)
	}
	if rec2.Body.Len() == 0 {
		t.Fatalf("GET devices: empty body")
	}
}

func TestPutDeviceRejectsWrongSignerAndReplay(t *testing.T) {
	h, _ := newTestRouter(t)
	owner := newTestActor(t, 2, "Owner Phone")
	stranger := newTestActor(t, 3, "Stranger Phone")
	certCbor, err := owner.cert.FullCbor()
	if err != nil {
		t.Fatalf("FullCbor: %v", err)
	}
	target := fmt.Sprintf("/v1/users/%s/devices/%s", b64(owner.userPub), b64(owner.devicePub))

	// Signed by a different device than the one being registered -> forbidden.
	req, _ := signedRequest(t, stranger.devicePriv, stranger.devicePub, http.MethodPut, target, certCbor)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong signer: got %d, want 403", rec.Code)
	}

	// Correct signer: first request succeeds...
	req2, header := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPut, target, certCbor)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("PUT device: got %d, body %s", rec2.Code, rec2.Body.String())
	}

	// ...replaying the exact same signature (fresh request, same header+body) must be rejected.
	req3 := httptest.NewRequest(http.MethodPut, target, bytes.NewReader(certCbor))
	req3.Header.Set("Authorization", header)
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("replay: got %d, want 401", rec3.Code)
	}
}

func TestRoomLifecycleOverHTTP(t *testing.T) {
	h, _ := newTestRouter(t)
	owner := newTestActor(t, 4, "Owner Phone")

	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i + 40)
	}
	roomID := membership.RoomID(owner.userPub, nonce)
	genesis := owner.buildEntry(t, roomID, 0, nil, proto.EntryGenesis, map[uint64]any{
		0: nonce, 1: "relay.squaddle.org", 2: make([]byte, 48),
	})
	genesisCbor, err := genesis.FullCbor()
	if err != nil {
		t.Fatalf("FullCbor: %v", err)
	}

	req, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPost, "/v1/rooms", genesisCbor)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /rooms: got %d, body %s", rec.Code, rec.Body.String())
	}

	// Creating the same room again must 409.
	req2, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPost, "/v1/rooms", genesisCbor)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("duplicate POST /rooms: got %d, want 409", rec2.Code)
	}

	// Append a second entry (roomSettings) and read the log back.
	settings := owner.buildEntry(t, roomID, 1, genesis.EntryHash(), proto.EntryRoomSettings, map[uint64]any{})
	settingsCbor, err := settings.FullCbor()
	if err != nil {
		t.Fatalf("FullCbor: %v", err)
	}
	logTarget := "/v1/rooms/" + b64(roomID) + "/log"
	req3, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPost, logTarget, settingsCbor)
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusCreated {
		t.Fatalf("POST log: got %d, body %s", rec3.Code, rec3.Body.String())
	}

	req4, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodGet, logTarget, nil)
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusOK {
		t.Fatalf("GET log: got %d", rec4.Code)
	}
	if rec4.Body.Len() == 0 {
		t.Fatalf("GET log: empty body")
	}

	// A stale prev (reusing genesis as prev for a second "index 1" entry) must 409 stale_head.
	stale := owner.buildEntry(t, roomID, 1, genesis.EntryHash(), proto.EntryRoomSettings, map[uint64]any{})
	staleCbor, err := stale.FullCbor()
	if err != nil {
		t.Fatalf("FullCbor: %v", err)
	}
	req5, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPost, logTarget, staleCbor)
	rec5 := httptest.NewRecorder()
	h.ServeHTTP(rec5, req5)
	if rec5.Code != http.StatusConflict {
		t.Fatalf("stale POST log: got %d, want 409", rec5.Code)
	}
}

func TestInviteEnvelopeHTTPRoundTripAndAuthorization(t *testing.T) {
	h, _ := newTestRouter(t)
	owner := newTestActor(t, 5, "Owner Phone")
	member := newTestActor(t, 6, "Member Phone")

	// Register both devices (needed so callerIsOwnerOrAdmin can resolve device -> user).
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
		nonce[i] = byte(i + 50)
	}
	roomID := membership.RoomID(owner.userPub, nonce)
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

	// The envelope lifecycle (expiry/exhaustion/revoked) lives in the replayed membership state
	// (invites.go), so the invite must actually exist there via a real inviteCreate entry before
	// any envelope PUT/GET makes sense - a bare envelope with no matching invite record 404s.
	inviteID := make([]byte, 16)
	for i := range inviteID {
		inviteID[i] = byte(i + 70)
	}
	inviteCreate := owner.buildEntry(t, roomID, 1, genesis.EntryHash(), proto.EntryInviteCreate, map[uint64]any{
		0: inviteID, 3: false, 4: "member",
	})
	inviteCreateCbor, err := inviteCreate.FullCbor()
	if err != nil {
		t.Fatalf("FullCbor: %v", err)
	}
	logTarget := "/v1/rooms/" + b64(roomID) + "/log"
	reqInvite, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPost, logTarget, inviteCreateCbor)
	recInvite := httptest.NewRecorder()
	h.ServeHTTP(recInvite, reqInvite)
	if recInvite.Code != http.StatusCreated {
		t.Fatalf("POST inviteCreate: got %d, body %s", recInvite.Code, recInvite.Body.String())
	}

	envelopeTarget := "/v1/invites/" + b64(roomID) + "/" + b64(inviteID) + "/envelope"
	envelopeBytes := []byte("opaque-envelope-bytes")

	// A non-admin member must not be able to upload an envelope.
	reqMember, _ := signedRequest(t, member.devicePriv, member.devicePub, http.MethodPut, envelopeTarget, envelopeBytes)
	recMember := httptest.NewRecorder()
	h.ServeHTTP(recMember, reqMember)
	if recMember.Code != http.StatusForbidden {
		t.Fatalf("member PUT envelope: got %d, want 403", recMember.Code)
	}

	// The owner can.
	reqOwner, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPut, envelopeTarget, envelopeBytes)
	recOwner := httptest.NewRecorder()
	h.ServeHTTP(recOwner, reqOwner)
	if recOwner.Code != http.StatusNoContent {
		t.Fatalf("owner PUT envelope: got %d, body %s", recOwner.Code, recOwner.Body.String())
	}

	// GET is unauthenticated and returns the stored bytes verbatim.
	recGet := httptest.NewRecorder()
	h.ServeHTTP(recGet, httptest.NewRequest(http.MethodGet, envelopeTarget, nil))
	if recGet.Code != http.StatusOK || !bytes.Equal(recGet.Body.Bytes(), envelopeBytes) {
		t.Fatalf("GET envelope: got %d %q, want 200 %q", recGet.Code, recGet.Body.Bytes(), envelopeBytes)
	}
}

func TestLinkMailboxRoundTrip(t *testing.T) {
	h, _ := newTestRouter(t)
	code := make([]byte, 16)
	for i := range code {
		code[i] = byte(i + 200)
	}
	target := "/v1/link/" + b64(code)
	blob := []byte("ephemeral-link-blob")

	recPost := httptest.NewRecorder()
	h.ServeHTTP(recPost, httptest.NewRequest(http.MethodPost, target, bytes.NewReader(blob)))
	if recPost.Code != http.StatusNoContent {
		t.Fatalf("POST link: got %d", recPost.Code)
	}

	recGet := httptest.NewRecorder()
	h.ServeHTTP(recGet, httptest.NewRequest(http.MethodGet, target, nil))
	if recGet.Code != http.StatusOK || !bytes.Equal(recGet.Body.Bytes(), blob) {
		t.Fatalf("GET link: got %d %q", recGet.Code, recGet.Body.Bytes())
	}

	// Second read must be empty - "single read, deletes".
	recGet2 := httptest.NewRecorder()
	h.ServeHTTP(recGet2, httptest.NewRequest(http.MethodGet, target, nil))
	if recGet2.Code != http.StatusNotFound {
		t.Fatalf("second GET link: got %d, want 404", recGet2.Code)
	}
}
