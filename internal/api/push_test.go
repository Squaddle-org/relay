package api

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/squaddle-org/relay/internal/limits"
	"github.com/squaddle-org/relay/internal/proto"
	"github.com/squaddle-org/relay/internal/store"
	"github.com/squaddle-org/relay/internal/webpush"
)

// newTestRouterWithVapid is newTestRouter's VAPID-enabled sibling - every other test in this
// package passes a nil key (push silently disabled), also exercised directly below in
// TestPushNoVapidKeyMeansNotifyIsANoOp.
func newTestRouterWithVapid(t *testing.T) (http.Handler, *ecdsa.PrivateKey) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	key, err := webpush.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	policy := limits.NewPolicy("none", "")
	h := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), st, policy, "", key)
	return h, key
}

var vapidAuthHeaderPattern = regexp.MustCompile(`^vapid t=([^,]+), k=(.+)$`)

// TestPushSendsRealVapidAuthenticatedEmptyBodyWebPush exercises the full path: register a push
// endpoint pointing at a real httptest.Server, join a room, post a content-plane op as the other
// member, and assert the *actual* outbound push request (not a mock) carries a well-formed
// `Authorization: vapid t=...,k=...` header whose JWT verifies against the relay's own public
// key, a `TTL` header, and a genuinely empty body (PROTOCOL.md §6, ADR-0013).
func TestPushSendsRealVapidAuthenticatedEmptyBodyWebPush(t *testing.T) {
	h, vapidKey := newTestRouterWithVapid(t)

	type captured struct {
		contentLength int64
		ttl           string
		authorization string
	}
	received := make(chan captured, 1)
	pushEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		c := captured{contentLength: int64(len(bodyBytes)), ttl: r.Header.Get("TTL"), authorization: r.Header.Get("Authorization")}
		select {
		case received <- c:
		default:
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer pushEndpoint.Close()

	owner := newTestActor(t, 30, "Owner Phone")
	member := newTestActor(t, 31, "Member Phone")
	roomID := setUpRoomWithOwnerAndMember(t, h, owner, member)

	regBody := []byte(fmt.Sprintf(`{"endpoint":%q}`, pushEndpoint.URL))
	reqPush, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPost, "/v1/push", regBody)
	recPush := httptest.NewRecorder()
	h.ServeHTTP(recPush, reqPush)
	if recPush.Code != http.StatusNoContent {
		t.Fatalf("POST /v1/push: got %d, body %s", recPush.Code, recPush.Body.String())
	}

	// member posts an op - owner (who registered the endpoint above) should get woken.
	op := member.buildOp(t, roomID, 0, 1, 1)
	opCbor, err := proto.EncodeCanonical([]proto.OpEnvelope{op})
	if err != nil {
		t.Fatalf("encoding batch: %v", err)
	}
	reqOps, _ := signedRequest(t, member.devicePriv, member.devicePub, http.MethodPost, "/v1/rooms/"+b64(roomID)+"/ops", opCbor)
	recOps := httptest.NewRecorder()
	h.ServeHTTP(recOps, reqOps)
	if recOps.Code != http.StatusCreated {
		t.Fatalf("POST ops: got %d, body %s", recOps.Code, recOps.Body.String())
	}

	var got captured
	select {
	case got = <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("push endpoint never received a request")
	}

	if got.contentLength != 0 {
		t.Fatalf("expected an empty push body, got %d bytes", got.contentLength)
	}
	if got.ttl == "" {
		t.Fatal("missing TTL header (RFC 8030 §5.2)")
	}
	m := vapidAuthHeaderPattern.FindStringSubmatch(got.authorization)
	if m == nil {
		t.Fatalf("Authorization header %q does not match `vapid t=..., k=...`", got.authorization)
	}
	jwt, pubKeyB64 := m[1], m[2]
	if pubKeyB64 != webpush.PublicKeyBase64URL(&vapidKey.PublicKey) {
		t.Fatalf("k= in Authorization header does not match the relay's own VAPID public key")
	}
	if err := webpush.VerifyJWT(jwt, &vapidKey.PublicKey); err != nil {
		t.Fatalf("VAPID JWT in Authorization header does not verify against the relay's own public key: %v", err)
	}
}

// TestPushNoVapidKeyMeansNotifyIsANoOp confirms a relay started without -vapid-private-key-file
// (the default, nil key) never attempts to send anything - not an error, a deliberate permissive
// default (ADR-0013).
func TestPushNoVapidKeyMeansNotifyIsANoOp(t *testing.T) {
	h, _ := newTestRouter(t) // nil VAPID key

	called := make(chan struct{}, 1)
	pushEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case called <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer pushEndpoint.Close()

	owner := newTestActor(t, 32, "Owner Phone")
	member := newTestActor(t, 33, "Member Phone")
	roomID := setUpRoomWithOwnerAndMember(t, h, owner, member)

	regBody := []byte(fmt.Sprintf(`{"endpoint":%q}`, pushEndpoint.URL))
	reqPush, _ := signedRequest(t, owner.devicePriv, owner.devicePub, http.MethodPost, "/v1/push", regBody)
	recPush := httptest.NewRecorder()
	h.ServeHTTP(recPush, reqPush)
	if recPush.Code != http.StatusNoContent {
		t.Fatalf("POST /v1/push: got %d", recPush.Code)
	}

	op := member.buildOp(t, roomID, 0, 1, 1)
	opCbor, err := proto.EncodeCanonical([]proto.OpEnvelope{op})
	if err != nil {
		t.Fatalf("encoding batch: %v", err)
	}
	reqOps, _ := signedRequest(t, member.devicePriv, member.devicePub, http.MethodPost, "/v1/rooms/"+b64(roomID)+"/ops", opCbor)
	recOps := httptest.NewRecorder()
	h.ServeHTTP(recOps, reqOps)
	if recOps.Code != http.StatusCreated {
		t.Fatalf("POST ops: got %d, body %s", recOps.Code, recOps.Body.String())
	}

	select {
	case <-called:
		t.Fatal("push endpoint received a request even though no VAPID key was configured")
	case <-time.After(300 * time.Millisecond):
		// expected: nothing arrives
	}
}

// TestGetVapidPublicKey covers both states: configured (200, matches the key used) and
// unconfigured (404, push disabled - ADR-0013).
func TestGetVapidPublicKey(t *testing.T) {
	h, vapidKey := newTestRouterWithVapid(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/push/vapid", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/push/vapid: got %d", rec.Code)
	}
	var body struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body.PublicKey != webpush.PublicKeyBase64URL(&vapidKey.PublicKey) {
		t.Fatalf("GET /v1/push/vapid returned a different key than the one configured")
	}

	hNoKey, _ := newTestRouter(t)
	reqNoKey := httptest.NewRequest(http.MethodGet, "/v1/push/vapid", nil)
	recNoKey := httptest.NewRecorder()
	hNoKey.ServeHTTP(recNoKey, reqNoKey)
	if recNoKey.Code != http.StatusNotFound {
		t.Fatalf("GET /v1/push/vapid with no key configured: got %d, want 404", recNoKey.Code)
	}
}
