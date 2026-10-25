package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/squaddle-org/relay/internal/proto"
)

// loadVectors is duplicated from internal/proto's own helper of the same name (see
// control_plane_test.go's testActor doc comment: Go can't share _test.go files across packages,
// and this is small enough not to need a shared internal testutil package).
func loadVectors(t *testing.T, name string) []map[string]any {
	t.Helper()
	dir := os.Getenv("SQUADDLE_TESTVECTORS")
	if dir == "" {
		t.Skip("SQUADDLE_TESTVECTORS not set - run via `make test`")
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	var vectors []map[string]any
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return vectors
}

func vobj(v map[string]any, key string) map[string]any {
	m, _ := v[key].(map[string]any)
	return m
}

func vstr(v map[string]any, key string) string {
	s, _ := v[key].(string)
	return s
}

func vbytes(t *testing.T, v map[string]any, key string) []byte {
	t.Helper()
	s := vstr(v, key)
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url decode %s=%q: %v", key, s, err)
	}
	return b
}

// TestRequestAuthVectors is the Go side of the cross-implementation test for PROTOCOL.md §5: it
// reproduces core's exact reqLine+signingInput+header construction (the same formula
// requestAuth() in auth.go verifies against on every real request) and checks it against core's
// vectors, rather than only exercising it indirectly through signedRequest()'s own ad-hoc helper
// in every other test in this package.
func TestRequestAuthVectors(t *testing.T) {
	for _, v := range loadVectors(t, "request-auth.json") {
		name := vstr(v, "name")
		input := vobj(v, "input")
		expected := vobj(v, "expected")

		method := vstr(input, "method")
		pathAndQuery := vstr(input, "pathAndQuery")
		ts, ok := input["ts"].(float64)
		if !ok {
			t.Fatalf("%s: ts is not a number", name)
		}
		tsStr := strconv.FormatInt(int64(ts), 10)
		body := vbytes(t, input, "body")
		device := vbytes(t, input, "device")

		reqLine := method + "\n" + pathAndQuery + "\n" + tsStr + "\n"
		signingInput := proto.SigningInput("req", append([]byte(reqLine), proto.Blake2b256(body)...))
		if !bytes.Equal(signingInput, vbytes(t, expected, "signingInput")) {
			t.Errorf("%s: signingInput mismatch", name)
		}

		sig := vbytes(t, expected, "sig")
		if !proto.Ed25519Verify(device, signingInput, sig) {
			t.Errorf("%s: vector's sig does not verify under relay's own signingInput construction", name)
		}

		wantHeader := fmt.Sprintf("SQDL1 device=%s, ts=%s, sig=%s", base64.RawURLEncoding.EncodeToString(device), tsStr, base64.RawURLEncoding.EncodeToString(sig))
		if wantHeader != vstr(expected, "header") {
			t.Errorf("%s: header = %q, want %q", name, wantHeader, vstr(expected, "header"))
		}
	}
}
