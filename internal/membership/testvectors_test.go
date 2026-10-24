package membership

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// loadVectors mirrors internal/proto's test helper (duplicated, not shared - Go doesn't let
// packages import each other's _test.go files, and this is small enough not to need its own
// internal testutil package for two call sites).
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

func vbool(v map[string]any, key string) (bool, bool) {
	b, ok := v[key].(bool)
	return b, ok
}

func varr(v map[string]any, key string) []any {
	a, _ := v[key].([]any)
	return a
}

func vbytes(t *testing.T, v map[string]any, key string) []byte {
	t.Helper()
	return b64(t, vstr(v, key))
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url decode %q: %v", s, err)
	}
	return b
}
