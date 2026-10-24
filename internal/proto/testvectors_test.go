package proto

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// loadVectors reads a spec test-vector file via SQUADDLE_TESTVECTORS (set by the Makefile's
// `make test` / `make vectors` targets). Skips (not fails) if unset, so `go test ./...` without
// `make` still runs everything else.
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

func vstrings(v map[string]any, key string) []string {
	arr, _ := v[key].([]any)
	out := make([]string, len(arr))
	for i, a := range arr {
		out[i], _ = a.(string)
	}
	return out
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
