package store

import "encoding/hex"

// hexKey is the same map-key trick package membership uses: byte slices have no structural
// equality, so the in-memory state cache is keyed by hex string instead.
func hexKey(b []byte) string { return hex.EncodeToString(b) }
