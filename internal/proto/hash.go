package proto

import "golang.org/x/crypto/blake2b"

// Blake2b256 concatenates parts and returns their BLAKE2b-256 digest (PROTOCOL.md §1,
// crypto_generichash, 32 bytes, no key). golang.org/x/crypto/blake2b's public API covers this
// directly - only crypto_kdf_derive_from_key (salt+personalization) needs the hand-written
// compression function in kdf.go.
func Blake2b256(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	buf := make([]byte, 0, total)
	for _, p := range parts {
		buf = append(buf, p...)
	}
	sum := blake2b.Sum256(buf)
	return sum[:]
}

// SigningInput is the domain-separated signing-input construction every signed structure uses -
// PROTOCOL.md §1: sig = Ed25519(sk, "SQDL1" || domain || 0x00 || BLAKE2b(CBOR(struct without sig))).
func SigningInput(domain string, unsignedCbor []byte) []byte {
	prefix := []byte("SQDL1" + domain + "\x00")
	return append(prefix, Blake2b256(unsignedCbor)...)
}
