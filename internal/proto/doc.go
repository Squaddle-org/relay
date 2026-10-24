// Package proto holds canonical CBOR encode/decode (PROTOCOL.md §1), the crypto primitives that
// section needs (BLAKE2b-256, Ed25519 verify, X25519/Ed25519 seed-keypair public key derivation,
// crypto_kdf_derive_from_key, XChaCha20-Poly1305-IETF AEAD), BIP39 (§2.1), DeviceCert (§2.2) and
// LogEntry (§3.2). The relay never signs or seals anything itself - it only verifies - but the
// seed-keypair/BIP39/KDF surface here exists to pass identity.json, exactly like core's own
// implementation and spec/tools/verify_vectors.py (Python) do independently in their languages.
package proto
