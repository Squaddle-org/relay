package proto

import (
	"crypto/ed25519"
	"crypto/sha512"

	"golang.org/x/crypto/curve25519"
)

// Ed25519SeedKeypairPublic is crypto_sign_seed_keypair(seed)'s public key - RFC 8032's
// deterministic Ed25519 key derivation, identical across implementations (same algorithm, not an
// implementation-specific choice), used to cross-check identity.json's userKey.
func Ed25519SeedKeypairPublic(seed []byte) []byte {
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}

// Ed25519Verify verifies a detached Ed25519 signature (crypto_sign_verify_detached).
func Ed25519Verify(publicKey, message, sig []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, message, sig)
}

// X25519SeedKeypairPublic is crypto_box_seed_keypair(seed)'s public key. Per libsodium's actual
// source (box_curve25519xsalsa20poly1305.c): the X25519 secret scalar is SHA-512(seed)[0:32] -
// *not* BLAKE2b, despite every other hash in this protocol being BLAKE2b; this is libsodium's own
// fixed construction for this one function, confirmed against libsodium's source directly (a
// first attempt using BLAKE2b-256(seed) failed identity.json's userBoxKey vectors). The relay
// never needs the matching secret key (it never seals/opens boxes - see package doc), only this
// public-key derivation, to cross-check identity.json's userBoxKey.
func X25519SeedKeypairPublic(seed []byte) []byte {
	hash := sha512.Sum512(seed)
	scalar := hash[:32]
	pub, err := curve25519.X25519(scalar, curve25519.Basepoint)
	if err != nil {
		panic(err) // scalar is always exactly 32 bytes here; X25519 only errors on wrong-sized input
	}
	return pub
}
