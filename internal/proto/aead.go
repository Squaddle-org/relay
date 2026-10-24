package proto

import "golang.org/x/crypto/chacha20poly1305"

// AeadEncrypt is crypto_aead_xchacha20poly1305_ietf_encrypt (PROTOCOL.md §1). nonce MUST be 24
// random bytes (never reused for the same key).
func AeadEncrypt(key, nonce, plaintext, associatedData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, associatedData), nil
}

// AeadDecrypt is crypto_aead_xchacha20poly1305_ietf_decrypt. Returns an error (never panics) on
// any authentication failure - wrong key, tampered ciphertext, or wrong associated data.
func AeadDecrypt(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, associatedData)
}
