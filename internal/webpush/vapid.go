// Package webpush implements the relay↔push-service transport authentication only: VAPID
// (RFC 8292) key generation/encoding and JWT signing. See spec/adr/0013-vapid-for-web-push.md
// for why this is the one place in the relay that uses ECDSA P-256/ES256 instead of a libsodium
// construction - an external interop mandate from the Web Push ecosystem, not a free choice, and
// scoped only to this one subsystem.
package webpush

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// GenerateKeypair creates a fresh VAPID keypair. RFC 8292 §3 mandates ES256 (ECDSA P-256 +
// SHA-256) - this is not a choice.
func GenerateKeypair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// EncodePrivateKeyPEM is the standard SEC1 EC private key PEM encoding, so the output of `vapid
// generate` is inspectable/regeneratable with any other tool (e.g. `openssl ec`), not a
// Squaddle-specific format.
func EncodePrivateKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("webpush: marshal EC private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// DecodePrivateKeyPEM is EncodePrivateKeyPEM's inverse - what `-vapid-private-key-file` reads.
func DecodePrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("webpush: not a PEM-encoded EC private key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("webpush: parse EC private key: %w", err)
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("webpush: VAPID key must be P-256 (RFC 8292 §3)")
	}
	return key, nil
}

// PublicKeyBase64URL is "base64url, uncompressed P-256 point" (0x04 ‖ X ‖ Y, each coordinate
// padded to 32 bytes) - the form `GET /v1/push/vapid` and the `k=` Authorization parameter both
// use (RFC 8292 §3's own `k` example uses this same uncompressed-point encoding).
func PublicKeyBase64URL(pub *ecdsa.PublicKey) string {
	point := make([]byte, 65)
	point[0] = 0x04
	pub.X.FillBytes(point[1:33])
	pub.Y.FillBytes(point[33:65])
	return base64.RawURLEncoding.EncodeToString(point)
}

type vapidClaims struct {
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Sub string `json:"sub"`
}

const vapidJWTHeader = `{"typ":"JWT","alg":"ES256"}`

// SignJWT builds and signs a VAPID JWT (RFC 8292 §2): `aud` identifies the push service's
// origin, `sub` is a contact URI for that service's operator to reach the sender,  `exp` is
// `now.Add(ttl)`. The signature is the raw `r‖s` concatenation (each padded to 32 bytes) per
// RFC 7518 §3.4 - *not* the ASN.1 DER encoding `ecdsa.Sign` normally produces; a push service
// validating this JWT expects the JOSE/JWS raw form, not DER.
func SignJWT(key *ecdsa.PrivateKey, aud, sub string, now time.Time, ttl time.Duration) (string, error) {
	claims, err := json.Marshal(vapidClaims{Aud: aud, Exp: now.Add(ttl).Unix(), Sub: sub})
	if err != nil {
		return "", fmt.Errorf("webpush: marshal claims: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(vapidJWTHeader)) + "." + base64.RawURLEncoding.EncodeToString(claims)
	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", fmt.Errorf("webpush: sign: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyJWT is used by this package's own tests only - a real push service does the equivalent
// check with the `k=` public key it was handed, this relay never needs to verify its own JWTs in
// production.
func VerifyJWT(token string, pub *ecdsa.PublicKey) error {
	parts, ok := splitJWT(token)
	if !ok {
		return errors.New("webpush: malformed JWT")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return errors.New("webpush: malformed signature")
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return errors.New("webpush: signature does not verify")
	}
	return nil
}

func splitJWT(token string) (parts [3]string, ok bool) {
	start := 0
	idx := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			if idx >= 2 {
				return parts, false
			}
			parts[idx] = token[start:i]
			idx++
			start = i + 1
		}
	}
	if idx != 2 {
		return parts, false
	}
	parts[2] = token[start:]
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return parts, false
	}
	return parts, true
}
