package webpush

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateKeypairProducesAValidP256Key(t *testing.T) {
	key, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if key.Curve != key.PublicKey.Curve {
		t.Fatal("private/public curve mismatch")
	}
	pub := PublicKeyBase64URL(&key.PublicKey)
	if len(pub) == 0 {
		t.Fatal("empty public key encoding")
	}
}

func TestPrivateKeyPEMRoundTrips(t *testing.T) {
	key, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	pemBytes, err := EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM: %v", err)
	}
	if !strings.Contains(string(pemBytes), "EC PRIVATE KEY") {
		t.Fatalf("unexpected PEM block type: %s", pemBytes)
	}
	decoded, err := DecodePrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("DecodePrivateKeyPEM: %v", err)
	}
	if decoded.D.Cmp(key.D) != 0 {
		t.Fatal("decoded private scalar does not match original")
	}
}

func TestDecodePrivateKeyPEMRejectsGarbage(t *testing.T) {
	if _, err := DecodePrivateKeyPEM([]byte("not pem at all")); err == nil {
		t.Fatal("expected an error for non-PEM input")
	}
	if _, err := DecodePrivateKeyPEM([]byte("-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----\n")); err == nil {
		t.Fatal("expected an error for a wrong PEM block type")
	}
}

func TestSignJWTRoundTripsAndVerifies(t *testing.T) {
	key, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	token, err := SignJWT(key, "https://push.example.org", "mailto:ops@squaddle.org", now, 12*time.Hour)
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a 3-part JWT, got %d parts", len(parts))
	}
	if err := VerifyJWT(token, &key.PublicKey); err != nil {
		t.Fatalf("VerifyJWT on a freshly signed token: %v", err)
	}
}

func TestSignJWTSignatureIsRawNotASN1DER(t *testing.T) {
	// RFC 7518 §3.4: the JWS signature is raw r‖s, 32 bytes each - this is the one real gotcha
	// ecdsa.Sign's default DER output would silently get wrong, so pin the exact byte length.
	key, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	token, err := SignJWT(key, "https://push.example.org", "mailto:ops@squaddle.org", time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	parts := strings.Split(token, ".")
	sigB64 := parts[2]
	// base64.RawURLEncoding of exactly 64 bytes is 86 characters (ceil(64*4/3) with no padding).
	if len(sigB64) != 86 {
		t.Fatalf("expected an 86-char base64url signature (raw 64-byte r‖s), got %d chars", len(sigB64))
	}
}

func TestVerifyJWTRejectsTamperedToken(t *testing.T) {
	key, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	token, err := SignJWT(key, "https://push.example.org", "mailto:ops@squaddle.org", time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	tampered := token[:len(token)-4] + "AAAA"
	if err := VerifyJWT(tampered, &key.PublicKey); err == nil {
		t.Fatal("expected a tampered token to fail verification")
	}
}

func TestVerifyJWTRejectsWrongKey(t *testing.T) {
	key, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	other, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (other): %v", err)
	}
	token, err := SignJWT(key, "https://push.example.org", "mailto:ops@squaddle.org", time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	if err := VerifyJWT(token, &other.PublicKey); err == nil {
		t.Fatal("expected verification against the wrong public key to fail")
	}
}

func TestVerifyJWTRejectsMalformedToken(t *testing.T) {
	if err := VerifyJWT("not.a.jwt.at.all", nil); err == nil {
		t.Fatal("expected a malformed token (too many parts) to fail")
	}
	if err := VerifyJWT("onlyonepart", nil); err == nil {
		t.Fatal("expected a malformed token (no dots) to fail")
	}
}
