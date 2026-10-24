package main

import (
	"crypto/rand"
	"encoding/base32"
	"strings"

	"github.com/squaddle-org/relay/internal/proto"
)

// generateVoucherCode returns a fresh, random, printable voucher code and its BLAKE2b-256 hash
// (what's actually persisted - schema.sql's `vouchers.code_hash`, "never store plaintext"). The
// hash is over the code *string* itself (matching postVoucherEntitlement's redemption check,
// api/limits.go), not over the raw random bytes - simplest, and avoids any base32-decode step at
// redemption time.
func generateVoucherCode() (code string, codeHash []byte) {
	raw := make([]byte, 20) // 160 bits
	if _, err := rand.Read(raw); err != nil {
		panic(err) // crypto/rand failing is not something this process can recover from
	}
	code = strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	return code, proto.Blake2b256([]byte(code))
}
