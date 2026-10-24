package main

import (
	"testing"

	"github.com/squaddle-org/relay/internal/store"
)

func TestGenerateVoucherCodeMintableAndRedeemable(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	code, codeHash := generateVoucherCode()
	if code == "" || len(codeHash) != 32 {
		t.Fatalf("generateVoucherCode() = %q, %d-byte hash", code, len(codeHash))
	}

	duration := 30
	if err := st.MintVoucher(codeHash, "boosted", &duration); err != nil {
		t.Fatalf("MintVoucher: %v", err)
	}

	tier, got, err := st.RedeemVoucher(codeHash, 1_700_000_000)
	if err != nil {
		t.Fatalf("RedeemVoucher: %v", err)
	}
	if tier != "boosted" || got == nil || *got != 30 {
		t.Fatalf("RedeemVoucher = %q, %v, want boosted, 30", tier, got)
	}

	if _, _, err := st.RedeemVoucher(codeHash, 1_700_000_001); err != store.ErrVoucherAlreadyRedeemed {
		t.Fatalf("second RedeemVoucher: got %v, want ErrVoucherAlreadyRedeemed", err)
	}
}

func TestGenerateVoucherCodeIsUniqueAndMatchesItsOwnHash(t *testing.T) {
	codeA, hashA := generateVoucherCode()
	codeB, hashB := generateVoucherCode()
	if codeA == codeB {
		t.Fatalf("two generated codes collided: %q", codeA)
	}
	if string(hashA) == string(hashB) {
		t.Fatalf("two generated code hashes collided")
	}
}
