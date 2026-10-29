package main

import (
	"bufio"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/squaddle-org/relay/internal/proto"
	"github.com/squaddle-org/relay/internal/store"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns everything written to
// it - needed to recover the plaintext voucher code runVoucherCLI prints (and never stores).
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	real := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = real }()

	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		_, _ = io.Copy(&sb, bufio.NewReader(r))
		done <- sb.String()
	}()

	fn()
	_ = w.Close()
	return <-done
}

// TestRunVoucherCLIActuallyHonorsItsFlags is a regression test: `fs.Parse` was previously called
// on args still carrying the leading "mint" positional token, which made flag.Parse stop
// immediately (it stops at the first non-flag argument) - so -db/-tier/-duration-days were all
// silently ignored in favor of their defaults. A command with an explicit -db used to write a
// *different* file (./relay.db, 122KB left behind right here from a real run) while reporting
// success - confirmed by end-to-end testing against a real file, not something a :memory:-only
// test like the one above could ever have caught.
func TestRunVoucherCLIActuallyHonorsItsFlags(t *testing.T) {
	dbPath := t.TempDir() + "/explicit-path.db"

	output := captureStdout(t, func() {
		runVoucherCLI([]string{"mint", "-tier=unlimited", "-duration-days=7", "-db", dbPath})
	})

	lines := strings.Split(strings.TrimSpace(output), "\n")
	code := lines[len(lines)-1]
	if code == "" {
		t.Fatalf("no voucher code captured from output: %q", output)
	}

	if _, err := os.Stat("relay.db"); err == nil {
		t.Fatal("runVoucherCLI wrote to the default ./relay.db instead of the explicit -db path")
	}

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("opening the explicit -db path: %v", err)
	}
	defer st.Close()

	// -tier=unlimited means duration-days (7) must be ignored (§8.1a: unlimited is always
	// permanent) - this is the store layer's own job, checked here only as end-to-end proof that
	// -tier actually reached it (not silently defaulted to "boosted").
	tier, duration, err := st.RedeemVoucher(proto.Blake2b256([]byte(code)), 1_700_000_000)
	if err != nil {
		t.Fatalf("RedeemVoucher on the minted code: %v", err)
	}
	if tier != "unlimited" {
		t.Fatalf("tier = %q, want %q (the -tier flag was not honored)", tier, "unlimited")
	}
	if duration != nil {
		t.Fatalf("duration = %v, want nil for an unlimited voucher", *duration)
	}
}

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
