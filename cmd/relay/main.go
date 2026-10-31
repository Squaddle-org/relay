package main

import (
	"context"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/squaddle-org/relay/internal/api"
	"github.com/squaddle-org/relay/internal/limits"
	"github.com/squaddle-org/relay/internal/retention"
	"github.com/squaddle-org/relay/internal/store"
	"github.com/squaddle-org/relay/internal/webpush"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "voucher" {
		runVoucherCLI(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "vapid" {
		runVapidCLI(os.Args[2:])
		return
	}
	runServer()
}

// loadVapidKey is ADR-0013: `-vapid-private-key-file` unset is a supported, permissive default
// (push just stays disabled) - only a *given but unreadable/invalid* file fails fast, since that
// means the operator tried to configure push and got it wrong.
func loadVapidKey(path string) *ecdsa.PrivateKey {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reading -vapid-private-key-file:", err)
		os.Exit(1)
	}
	key, err := webpush.DecodePrivateKeyPEM(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parsing -vapid-private-key-file:", err)
		os.Exit(1)
	}
	return key
}

func runServer() {
	listen := flag.String("listen", ":8080", "public listen address")
	metrics := flag.String("metrics", ":9090", "internal metrics/health address")
	dbPath := flag.String("db", "relay.db", "SQLite database path")
	limitsMode := flag.String("limits", "none", "room limits policy: none (self-hosted default) | hosted (PROTOCOL.md §8)")
	unlimitedOwners := flag.String("unlimited-owners", "", "comma-separated base32 user keys; rooms they currently own get tier unlimited (§8.1a)")
	corsOrigins := flag.String("cors-allowed-origins", "", "comma-separated allowed CORS origins for browser clients (empty = no CORS headers sent)")
	vapidKeyFile := flag.String("vapid-private-key-file", "", "PEM-encoded P-256 EC private key for VAPID-authenticated Web Push (ADR-0013); empty = push disabled")
	logLevel := flag.String("log-level", "info", "minimum log level: debug | info | warn | error - debug includes logRequests' own per-request method+pattern line (router.go)")
	flag.Parse()

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintln(os.Stderr, "parsing -log-level:", err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	policy := limits.NewPolicy(*limitsMode, *unlimitedOwners)
	vapidKey := loadVapidKey(*vapidKeyFile)
	logger.Info("starting relay", "listen", *listen, "db", *dbPath, "limits", *limitsMode, "unlimitedOwnersHosted", policy.Hosted, "pushEnabled", vapidKey != nil)

	st, err := store.Open(*dbPath)
	if err != nil {
		logger.Error("opening store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	srv := &http.Server{Addr: *listen, Handler: api.NewRouter(logger, st, policy, *corsOrigins, vapidKey), ReadHeaderTimeout: 10 * time.Second}
	internal := &http.Server{Addr: *metrics, Handler: api.NewInternalRouter(), ReadHeaderTimeout: 5 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	retention.StartPeriodic(ctx, logger, st, policy, retention.DefaultInterval)
	go func() { _ = internal.ListenAndServe() }()
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	_ = internal.Shutdown(shutdown)
}

// runVoucherCLI is the relay admin CLI for minting §8.3 vouchers: `relay voucher mint
// -tier=boosted|unlimited [-duration-days=30] -db=relay.db`. Only `code_hash` is ever stored
// (schema.sql) - the plaintext code is generated here and printed exactly once; the operator is
// responsible for handing it to whoever redeems it via `POST /entitlements`.
func runVoucherCLI(args []string) {
	// "mint" must be checked and stripped *before* flag.Parse, not handled via fs.Arg(0) after
	// - flag.Parse stops at the first non-flag argument, and "mint" (positional, first) would
	// otherwise make it stop immediately, silently never parsing -tier/-duration-days/-db at all
	// (they'd all silently keep their defaults regardless of what's actually passed - found via
	// a real file ending up written to the default ./relay.db instead of an explicit -db path).
	if len(args) < 1 || args[0] != "mint" {
		fmt.Fprintln(os.Stderr, "usage: relay voucher mint -tier=boosted|unlimited [-duration-days=30] [-db=relay.db]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("voucher", flag.ExitOnError)
	dbPath := fs.String("db", "relay.db", "SQLite database path")
	tier := fs.String("tier", "boosted", "voucher tier: boosted | unlimited")
	durationDays := fs.Int("duration-days", 30, "boost duration in days (ignored for -tier=unlimited, which is always permanent, §8.1a)")
	_ = fs.Parse(args[1:])
	if *tier != "boosted" && *tier != "unlimited" {
		fmt.Fprintln(os.Stderr, "tier must be \"boosted\" or \"unlimited\"")
		os.Exit(2)
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "opening store:", err)
		os.Exit(1)
	}
	defer st.Close()

	code, codeHash := generateVoucherCode()
	var duration *int
	if *tier == "boosted" {
		duration = durationDays
	}
	if err := st.MintVoucher(codeHash, *tier, duration); err != nil {
		fmt.Fprintln(os.Stderr, "minting voucher:", err)
		os.Exit(1)
	}

	fmt.Println("voucher minted - this code is never stored in plaintext, hand it to the redeemer now:")
	fmt.Println(code)
}
