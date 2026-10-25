package main

import (
	"context"
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
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "voucher" {
		runVoucherCLI(os.Args[2:])
		return
	}
	runServer()
}

func runServer() {
	listen := flag.String("listen", ":8080", "public listen address")
	metrics := flag.String("metrics", ":9090", "internal metrics/health address")
	dbPath := flag.String("db", "relay.db", "SQLite database path")
	limitsMode := flag.String("limits", "none", "room limits policy: none (self-hosted default) | hosted (PROTOCOL.md §8)")
	unlimitedOwners := flag.String("unlimited-owners", "", "comma-separated base32 user keys; rooms they currently own get tier unlimited (§8.1a)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	policy := limits.NewPolicy(*limitsMode, *unlimitedOwners)
	logger.Info("starting relay", "listen", *listen, "db", *dbPath, "limits", *limitsMode, "unlimitedOwnersHosted", policy.Hosted)

	st, err := store.Open(*dbPath)
	if err != nil {
		logger.Error("opening store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	srv := &http.Server{Addr: *listen, Handler: api.NewRouter(logger, st, policy), ReadHeaderTimeout: 10 * time.Second}
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
	fs := flag.NewFlagSet("voucher", flag.ExitOnError)
	dbPath := fs.String("db", "relay.db", "SQLite database path")
	tier := fs.String("tier", "boosted", "voucher tier: boosted | unlimited")
	durationDays := fs.Int("duration-days", 30, "boost duration in days (ignored for -tier=unlimited, which is always permanent, §8.1a)")
	_ = fs.Parse(args)

	if fs.NArg() < 1 || fs.Arg(0) != "mint" {
		fmt.Fprintln(os.Stderr, "usage: relay voucher mint -tier=boosted|unlimited [-duration-days=30] [-db=relay.db]")
		os.Exit(2)
	}
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
