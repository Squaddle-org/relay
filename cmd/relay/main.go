package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/squaddle-org/relay/internal/api"
)

func main() {
	listen := flag.String("listen", ":8080", "public listen address")
	metrics := flag.String("metrics", ":9090", "internal metrics/health address")
	dbPath := flag.String("db", "relay.db", "SQLite database path")
	limits := flag.String("limits", "none", "room limits policy: none (self-hosted default) | hosted (PROTOCOL.md §8)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	logger.Info("starting relay", "listen", *listen, "db", *dbPath, "limits", *limits)

	srv := &http.Server{Addr: *listen, Handler: api.NewRouter(logger), ReadHeaderTimeout: 10 * time.Second}
	internal := &http.Server{Addr: *metrics, Handler: api.NewInternalRouter(), ReadHeaderTimeout: 5 * time.Second}

	go func() { _ = internal.ListenAndServe() }()
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	_ = internal.Shutdown(shutdown)
}
