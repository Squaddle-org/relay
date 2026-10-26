// Package api implements relay-api.yaml. google_play entitlements are M5b - out of M2 scope.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/squaddle-org/relay/internal/limits"
	"github.com/squaddle-org/relay/internal/store"
)

func NewRouter(log *slog.Logger, st *store.Store, policy *limits.Policy, corsAllowedOriginsCSV string) http.Handler {
	mux := http.NewServeMux()
	replay := newReplayCache()
	limiter := newEnvelopeRateLimiter()
	notifier := newPushNotifier()
	hub := newWsHub()
	auth := func(h http.HandlerFunc) http.HandlerFunc { return requestAuth(replay, h) }

	mux.HandleFunc("PUT /v1/users/{user}/devices/{device}", auth(putDevice(st)))
	mux.HandleFunc("GET /v1/users/{user}/devices", listDevices(st)) // unauthenticated, relay-api.yaml
	mux.HandleFunc("POST /v1/users/{user}/revocations", auth(postRevocation(st)))
	mux.HandleFunc("GET /v1/users/{user}/rooms", auth(getUserRooms(st)))
	mux.HandleFunc("POST /v1/rooms", auth(postRoom(st)))
	mux.HandleFunc("GET /v1/rooms/{room}/log", auth(getLog(st)))
	mux.HandleFunc("POST /v1/rooms/{room}/log", auth(postLog(st, notifier, hub, policy)))
	mux.HandleFunc("GET /v1/rooms/{room}/ops", auth(getOps(st)))
	mux.HandleFunc("POST /v1/rooms/{room}/ops", auth(postOps(st, notifier, hub)))
	mux.HandleFunc("GET /v1/rooms/{room}/limits", auth(getLimits(st, policy)))
	mux.HandleFunc("POST /v1/entitlements", auth(postEntitlements(st)))
	mux.HandleFunc("POST /v1/billing/google/rtdn", notImplemented) // M5b - out of M2 scope
	mux.HandleFunc("GET /v1/rooms/{room}/snapshots/latest", auth(getLatestSnapshot(st)))
	mux.HandleFunc("POST /v1/rooms/{room}/snapshots", auth(postSnapshot(st)))
	mux.HandleFunc("GET /v1/invites/{room}/{invite}/envelope", getInviteEnvelope(st, limiter)) // unauthenticated, rate-limited
	mux.HandleFunc("PUT /v1/invites/{room}/{invite}/envelope", auth(putInviteEnvelope(st)))
	mux.HandleFunc("POST /v1/link/{code}", postLinkMailbox(st)) // unauthenticated, relay-api.yaml
	mux.HandleFunc("GET /v1/link/{code}", getLinkMailbox(st))   // unauthenticated, relay-api.yaml
	mux.HandleFunc("POST /v1/push", auth(postPushRegister(st)))
	mux.HandleFunc("DELETE /v1/push", auth(deletePushRegister(st)))
	mux.HandleFunc("GET /v1/ws", auth(serveWS(st, hub)))
	// CORS outermost: an OPTIONS preflight to an unauthenticated route (e.g. the invite envelope
	// GET) must never reach requestAuth, and method-specific mux patterns never match OPTIONS at
	// all, so this has to sit in front of everything else.
	return corsMiddleware(parseCommaList(corsAllowedOriginsCSV), logRequests(log, metricsMiddleware(mux)))
}

func NewInternalRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("GET /metrics", metricsHandler())
	return mux
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiError{Code: code, Message: msg})
}

func notImplemented(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotImplemented, "invalid", "not implemented yet")
}

// logRequests never logs bodies, auth headers or query strings (may contain ids worth protecting).
func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug("request", "method", r.Method, "pattern", r.Pattern)
		next.ServeHTTP(w, r)
	})
}
