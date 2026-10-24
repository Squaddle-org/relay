// Package api implements relay-api.yaml. Handlers are stubs until M2.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func NewRouter(log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	todo := notImplemented
	mux.HandleFunc("PUT /v1/users/{user}/devices/{device}", todo)
	mux.HandleFunc("GET /v1/users/{user}/devices", todo)
	mux.HandleFunc("POST /v1/users/{user}/revocations", todo)
	mux.HandleFunc("POST /v1/rooms", todo)
	mux.HandleFunc("GET /v1/rooms/{room}/log", todo)
	mux.HandleFunc("POST /v1/rooms/{room}/log", todo)
	mux.HandleFunc("GET /v1/rooms/{room}/ops", todo)
	mux.HandleFunc("POST /v1/rooms/{room}/ops", todo)
	mux.HandleFunc("GET /v1/rooms/{room}/limits", todo)
	mux.HandleFunc("POST /v1/entitlements", todo)
	mux.HandleFunc("POST /v1/billing/google/rtdn", todo)
	mux.HandleFunc("GET /v1/rooms/{room}/snapshots/latest", todo)
	mux.HandleFunc("POST /v1/rooms/{room}/snapshots", todo)
	mux.HandleFunc("GET /v1/invites/{room}/{invite}/envelope", todo)
	mux.HandleFunc("PUT /v1/invites/{room}/{invite}/envelope", todo)
	mux.HandleFunc("POST /v1/link/{code}", todo)
	mux.HandleFunc("GET /v1/link/{code}", todo)
	mux.HandleFunc("POST /v1/push", todo)
	mux.HandleFunc("DELETE /v1/push", todo)
	mux.HandleFunc("GET /v1/ws", todo)
	return logRequests(log, mux)
}

func NewInternalRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	// TODO(M2): /metrics via prometheus/client_golang
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
