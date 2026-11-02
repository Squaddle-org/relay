package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Labeled by method/route pattern/status only, never room/user/device ids (CLAUDE.md: "Metrics
// without room ids as labels"). r.Pattern (Go 1.22+ ServeMux) is the *registered* pattern (e.g.
// "/v1/rooms/{room}/log"), not the resolved path, so no id ever reaches a label.
var (
	requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "relay_http_requests_total",
		Help: "Total HTTP requests.",
	}, []string{"method", "pattern", "status"})

	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "relay_http_request_duration_seconds",
		Help: "HTTP request duration in seconds.",
	}, []string{"method", "pattern"})
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap - not a direct Hijack passthrough - is what's required here. coder/websocket's own
// hijacker() helper (see its doc comment) walks a chain of Unwrap() methods looking for the
// first concrete http.Hijacker; a *direct* type-assertion Hijack() method on statusRecorder
// (the previous shape of this method) stops that walk early and fails the instant anything else
// sits between statusRecorder and the real ResponseWriter - which is exactly what logRequests'
// statusCapturingWriter (router.go) does today. Found live: GET /v1/ws's 101 response headers
// went out fine (written before the failed hijack attempt), then the hijack itself failed and
// the connection was left in a broken half-upgraded state - the client saw what looked like a
// successful handshake but then got garbage instead of WS frames.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)
		pattern := r.Pattern
		if pattern == "" {
			pattern = "unmatched"
		}
		requestsTotal.WithLabelValues(r.Method, pattern, strconv.Itoa(rec.status)).Inc()
		requestDuration.WithLabelValues(r.Method, pattern).Observe(time.Since(start).Seconds())
	})
}

// metricsHandler serves /metrics on the internal port (NewInternalRouter), next to /healthz.
func metricsHandler() http.Handler { return promhttp.Handler() }
