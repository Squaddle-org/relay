package api

import (
	"bufio"
	"fmt"
	"net"
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

// Hijack delegates to the underlying ResponseWriter's http.Hijacker, if it has one. Without
// this, wrapping a ResponseWriter in a struct that only embeds the http.ResponseWriter
// *interface* silently drops Hijacker support (embedding an interface only promotes that
// interface's own methods, not ones satisfied by the concrete value underneath) - which broke
// GET /v1/ws: websocket.Accept requires Hijacker and fails closed with 501 otherwise.
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
	}
	return hj.Hijack()
}

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
