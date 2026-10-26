package api

import (
	"net/http"
	"strings"
)

// parseCommaList splits a comma-separated flag value into trimmed, non-empty entries.
func parseCommaList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// corsMiddleware is a browser-enforced boundary only - it controls whether a *browser* lets its
// own JS read a response, nothing more. The real authorization boundary is request-auth (§5):
// a request from a disallowed origin still gets processed normally server-side; it just won't
// carry Access-Control-Allow-Origin, so a browser's own same-origin policy blocks the calling
// page from reading the result. An empty allowlist means no CORS headers are ever sent (the
// default - this relay has no browser-based client configured unless the operator opts in).
func corsMiddleware(allowedOrigins []string, next http.Handler) http.Handler {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && allowed[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			// Preflight for a custom-header request (Authorization, per PROTOCOL.md §5) - must
			// be intercepted here, before the mux: method-specific patterns like
			// "GET /v1/rooms" never match an OPTIONS request, so it would otherwise 404.
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
