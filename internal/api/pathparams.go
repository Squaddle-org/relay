package api

import (
	"encoding/base64"
	"net/http"
)

// b64PathParam decodes a base64url-without-padding path parameter (room/user/device/invite ids -
// PROTOCOL.md: "Binary fields are base64url (no padding) in JSON"; path parameters follow the
// same convention throughout relay-api.yaml).
func b64PathParam(r *http.Request, name string) ([]byte, bool) {
	v := r.PathValue(name)
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, false
	}
	return b, true
}
