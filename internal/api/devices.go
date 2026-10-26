package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"

	"github.com/squaddle-org/relay/internal/proto"
	"github.com/squaddle-org/relay/internal/store"
)

// putDevice is `PUT /v1/users/{user}/devices/{device}`: publishes a DeviceCert. Checked, in
// order: canonical CBOR + the cert's own signature (PROTOCOL.md §2.2), path user/device match
// the cert's own fields, and the *request* itself (per requestAuth) was signed by that same
// device key - "must be signed by the device itself" (relay-api.yaml), independent of the cert's
// own (unrelated) user-key signature.
func putDevice(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pathUser, ok := b64PathParam(r, "user")
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid", "bad user path parameter")
			return
		}
		pathDevice, ok := b64PathParam(r, "device")
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid", "bad device path parameter")
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", "cannot read body")
			return
		}
		cert, err := proto.DecodeDeviceCert(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", "not a canonical DeviceCert")
			return
		}
		if !cert.Verify() {
			writeError(w, http.StatusBadRequest, "invalid", "DeviceCert does not verify")
			return
		}
		if !bytes.Equal(pathUser, cert.User) || !bytes.Equal(pathDevice, cert.Device) {
			writeError(w, http.StatusBadRequest, "invalid", "path user/device does not match cert")
			return
		}
		if !bytes.Equal(DeviceKeyFromContext(r.Context()), cert.Device) {
			writeError(w, http.StatusForbidden, "forbidden", "request must be signed by the device being registered")
			return
		}
		if err := st.PutDeviceCert(*cert); err != nil {
			writeError(w, http.StatusInternalServerError, "invalid", "store error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// deviceListItem is the relay's own wire shape for GET /users/{user}/devices - relay-api.yaml
// only specifies "CBOR array" of DeviceCerts and DeviceRevokes, with no vector governing the
// exact layout, so a small kind-tagged wrapper around each item's own full CBOR keeps the two
// distinguishable without guessing.
type deviceListItem struct {
	Kind string `cbor:"0,keyasint"` // "cert" | "revoke"
	Data []byte `cbor:"1,keyasint"`
}

func listDevices(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := b64PathParam(r, "user")
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid", "bad user path parameter")
			return
		}
		entries, err := st.ListDeviceCertsAndRevocations(user)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "invalid", "store error")
			return
		}
		items := make([]deviceListItem, 0, len(entries))
		for _, e := range entries {
			if e.CertCbor != nil {
				items = append(items, deviceListItem{Kind: "cert", Data: e.CertCbor})
			} else {
				items = append(items, deviceListItem{Kind: "revoke", Data: e.RevokeCbor})
			}
		}
		out, err := proto.EncodeCanonical(items)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "invalid", "encoding error")
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(out)
	}
}

// postRevocation is `POST /v1/users/{user}/revocations`. Business authorization is the
// DeviceRevoke's own Ed25519 signature by the *user* key (proves the user authorized revoking
// one of their devices) - separate from, and independent of, requestAuth's device-level
// transport signature on the HTTP request itself (see requestAuth's doc comment).
func postRevocation(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pathUser, ok := b64PathParam(r, "user")
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid", "bad user path parameter")
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", "cannot read body")
			return
		}
		revoke, err := proto.DecodeDeviceRevoke(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", "not a canonical DeviceRevoke")
			return
		}
		if !revoke.Verify() {
			writeError(w, http.StatusBadRequest, "invalid", "DeviceRevoke does not verify")
			return
		}
		if !bytes.Equal(pathUser, revoke.User) {
			writeError(w, http.StatusBadRequest, "invalid", "path user does not match revoke")
			return
		}
		if err := st.RevokeDevice(*revoke); err != nil {
			writeError(w, http.StatusInternalServerError, "invalid", "store error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

type userRoomItem struct {
	RoomID    string `json:"roomId"`
	RelayHost string `json:"relayHost"`
}

// getUserRooms is `GET /v1/users/{user}/rooms` - self-only (caller's own device must belong to
// {user}, mirroring invites.go's callerIsOwnerOrAdmin pattern but checking identity rather than
// role), for seed-restore room recovery (PROTOCOL.md §5, spec v1.0.0-draft.3).
func getUserRooms(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pathUser, ok := b64PathParam(r, "user")
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid", "bad user path parameter")
			return
		}
		device := DeviceKeyFromContext(r.Context())
		cert, err := st.GetDeviceCert(device)
		if err != nil || !bytes.Equal(cert.User, pathUser) {
			writeError(w, http.StatusForbidden, "forbidden", "caller's device does not belong to this user")
			return
		}
		rooms, err := st.RoomsForUser(pathUser)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "invalid", "store error")
			return
		}
		items := make([]userRoomItem, 0, len(rooms))
		for _, rm := range rooms {
			items = append(items, userRoomItem{
				RoomID:    base64.RawURLEncoding.EncodeToString(rm.RoomID),
				RelayHost: rm.RelayHost,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(items)
	}
}
