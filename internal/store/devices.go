package store

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/squaddle-org/relay/internal/proto"
)

var ErrDeviceNotFound = errors.New("store: device not found")

// PutDeviceCert stores cert (already verified by the caller) keyed by its device key -
// `PUT /users/{user}/devices/{device}`.
func (s *Store) PutDeviceCert(cert proto.DeviceCert) error {
	cbor, err := cert.FullCbor()
	if err != nil {
		return fmt.Errorf("store: encoding device cert: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO device_certs (user_key, device_key, cert_cbor) VALUES (?, ?, ?)
		 ON CONFLICT(device_key) DO UPDATE SET user_key = excluded.user_key, cert_cbor = excluded.cert_cbor,
		   revoked_at = NULL, revoke_cbor = NULL`,
		cert.User, cert.Device, cbor,
	)
	if err != nil {
		return fmt.Errorf("store: storing device cert: %w", err)
	}
	return nil
}

// GetDeviceCert returns the stored cert for deviceKey, or ErrDeviceNotFound.
func (s *Store) GetDeviceCert(deviceKey []byte) (*proto.DeviceCert, error) {
	var cborBytes []byte
	err := s.db.QueryRow(`SELECT cert_cbor FROM device_certs WHERE device_key = ? AND revoked_at IS NULL`, deviceKey).Scan(&cborBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDeviceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: loading device cert: %w", err)
	}
	cert, err := proto.DecodeDeviceCert(cborBytes)
	if err != nil {
		return nil, fmt.Errorf("store: corrupt stored device cert: %w", err)
	}
	return cert, nil
}

// DeviceListEntry is one row of `GET /users/{user}/devices`: either an active cert or (once
// revoked) its revocation - never both halves of the same device key at once.
type DeviceListEntry struct {
	CertCbor   []byte // nil if revoked
	RevokeCbor []byte // nil unless revoked
}

// ListDeviceCertsAndRevocations returns every device the relay has seen for userKey - active
// certs and revocations alike (relay-api.yaml: "List DeviceCerts and DeviceRevokes for a user").
func (s *Store) ListDeviceCertsAndRevocations(userKey []byte) ([]DeviceListEntry, error) {
	rows, err := s.db.Query(`SELECT cert_cbor, revoked_at, revoke_cbor FROM device_certs WHERE user_key = ?`, userKey)
	if err != nil {
		return nil, fmt.Errorf("store: listing device certs: %w", err)
	}
	defer rows.Close()

	var out []DeviceListEntry
	for rows.Next() {
		var certCbor, revokeCbor []byte
		var revokedAt sql.NullInt64
		if err := rows.Scan(&certCbor, &revokedAt, &revokeCbor); err != nil {
			return nil, fmt.Errorf("store: scanning device cert: %w", err)
		}
		if revokedAt.Valid {
			out = append(out, DeviceListEntry{RevokeCbor: revokeCbor})
		} else {
			out = append(out, DeviceListEntry{CertCbor: certCbor})
		}
	}
	return out, rows.Err()
}

// RevokeDevice marks revoke.Device revoked, storing the verified DeviceRevoke itself so
// ListDeviceCertsAndRevocations can serve it back - `POST /users/{user}/revocations`.
func (s *Store) RevokeDevice(revoke proto.DeviceRevoke) error {
	cbor, err := revoke.FullCbor()
	if err != nil {
		return fmt.Errorf("store: encoding device revoke: %w", err)
	}
	_, err = s.db.Exec(`UPDATE device_certs SET revoked_at = ?, revoke_cbor = ? WHERE device_key = ?`, revoke.RevokedAt, cbor, revoke.Device)
	if err != nil {
		return fmt.Errorf("store: revoking device: %w", err)
	}
	return nil
}
