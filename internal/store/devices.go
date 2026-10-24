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
		 ON CONFLICT(device_key) DO UPDATE SET user_key = excluded.user_key, cert_cbor = excluded.cert_cbor`,
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

// ListDeviceCerts returns every (non-revoked) device cert for userKey, in no particular order -
// `GET /users/{user}/devices`.
func (s *Store) ListDeviceCerts(userKey []byte) ([]proto.DeviceCert, error) {
	rows, err := s.db.Query(`SELECT cert_cbor FROM device_certs WHERE user_key = ? AND revoked_at IS NULL`, userKey)
	if err != nil {
		return nil, fmt.Errorf("store: listing device certs: %w", err)
	}
	defer rows.Close()

	var out []proto.DeviceCert
	for rows.Next() {
		var cborBytes []byte
		if err := rows.Scan(&cborBytes); err != nil {
			return nil, fmt.Errorf("store: scanning device cert: %w", err)
		}
		cert, err := proto.DecodeDeviceCert(cborBytes)
		if err != nil {
			return nil, fmt.Errorf("store: corrupt stored device cert: %w", err)
		}
		out = append(out, *cert)
	}
	return out, rows.Err()
}

// RevokeDevice marks deviceKey revoked as of revokedAt (unix seconds) - `POST /users/{user}/revocations`.
func (s *Store) RevokeDevice(deviceKey []byte, revokedAt uint64) error {
	_, err := s.db.Exec(`UPDATE device_certs SET revoked_at = ? WHERE device_key = ?`, revokedAt, deviceKey)
	if err != nil {
		return fmt.Errorf("store: revoking device: %w", err)
	}
	return nil
}
