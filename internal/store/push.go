package store

import "fmt"

// PutPushEndpoint registers/replaces deviceKey's UnifiedPush endpoint - `POST /v1/push`.
func (s *Store) PutPushEndpoint(deviceKey []byte, endpoint string) error {
	_, err := s.db.Exec(
		`INSERT INTO push_endpoints (device_key, endpoint, updated_at) VALUES (?, ?, unixepoch())
		 ON CONFLICT(device_key) DO UPDATE SET endpoint = excluded.endpoint, updated_at = excluded.updated_at`,
		deviceKey, endpoint,
	)
	if err != nil {
		return fmt.Errorf("store: storing push endpoint: %w", err)
	}
	return nil
}

// DeletePushEndpoint unregisters deviceKey - `DELETE /v1/push`.
func (s *Store) DeletePushEndpoint(deviceKey []byte) error {
	_, err := s.db.Exec(`DELETE FROM push_endpoints WHERE device_key = ?`, deviceKey)
	if err != nil {
		return fmt.Errorf("store: deleting push endpoint: %w", err)
	}
	return nil
}

// ListPushEndpointsForRoom returns the UnifiedPush endpoints of every current member device of
// roomID - used by the push-on-new-content sender (B7).
func (s *Store) ListPushEndpointsForRoom(roomID []byte) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT DISTINCT pe.endpoint
		   FROM push_endpoints pe
		   JOIN device_certs dc ON dc.device_key = pe.device_key AND dc.revoked_at IS NULL
		   JOIN members m ON m.user_key = dc.user_key AND m.room_id = ?`,
		roomID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing push endpoints for room: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var endpoint string
		if err := rows.Scan(&endpoint); err != nil {
			return nil, fmt.Errorf("store: scanning push endpoint: %w", err)
		}
		out = append(out, endpoint)
	}
	return out, rows.Err()
}
