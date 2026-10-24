package store

import "fmt"

// StoredOp is one op-log entry as the relay sees it: opaque ciphertext plus only the envelope
// fields (PROTOCOL.md §4.1) the relay actually inspects - it never decrypts `ct`. Parsing/
// verifying the envelope is package api's job (B7); this layer is pure persistence.
type StoredOp struct {
	Cursor    int64
	OpID      []byte
	DeviceKey []byte
	Seq       uint64
	Epoch     uint64
	Envelope  []byte // full OpEnvelope CBOR, as received
}

// AppendOp stores one op. The schema's UNIQUE(room_id, device_key, seq) enforces the per-device
// monotonic sequence (gap detection, PROTOCOL.md §4.1) at the database level.
func (s *Store) AppendOp(roomID, opID, deviceKey []byte, seq, epoch uint64, envelope []byte) (cursor int64, err error) {
	res, err := s.db.Exec(
		`INSERT INTO ops (room_id, op_id, device_key, seq, epoch, envelope, received_at) VALUES (?, ?, ?, ?, ?, ?, unixepoch())`,
		roomID, opID, deviceKey, seq, epoch, envelope,
	)
	if err != nil {
		return 0, fmt.Errorf("store: appending op: %w", err)
	}
	return res.LastInsertId()
}

// GetOpsAfter returns up to limit ops for roomID with cursor > after, in cursor order - for
// `GET /rooms/{room}/ops`.
func (s *Store) GetOpsAfter(roomID []byte, after int64, limit int) ([]StoredOp, error) {
	rows, err := s.db.Query(
		`SELECT cursor, op_id, device_key, seq, epoch, envelope FROM ops WHERE room_id = ? AND cursor > ? ORDER BY cursor ASC LIMIT ?`,
		roomID, after, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("store: querying ops: %w", err)
	}
	defer rows.Close()

	var out []StoredOp
	for rows.Next() {
		var op StoredOp
		if err := rows.Scan(&op.Cursor, &op.OpID, &op.DeviceKey, &op.Seq, &op.Epoch, &op.Envelope); err != nil {
			return nil, fmt.Errorf("store: scanning op: %w", err)
		}
		out = append(out, op)
	}
	return out, rows.Err()
}
