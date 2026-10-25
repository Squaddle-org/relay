package store

import (
	"database/sql"
	"errors"
	"fmt"
)

var ErrSnapshotNotFound = errors.New("store: no snapshot for room")

// PutSnapshot stores a Snapshot envelope (PROTOCOL.md §4.4) keyed by its real coversUpTo cursor -
// the caller (internal/api's postSnapshot) has already verified the signature and that Device
// belongs to Author; the relay still never decrypts Ct.
func (s *Store) PutSnapshot(roomID []byte, coversUpTo int64, snapshotCbor []byte) error {
	_, err := s.db.Exec(
		`INSERT INTO snapshots (room_id, covers_up_to, snapshot_cbor, created_at) VALUES (?, ?, ?, unixepoch())
		 ON CONFLICT(room_id, covers_up_to) DO UPDATE SET snapshot_cbor = excluded.snapshot_cbor`,
		roomID, coversUpTo, snapshotCbor,
	)
	if err != nil {
		return fmt.Errorf("store: storing snapshot: %w", err)
	}
	return nil
}

// GetLatestSnapshot returns the snapshot with the highest covers_up_to for roomID.
func (s *Store) GetLatestSnapshot(roomID []byte) ([]byte, error) {
	var snapshotCbor []byte
	err := s.db.QueryRow(
		`SELECT snapshot_cbor FROM snapshots WHERE room_id = ? ORDER BY covers_up_to DESC LIMIT 1`, roomID,
	).Scan(&snapshotCbor)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSnapshotNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: loading snapshot: %w", err)
	}
	return snapshotCbor, nil
}

// LatestSnapshotMeta returns the covers_up_to cursor and created_at unix timestamp of roomID's
// most recent snapshot - internal/retention needs created_at (PROTOCOL.md §4.4's "30 days after
// a snapshot exists" floor), which GetLatestSnapshot's client-facing shape doesn't expose.
func (s *Store) LatestSnapshotMeta(roomID []byte) (coversUpTo int64, createdAt int64, err error) {
	err = s.db.QueryRow(
		`SELECT covers_up_to, created_at FROM snapshots WHERE room_id = ? ORDER BY covers_up_to DESC LIMIT 1`, roomID,
	).Scan(&coversUpTo, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, ErrSnapshotNotFound
	}
	if err != nil {
		return 0, 0, fmt.Errorf("store: loading snapshot meta: %w", err)
	}
	return coversUpTo, createdAt, nil
}
