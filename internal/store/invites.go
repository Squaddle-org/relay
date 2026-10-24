package store

import (
	"database/sql"
	"errors"
	"fmt"
)

var ErrEnvelopeNotFound = errors.New("store: invite envelope not found")

// PutInviteEnvelope stores/replaces the raw envelope bytes for (roomID, inviteID). The relay
// never decrypts these (PROTOCOL.md §3.5) - the invite's own expiry/uses/revoked state already
// lives in the replayed membership.State (see rooms.go), so this table only needs the opaque
// envelope blob, not a mirror of those other columns.
func (s *Store) PutInviteEnvelope(roomID, inviteID, envelope []byte) error {
	_, err := s.db.Exec(
		`INSERT INTO invites (room_id, invite_id, requires_approval, envelope) VALUES (?, ?, 0, ?)
		 ON CONFLICT(room_id, invite_id) DO UPDATE SET envelope = excluded.envelope`,
		roomID, inviteID, envelope,
	)
	if err != nil {
		return fmt.Errorf("store: storing invite envelope: %w", err)
	}
	return nil
}

// GetInviteEnvelope returns the stored envelope bytes, or ErrEnvelopeNotFound.
func (s *Store) GetInviteEnvelope(roomID, inviteID []byte) ([]byte, error) {
	var envelope []byte
	err := s.db.QueryRow(`SELECT envelope FROM invites WHERE room_id = ? AND invite_id = ?`, roomID, inviteID).Scan(&envelope)
	if errors.Is(err, sql.ErrNoRows) || envelope == nil {
		return nil, ErrEnvelopeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: loading invite envelope: %w", err)
	}
	return envelope, nil
}

// DeleteInviteEnvelope removes the envelope (revoke, expiry, or uses exhausted - PROTOCOL.md §3.5:
// "Relay deletes the envelope on revoke, expiry, or when uses are exhausted.").
func (s *Store) DeleteInviteEnvelope(roomID, inviteID []byte) error {
	_, err := s.db.Exec(`UPDATE invites SET envelope = NULL WHERE room_id = ? AND invite_id = ?`, roomID, inviteID)
	if err != nil {
		return fmt.Errorf("store: deleting invite envelope: %w", err)
	}
	return nil
}
