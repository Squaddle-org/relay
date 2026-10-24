package store

import (
	"database/sql"
	"errors"
	"fmt"
)

var ErrMailboxEmpty = errors.New("store: link mailbox empty")

// PutLinkMailbox stores blob under code, expiring at expiresAt (unix seconds) - PROTOCOL.md
// §2.3: "Mailbox entries expire after 5 minutes" - the caller (api, B6) computes expiresAt.
func (s *Store) PutLinkMailbox(code, blob []byte, expiresAt uint64) error {
	_, err := s.db.Exec(`INSERT INTO link_mailbox (code, blob, expires_at) VALUES (?, ?, ?)`, code, blob, expiresAt)
	if err != nil {
		return fmt.Errorf("store: storing link mailbox entry: %w", err)
	}
	return nil
}

// TakeLinkMailbox returns and deletes the entry for code if it exists and hasn't expired as of
// now (unix seconds) - PROTOCOL.md §2.3: "deleted on first read."
func (s *Store) TakeLinkMailbox(code []byte, now uint64) ([]byte, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback()

	var blob []byte
	var expiresAt uint64
	err = tx.QueryRow(`SELECT blob, expires_at FROM link_mailbox WHERE code = ?`, code).Scan(&blob, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrMailboxEmpty
	}
	if err != nil {
		return nil, fmt.Errorf("store: loading link mailbox entry: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM link_mailbox WHERE code = ?`, code); err != nil {
		return nil, fmt.Errorf("store: deleting link mailbox entry: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: committing mailbox read: %w", err)
	}
	if now >= expiresAt {
		return nil, ErrMailboxEmpty
	}
	return blob, nil
}

// PruneExpiredLinkMailbox deletes every entry expired as of now - call periodically.
func (s *Store) PruneExpiredLinkMailbox(now uint64) error {
	_, err := s.db.Exec(`DELETE FROM link_mailbox WHERE expires_at <= ?`, now)
	if err != nil {
		return fmt.Errorf("store: pruning expired link mailbox entries: %w", err)
	}
	return nil
}
