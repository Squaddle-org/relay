package store

import (
	"database/sql"
	"errors"
	"fmt"

	sqlite "modernc.org/sqlite"
)

// sqliteConstraintUnique is SQLITE_CONSTRAINT_UNIQUE (2067) - modernc.org/sqlite's *Error.Code()
// value for a UNIQUE constraint violation.
const sqliteConstraintUnique = 2067

func isUniqueConstraintErr(err error) bool {
	var sqliteErr *sqlite.Error
	return errors.As(err, &sqliteErr) && sqliteErr.Code() == sqliteConstraintUnique
}

var (
	ErrVoucherNotFound         = errors.New("store: voucher not found")
	ErrVoucherAlreadyRedeemed  = errors.New("store: voucher already redeemed")
	ErrEntitlementAlreadyBound = errors.New("store: this purchase/voucher is already bound to another room")
)

// Entitlement is one relay-local boost record (PROTOCOL.md §8.3) - never part of the signed
// membership log (ADR-0010).
type Entitlement struct {
	Provider    string
	PurchaseRef string
	Tier        string
	Until       *int64 // nil = no expiry (tier "unlimited")
}

// GetActiveEntitlement returns room's best currently-active entitlement: an unlimited one if any
// exists, else the one with the furthest-future `until`, else nil (no active entitlement ->
// caller falls back to the free tier).
func (s *Store) GetActiveEntitlement(room []byte, now int64) (*Entitlement, error) {
	row := s.db.QueryRow(
		`SELECT provider, purchase_ref, tier, until FROM entitlements
		 WHERE room_id = ? AND (until IS NULL OR until > ?)
		 ORDER BY (until IS NULL) DESC, until DESC LIMIT 1`,
		room, now,
	)
	var e Entitlement
	var until sql.NullInt64
	err := row.Scan(&e.Provider, &e.PurchaseRef, &e.Tier, &until)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: loading entitlement: %w", err)
	}
	if until.Valid {
		e.Until = &until.Int64
	}
	return &e, nil
}

// PutEntitlement binds provider+purchaseRef to room - `POST /v1/entitlements`. The schema's
// UNIQUE(provider, purchase_ref) means a given purchase/voucher can only ever bind one room;
// a second attempt returns ErrEntitlementAlreadyBound.
func (s *Store) PutEntitlement(room []byte, provider, purchaseRef, tier string, until *int64) error {
	_, err := s.db.Exec(
		`INSERT INTO entitlements (room_id, provider, purchase_ref, tier, until, created_at) VALUES (?, ?, ?, ?, ?, unixepoch())`,
		room, provider, purchaseRef, tier, until,
	)
	if err != nil {
		if isUniqueConstraintErr(err) { // the only UNIQUE constraint this INSERT can hit is (provider, purchase_ref)
			return ErrEntitlementAlreadyBound
		}
		return fmt.Errorf("store: storing entitlement: %w", err)
	}
	return nil
}

// RedeemVoucher looks up codeHash, marks it redeemed (a voucher redeems exactly once), and
// returns its tier/duration. durationDays is nil for tier "unlimited" (always permanent).
func (s *Store) RedeemVoucher(codeHash []byte, now int64) (tier string, durationDays *int, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", nil, fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback()

	var redeemedAt sql.NullInt64
	var duration sql.NullInt64
	row := tx.QueryRow(`SELECT tier, duration_days, redeemed_at FROM vouchers WHERE code_hash = ?`, codeHash)
	if err := row.Scan(&tier, &duration, &redeemedAt); errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrVoucherNotFound
	} else if err != nil {
		return "", nil, fmt.Errorf("store: loading voucher: %w", err)
	}
	if redeemedAt.Valid {
		return "", nil, ErrVoucherAlreadyRedeemed
	}
	if _, err := tx.Exec(`UPDATE vouchers SET redeemed_at = ? WHERE code_hash = ?`, now, codeHash); err != nil {
		return "", nil, fmt.Errorf("store: marking voucher redeemed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", nil, fmt.Errorf("store: committing voucher redemption: %w", err)
	}
	if duration.Valid {
		d := int(duration.Int64)
		durationDays = &d
	}
	return tier, durationDays, nil
}

// MintVoucher (relay admin CLI only) inserts a new, unredeemed voucher. durationDays nil means
// tier "unlimited" (permanent, §8.1a).
func (s *Store) MintVoucher(codeHash []byte, tier string, durationDays *int) error {
	_, err := s.db.Exec(
		`INSERT INTO vouchers (code_hash, tier, duration_days, created_at) VALUES (?, ?, ?, unixepoch())`,
		codeHash, tier, durationDays,
	)
	if err != nil {
		return fmt.Errorf("store: minting voucher: %w", err)
	}
	return nil
}
