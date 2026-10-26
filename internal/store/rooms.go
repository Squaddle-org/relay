package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/squaddle-org/relay/internal/membership"
	"github.com/squaddle-org/relay/internal/proto"
)

var (
	ErrRoomExists   = errors.New("store: room already exists")
	ErrRoomNotFound = errors.New("store: room not found")
)

// StoredLogEntry is a log entry together with its relay-assigned timestamp (PROTOCOL.md §3.2 -
// rts travels next to the entry, never inside the signed part).
type StoredLogEntry struct {
	Cbor []byte
	Rts  uint64
}

// CreateRoom validates a genesis entry from scratch and persists the new room - for
// `POST /rooms`. Returns ErrRoomExists if the room id is already present.
func (s *Store) CreateRoom(entry proto.LogEntry, rts uint64) (*membership.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var exists int
	err := s.db.QueryRow(`SELECT 1 FROM rooms WHERE room_id = ?`, entry.Room).Scan(&exists)
	if err == nil {
		return nil, ErrRoomExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: checking room existence: %w", err)
	}

	next, err := membership.Empty().Apply(membership.StoredEntry{Entry: entry, Rts: rts})
	if err != nil {
		return nil, err
	}
	if err := s.persistAccepted(entry, rts, next); err != nil {
		return nil, err
	}
	s.states[hexKey(next.RoomID())] = next
	return next, nil
}

// AppendLogEntry validates entry against roomID's current state (cached, or rebuilt by
// replaying the stored log) and, if accepted, persists it - for `POST /rooms/{room}/log`.
func (s *Store) AppendLogEntry(roomID []byte, entry proto.LogEntry, rts uint64) (*membership.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, err := s.loadStateLocked(roomID)
	if err != nil {
		return nil, err
	}
	next, err := current.Apply(membership.StoredEntry{Entry: entry, Rts: rts})
	if err != nil {
		return nil, err
	}
	if err := s.persistAccepted(entry, rts, next); err != nil {
		return nil, err
	}
	s.states[hexKey(roomID)] = next
	return next, nil
}

// RoomForUser is one row of RoomsForUser's result.
type RoomForUser struct {
	RoomID    []byte
	RelayHost string
}

// RoomsForUser returns every room on this relay where user currently holds an active role (not
// pending) - for `GET /users/{user}/rooms`. The members table is already a materialized index of
// exactly this, and a removed/kicked user's row is already absent from it (persistAccepted's
// delete+reinsert-every-append pattern).
func (s *Store) RoomsForUser(user []byte) ([]RoomForUser, error) {
	rows, err := s.db.Query(
		`SELECT rooms.room_id, rooms.relay_host FROM members
		 JOIN rooms ON rooms.room_id = members.room_id
		 WHERE members.user_key = ? AND members.role != 'pending'`,
		user,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing rooms for user: %w", err)
	}
	defer rows.Close()

	var out []RoomForUser
	for rows.Next() {
		var r RoomForUser
		if err := rows.Scan(&r.RoomID, &r.RelayHost); err != nil {
			return nil, fmt.Errorf("store: scanning room for user: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// genesisRelayHost extracts the genesis body's field 1 (PROTOCOL.md §3.3 row 0, `relayHost`).
// The relay stays content-blind/lenient about this field, same posture as every other body-field
// check in this codebase (cf. applyRoomSettings) - absent or wrong type just means "" stored.
func genesisRelayHost(entry proto.LogEntry) string {
	host, _ := entry.Body[1].(string)
	return host
}

// ListRoomIDs returns every known room id - internal/retention's periodic job walks all of them.
func (s *Store) ListRoomIDs() ([][]byte, error) {
	rows, err := s.db.Query(`SELECT room_id FROM rooms`)
	if err != nil {
		return nil, fmt.Errorf("store: listing rooms: %w", err)
	}
	defer rows.Close()

	var out [][]byte
	for rows.Next() {
		var id []byte
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: scanning room id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// GetMembershipState returns the cached (or freshly rebuilt-from-log) state for roomID.
func (s *Store) GetMembershipState(roomID []byte) (*membership.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadStateLocked(roomID)
}

// GetLogEntriesFrom returns every stored entry at index >= fromIndex, in order - for
// `GET /rooms/{room}/log`.
func (s *Store) GetLogEntriesFrom(roomID []byte, fromIndex uint64) ([]StoredLogEntry, error) {
	rows, err := s.db.Query(`SELECT entry_cbor, rts FROM log_entries WHERE room_id = ? AND idx >= ? ORDER BY idx ASC`, roomID, fromIndex)
	if err != nil {
		return nil, fmt.Errorf("store: querying log entries: %w", err)
	}
	defer rows.Close()

	var out []StoredLogEntry
	for rows.Next() {
		var e StoredLogEntry
		if err := rows.Scan(&e.Cbor, &e.Rts); err != nil {
			return nil, fmt.Errorf("store: scanning log entry: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) loadStateLocked(roomID []byte) (*membership.State, error) {
	if cached, ok := s.states[hexKey(roomID)]; ok {
		return cached, nil
	}

	rows, err := s.db.Query(`SELECT entry_cbor, rts FROM log_entries WHERE room_id = ? ORDER BY idx ASC`, roomID)
	if err != nil {
		return nil, fmt.Errorf("store: loading log for replay: %w", err)
	}
	defer rows.Close()

	state := membership.Empty()
	found := false
	for rows.Next() {
		found = true
		var cborBytes []byte
		var rts uint64
		if err := rows.Scan(&cborBytes, &rts); err != nil {
			return nil, fmt.Errorf("store: scanning stored log entry: %w", err)
		}
		entry, err := proto.DecodeLogEntry(cborBytes)
		if err != nil {
			return nil, fmt.Errorf("store: corrupt stored log entry: %w", err)
		}
		next, err := state.Apply(membership.StoredEntry{Entry: *entry, Rts: rts})
		if err != nil {
			return nil, fmt.Errorf("store: replaying stored log entry %d: %w", entry.Index, err)
		}
		state = next
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrRoomNotFound
	}

	s.states[hexKey(roomID)] = state
	return state, nil
}

// persistAccepted writes the just-accepted entry, the updated rooms row, and a full replacement
// of the room's materialized members rows (room sizes are <50 per the spec - see ADR-0005 - so a
// delete+reinsert every append is simpler than diffing and plenty fast).
func (s *Store) persistAccepted(entry proto.LogEntry, rts uint64, next *membership.State) error {
	fullCbor, err := entry.FullCbor()
	if err != nil {
		return fmt.Errorf("store: encoding accepted entry: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback()

	rotationPending := 0
	if next.RotationPending() {
		rotationPending = 1
	}
	if entry.Index == 0 {
		if _, err := tx.Exec(
			`INSERT INTO rooms (room_id, head_hash, next_index, epoch, rotation_pending, relay_host, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			next.RoomID(), next.HeadHash(), next.NextIndex(), next.Epoch(), rotationPending, genesisRelayHost(entry), time.Now().Unix(),
		); err != nil {
			return fmt.Errorf("store: inserting room: %w", err)
		}
	} else {
		if _, err := tx.Exec(
			`UPDATE rooms SET head_hash = ?, next_index = ?, epoch = ?, rotation_pending = ? WHERE room_id = ?`,
			next.HeadHash(), next.NextIndex(), next.Epoch(), rotationPending, next.RoomID(),
		); err != nil {
			return fmt.Errorf("store: updating room: %w", err)
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO log_entries (room_id, idx, entry_hash, entry_cbor, rts) VALUES (?, ?, ?, ?, ?)`,
		next.RoomID(), entry.Index, entry.EntryHash(), fullCbor, rts,
	); err != nil {
		return fmt.Errorf("store: inserting log entry: %w", err)
	}

	if _, err := tx.Exec(`DELETE FROM members WHERE room_id = ?`, next.RoomID()); err != nil {
		return fmt.Errorf("store: clearing members: %w", err)
	}
	for _, m := range next.Members() {
		if _, err := tx.Exec(`INSERT INTO members (room_id, user_key, role) VALUES (?, ?, ?)`, next.RoomID(), m.User, m.Role.String()); err != nil {
			return fmt.Errorf("store: inserting member: %w", err)
		}
	}

	return tx.Commit()
}
