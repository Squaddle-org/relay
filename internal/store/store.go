package store

import (
	"database/sql"
	_ "embed"
	"fmt"
	"sync"

	_ "modernc.org/sqlite"

	"github.com/squaddle-org/relay/internal/membership"
)

//go:embed schema.sql
var schemaSQL string

// Store wraps one SQLite database and the in-memory membership.State cache built from it.
type Store struct {
	db *sql.DB

	mu     sync.Mutex
	states map[string]*membership.State // hex(roomId) -> cached state
}

// Open applies schema.sql (idempotent) and returns a ready Store. path may be a file path or
// ":memory:" (tests).
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: applying schema: %w", err)
	}
	return &Store{db: db, states: make(map[string]*membership.State)}, nil
}

func (s *Store) Close() error { return s.db.Close() }
