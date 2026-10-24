// Package store wraps SQLite (modernc.org/sqlite, CGO-free). Schema in schema.sql, embedded and
// applied (idempotently - every statement is CREATE TABLE/INDEX IF NOT EXISTS) on Open.
//
// Per-room membership.State is cached in memory (Store.states), rebuilt by replaying the room's
// stored log entries the first time it's needed after process start - members/rooms.* columns are
// a queryable mirror of that same state for cheap reads, not the source of truth; the log is.
package store
