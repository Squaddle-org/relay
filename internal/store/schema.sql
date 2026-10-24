-- SQLite, WAL mode. All ids are raw BLOBs (32 bytes unless noted).
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS device_certs (
  user_key    BLOB NOT NULL,
  device_key  BLOB NOT NULL PRIMARY KEY,
  cert_cbor   BLOB NOT NULL,
  revoked_at  INTEGER,
  revoke_cbor BLOB  -- the signed DeviceRevoke itself, so GET /users/{user}/devices can serve it back
);
CREATE INDEX IF NOT EXISTS device_certs_user ON device_certs(user_key);

CREATE TABLE IF NOT EXISTS rooms (
  room_id          BLOB PRIMARY KEY,
  head_hash        BLOB NOT NULL,
  next_index       INTEGER NOT NULL,
  epoch            INTEGER NOT NULL,
  rotation_pending INTEGER NOT NULL DEFAULT 0, -- ADR-0012 (PROTOCOL.md §3.4)
  created_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS log_entries (
  room_id     BLOB NOT NULL REFERENCES rooms(room_id),
  idx         INTEGER NOT NULL,
  entry_hash  BLOB NOT NULL,
  entry_cbor  BLOB NOT NULL,
  rts         INTEGER NOT NULL,
  PRIMARY KEY (room_id, idx)
);

-- Materialized from log for fast authorization checks; rebuildable from log_entries.
CREATE TABLE IF NOT EXISTS members (
  room_id     BLOB NOT NULL REFERENCES rooms(room_id),
  user_key    BLOB NOT NULL,
  role        TEXT NOT NULL CHECK (role IN ('owner','admin','member','pending')),
  PRIMARY KEY (room_id, user_key)
);

CREATE TABLE IF NOT EXISTS invites (
  room_id           BLOB NOT NULL REFERENCES rooms(room_id),
  invite_id         BLOB NOT NULL,          -- 16 bytes
  expires_at        INTEGER,
  max_uses          INTEGER,
  uses              INTEGER NOT NULL DEFAULT 0,
  requires_approval INTEGER NOT NULL,
  revoked           INTEGER NOT NULL DEFAULT 0,
  envelope          BLOB,                   -- NULL for approval invites / after revoke
  PRIMARY KEY (room_id, invite_id)
);

CREATE TABLE IF NOT EXISTS ops (
  cursor      INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id     BLOB NOT NULL REFERENCES rooms(room_id),
  op_id       BLOB NOT NULL UNIQUE,
  device_key  BLOB NOT NULL,
  seq         INTEGER NOT NULL,
  epoch       INTEGER NOT NULL,
  envelope    BLOB NOT NULL,
  received_at INTEGER NOT NULL,
  UNIQUE (room_id, device_key, seq)
);
CREATE INDEX IF NOT EXISTS ops_room_cursor ON ops(room_id, cursor);

CREATE TABLE IF NOT EXISTS snapshots (
  room_id       BLOB NOT NULL REFERENCES rooms(room_id),
  covers_up_to  INTEGER NOT NULL,
  snapshot_cbor BLOB NOT NULL,
  created_at    INTEGER NOT NULL,
  PRIMARY KEY (room_id, covers_up_to)
);

CREATE TABLE IF NOT EXISTS push_endpoints (
  device_key  BLOB PRIMARY KEY,
  endpoint    TEXT NOT NULL,
  updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS link_mailbox (
  code        BLOB NOT NULL,                -- 16 bytes
  blob        BLOB NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS link_mailbox_code ON link_mailbox(code);

-- PROTOCOL.md §8. Relay-local policy, never part of the signed log.
CREATE TABLE IF NOT EXISTS entitlements (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id       BLOB NOT NULL REFERENCES rooms(room_id),
  provider      TEXT NOT NULL CHECK (provider IN ('google_play','voucher')),
  purchase_ref  TEXT NOT NULL,             -- Play purchase token hash or voucher id
  tier          TEXT NOT NULL,
  until         INTEGER,                   -- NULL = no expiry (tier 'unlimited')
  created_at    INTEGER NOT NULL,
  UNIQUE (provider, purchase_ref)          -- one purchase boosts exactly one room
);
CREATE INDEX IF NOT EXISTS entitlements_room ON entitlements(room_id, until);

CREATE TABLE IF NOT EXISTS vouchers (
  code_hash     BLOB PRIMARY KEY,          -- BLAKE2b of the code, never store plaintext
  tier          TEXT NOT NULL,
  duration_days INTEGER,                   -- NULL = permanent (tier 'unlimited')
  redeemed_at   INTEGER,
  created_at    INTEGER NOT NULL
);
