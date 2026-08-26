-- +micrate Up
CREATE TABLE auth_sessions (
  id                  TEXT PRIMARY KEY,
  account_id          TEXT NOT NULL,
  tenant_id           TEXT,
  -- BLOB rather than PostgreSQL's BYTEA. Raw bytes either way, so no encoding for two
  -- adapters to disagree about.
  token_digest        BLOB NOT NULL,
  auth_version        INTEGER NOT NULL,
  assurance           INTEGER NOT NULL,
  created_at          TEXT NOT NULL,
  authenticated_at    TEXT NOT NULL,
  mfa_verified_at     TEXT,
  last_seen_at        TEXT NOT NULL,
  idle_expires_at     TEXT NOT NULL,
  absolute_expires_at TEXT NOT NULL,
  revoked_at          TEXT
);

CREATE UNIQUE INDEX idx_auth_sessions_digest ON auth_sessions (token_digest);

CREATE INDEX idx_auth_sessions_account ON auth_sessions (account_id)
  WHERE revoked_at IS NULL;

CREATE INDEX idx_auth_sessions_sweep ON auth_sessions (absolute_expires_at);

-- +micrate Down
DROP TABLE auth_sessions;
