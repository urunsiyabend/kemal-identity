-- +micrate Up
CREATE TABLE auth_sessions (
  id                  TEXT PRIMARY KEY,
  account_id          TEXT        NOT NULL,
  tenant_id           TEXT,
  token_digest        BYTEA       NOT NULL,
  auth_version        INTEGER     NOT NULL,
  assurance           SMALLINT    NOT NULL,
  created_at          TIMESTAMPTZ NOT NULL,
  authenticated_at    TIMESTAMPTZ NOT NULL,
  mfa_verified_at     TIMESTAMPTZ,
  last_seen_at        TIMESTAMPTZ NOT NULL,
  idle_expires_at     TIMESTAMPTZ NOT NULL,
  absolute_expires_at TIMESTAMPTZ NOT NULL,
  revoked_at          TIMESTAMPTZ
);

-- The hot path is one index lookup on this. Unique so that a digest collision is a
-- database error rather than a silent security failure.
CREATE UNIQUE INDEX idx_auth_sessions_digest ON auth_sessions (token_digest);

-- Partial: "log out everywhere" and "list my devices" only ever care about live sessions,
-- so the index stays small as revoked rows accumulate before the sweeper runs.
CREATE INDEX idx_auth_sessions_account ON auth_sessions (account_id)
  WHERE revoked_at IS NULL;

CREATE INDEX idx_auth_sessions_sweep ON auth_sessions (absolute_expires_at);

-- +micrate Down
DROP TABLE auth_sessions;
