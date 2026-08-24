-- Schema ships in v0.1; the reset/confirm/invite flows that use it ship in v0.2. The table
-- lands now so that adding those flows is not a migration.

-- +micrate Up
CREATE TABLE auth_action_tokens (
  id           TEXT PRIMARY KEY,
  account_id   TEXT        NOT NULL,
  purpose      TEXT        NOT NULL,   -- reset | confirm | invite
  token_digest BYTEA       NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL,
  expires_at   TIMESTAMPTZ NOT NULL,
  used_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_auth_action_tokens_digest ON auth_action_tokens (token_digest);

CREATE INDEX idx_auth_action_tokens_lookup
  ON auth_action_tokens (account_id, purpose, expires_at) WHERE used_at IS NULL;

-- +micrate Down
DROP TABLE auth_action_tokens;
