-- +micrate Up
CREATE TABLE auth_action_tokens (
  id           TEXT PRIMARY KEY,
  account_id   TEXT NOT NULL,
  purpose      TEXT NOT NULL,   -- reset | confirm | invite
  token_digest BLOB NOT NULL,
  created_at   TEXT NOT NULL,
  expires_at   TEXT NOT NULL,
  used_at      TEXT
);

CREATE UNIQUE INDEX idx_auth_action_tokens_digest ON auth_action_tokens (token_digest);

CREATE INDEX idx_auth_action_tokens_lookup
  ON auth_action_tokens (account_id, purpose, expires_at) WHERE used_at IS NULL;

-- +micrate Down
DROP TABLE auth_action_tokens;
