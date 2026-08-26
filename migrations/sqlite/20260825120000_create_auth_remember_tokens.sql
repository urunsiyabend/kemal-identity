-- +micrate Up
CREATE TABLE auth_remember_tokens (
  id           TEXT PRIMARY KEY,
  account_id   TEXT NOT NULL,
  family_id    TEXT NOT NULL,
  token_digest BLOB NOT NULL,
  created_at   TEXT NOT NULL,
  expires_at   TEXT NOT NULL,
  used_at      TEXT,
  revoked_at   TEXT
);

CREATE UNIQUE INDEX idx_auth_remember_digest ON auth_remember_tokens (token_digest);
CREATE INDEX idx_auth_remember_family ON auth_remember_tokens (family_id);
CREATE INDEX idx_auth_remember_account ON auth_remember_tokens (account_id)
  WHERE revoked_at IS NULL AND used_at IS NULL;
CREATE INDEX idx_auth_remember_sweep ON auth_remember_tokens (expires_at);

-- +micrate Down
DROP TABLE auth_remember_tokens;
