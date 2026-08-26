-- Personal access tokens: long-lived credentials a person creates deliberately so a script, a
-- CI job or a CLI can act as them.
--
-- SQLite dialect. A sibling of migrations/postgres, not a shared file.
-- effect on the next one -- which a stateless token cannot promise without server-side state,
-- at which point it is not stateless. See docs/06-roadmap.md.
--
-- There are deliberately no scopes. A token names an account and nothing else; scopes are
-- authorization, which docs/00-scope.md puts outside this shard permanently.

-- +micrate Up
CREATE TABLE auth_api_tokens (
  id           TEXT PRIMARY KEY,
  account_id   TEXT        NOT NULL,
  -- What a person calls this token in a management screen. For humans; nothing reads it.
  name         TEXT        NOT NULL,
  token_digest BLOB       NOT NULL,
  created_at   TEXT NOT NULL,
  -- NULL means it never expires: correct for a deploy key, poor for a laptop, and the
  -- application's choice either way.
  expires_at   TEXT,
  -- Written at most once per touch_interval, never on every request.
  last_used_at TEXT,
  revoked_at   TEXT
);

-- The hot path is one lookup on this. Unique so a digest collision is a loud error rather than
-- two accounts sharing a credential.
CREATE UNIQUE INDEX idx_auth_api_tokens_digest ON auth_api_tokens (token_digest);

-- The management screen, and "revoke all my tokens".
CREATE INDEX idx_auth_api_tokens_account ON auth_api_tokens (account_id);

CREATE INDEX idx_auth_api_tokens_sweep ON auth_api_tokens (expires_at)
  WHERE expires_at IS NOT NULL;

-- +micrate Down
DROP TABLE auth_api_tokens;
