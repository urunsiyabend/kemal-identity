-- Remember-me tokens.
--
-- Deliberately not "a session with a thirty-day expiry". That would be a bearer secret sitting
-- in a browser for a month with no way to notice it had been stolen. Instead each token is
-- single-use and rotates on every use, and every token descended from one login shares a
-- `family_id`.
--
-- That is what makes theft *detectable*: after a thief uses a stolen token, the token is spent,
-- so when the legitimate user next presents their copy it is a replay -- and the reverse if the
-- user gets there first. Either way somebody presents an already-used token, and the whole
-- family dies. See docs/02-security-model.md and blueprints/0012-remember-me.md.

-- +micrate Up
CREATE TABLE auth_remember_tokens (
  id           TEXT PRIMARY KEY,
  account_id   TEXT        NOT NULL,
  -- Every token issued by rotating from one original login shares this. Revoking a family
  -- ends that browser's remembered state without touching any other device.
  family_id    TEXT        NOT NULL,
  token_digest BYTEA       NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL,
  expires_at   TIMESTAMPTZ NOT NULL,
  -- Spent normally: the holder presented it and got a replacement.
  used_at      TIMESTAMPTZ,
  -- Killed, because a replay was detected in this family or the account revoked it. Distinct
  -- from used_at: a replayed token is used but not revoked, and the difference is what an
  -- audit trail needs to tell "rotated" from "we think this was stolen".
  revoked_at   TIMESTAMPTZ
);

-- The hot path is one lookup on this, and unique so a digest collision is a loud error rather
-- than two browsers sharing a remembered login.
CREATE UNIQUE INDEX idx_auth_remember_digest ON auth_remember_tokens (token_digest);

-- Family revocation walks this.
CREATE INDEX idx_auth_remember_family ON auth_remember_tokens (family_id);

-- "Forget me everywhere" and the sweeper.
CREATE INDEX idx_auth_remember_account ON auth_remember_tokens (account_id)
  WHERE revoked_at IS NULL AND used_at IS NULL;

CREATE INDEX idx_auth_remember_sweep ON auth_remember_tokens (expires_at);

-- +micrate Down
DROP TABLE auth_remember_tokens;
