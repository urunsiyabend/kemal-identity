-- Second factors, and the recovery codes that get somebody back in when the phone is gone.
--
-- SQLite dialect. A sibling of migrations/postgres, not a shared file.
--
-- Two tables rather than one, because they are different kinds of secret. A TOTP shared secret
-- has to be read back to compute a code, so it is encrypted rather than hashed -- the one
-- reversible secret in this shard, and the reason MFA::SecretBox exists. A recovery code is an
-- ordinary bearer secret: the server only has to recognise it, so it is a digest like every
-- other token here.

-- +micrate Up
CREATE TABLE auth_mfa_factors (
  id                TEXT PRIMARY KEY,
  account_id        TEXT        NOT NULL,
  -- MFA::FactorKind. Append only, never renumber: the numbers are on disk.
  kind              SMALLINT    NOT NULL,
  -- What the person calls this device in a management screen. For humans; nothing reads it.
  label             TEXT        NOT NULL,
  -- Ciphertext, never the secret. Useless without the application's key, which lives in its
  -- configuration and must never be stored in this database.
  sealed_secret     BLOB        NOT NULL,
  -- Stored per row rather than read from configuration at verification time. The app on the
  -- phone keeps computing whatever it was given at enrolment, so a later change of default
  -- would otherwise break every factor already enrolled.
  digits            SMALLINT    NOT NULL,
  period_seconds    INTEGER     NOT NULL,
  -- MFA::TOTP::Algorithm. Append only, as above.
  algorithm         SMALLINT    NOT NULL,
  created_at        TEXT        NOT NULL,
  -- NULL while enrolment is unfinished. An unconfirmed factor never authenticates and never
  -- counts towards "this account has MFA": a secret that was generated but never proved is a
  -- secret nobody may actually hold, and treating it as a factor is how somebody locks
  -- themselves out of their own account.
  confirmed_at      TEXT       ,
  -- The replay defence. A code stays arithmetically correct for its whole period plus the
  -- drift either side, which is exactly the window somebody who read it over a shoulder is
  -- working in. BIGINT because it counts 30-second steps since 1970 and will not wrap.
  last_used_counter BIGINT
);

-- "Which factors does this account have", on the login path and the management screen.
CREATE INDEX idx_auth_mfa_factors_account ON auth_mfa_factors (account_id);

CREATE TABLE auth_mfa_recovery_codes (
  id          TEXT PRIMARY KEY,
  account_id  TEXT        NOT NULL,
  code_digest BLOB        NOT NULL,
  created_at  TEXT        NOT NULL,
  -- Single use. Set by the one statement that spends the code, so two simultaneous requests
  -- cannot both succeed.
  used_at     TEXT       
);

-- The lookup that spends a code, and the count behind "2 remaining". Partial, because both
-- only ever care about unspent codes and the index stays small as used rows accumulate.
CREATE INDEX idx_auth_mfa_recovery_unused ON auth_mfa_recovery_codes (account_id)
  WHERE used_at IS NULL;

-- Unique so that two accounts cannot share a code and a collision is a loud error.
CREATE UNIQUE INDEX idx_auth_mfa_recovery_digest ON auth_mfa_recovery_codes (code_digest);

-- +micrate Down
DROP TABLE auth_mfa_recovery_codes;
DROP TABLE auth_mfa_factors;
