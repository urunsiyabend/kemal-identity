-- Reference implementation of AccountRepository, NOT a requirement.
--
-- An application that already has `users.email` and `users.password_digest` implements
-- AccountRepository against that table and never runs this migration. See
-- docs/03-data-model.md — this distinction is the difference between "adoptable
-- incrementally" and "rewrite your user model first".

-- +micrate Up
CREATE TABLE auth_accounts (
  -- The one and only account identifier: what Principal#subject carries and what
  -- auth_sessions.account_id references. There is deliberately no second "subject_id"
  -- column to keep in sync with it -- see blueprints/0005-one-account-identifier.md.
  id               TEXT PRIMARY KEY,
  tenant_id        TEXT,
  normalized_login TEXT        NOT NULL,
  email_verified_at TIMESTAMPTZ,
  disabled_at      TIMESTAMPTZ,
  auth_version     INTEGER     NOT NULL DEFAULT 1,
  password_digest  TEXT,
  password_scheme  TEXT,
  created_at       TIMESTAMPTZ NOT NULL,
  updated_at       TIMESTAMPTZ NOT NULL
);

-- Multi-tenant uniqueness.
CREATE UNIQUE INDEX idx_auth_accounts_login
  ON auth_accounts (tenant_id, normalized_login);

-- A NULL tenant_id does not collide under a plain unique constraint in PostgreSQL, so
-- single-tenant deployments need this partial index alongside the one above or duplicate
-- logins get in.
CREATE UNIQUE INDEX idx_auth_accounts_login_single_tenant
  ON auth_accounts (normalized_login) WHERE tenant_id IS NULL;

-- +micrate Down
DROP TABLE auth_accounts;
