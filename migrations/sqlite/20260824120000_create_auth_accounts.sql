-- SQLite dialect. A sibling of migrations/postgres, deliberately not a shared
-- lowest-common-denominator file: BYTEA vs BLOB and TIMESTAMPTZ vs TEXT are real differences,
-- and pretending otherwise produces a schema that is wrong in both dialects
-- (docs/03-data-model.md).
--
-- Reference implementation of AccountRepository, NOT a requirement.

-- +micrate Up
CREATE TABLE auth_accounts (
  -- The one and only account identifier -- see blueprints/0005-one-account-identifier.md.
  id                TEXT PRIMARY KEY,
  tenant_id         TEXT,
  normalized_login  TEXT NOT NULL,
  email_verified_at TEXT,
  disabled_at       TEXT,
  auth_version      INTEGER NOT NULL DEFAULT 1,
  password_digest   TEXT,
  password_scheme   TEXT,
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_auth_accounts_login
  ON auth_accounts (tenant_id, normalized_login);

-- SQLite treats NULLs as distinct in a unique index, exactly as PostgreSQL does, so the
-- single-tenant case needs the same partial index or duplicate logins get in.
CREATE UNIQUE INDEX idx_auth_accounts_login_single_tenant
  ON auth_accounts (normalized_login) WHERE tenant_id IS NULL;

-- +micrate Down
DROP TABLE auth_accounts;
