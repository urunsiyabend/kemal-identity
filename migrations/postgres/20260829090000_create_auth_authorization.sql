-- Authorization: who belongs to which tenant, and who holds which role.
--
-- Two tables and no third one. There is deliberately no table mapping roles to permissions:
-- roles are defined in code (`KemalIdentity::Authz::RoleCatalog`) and only the assignments
-- live here. A role definition in a table is a privilege-escalation surface — one UPDATE,
-- through an injection or an over-permissive admin screen or a restored backup, silently
-- rewrites what everybody holding that role can do, and nothing about the application
-- changed. See blueprints/0018-authorization-and-tenancy.md.
--
-- Nothing here expires. A time-limited grant puts the moment somebody loses access into a
-- column nobody watches, and an access review reading the table sees a row that looks live.
-- Temporary access is granted and then revoked, and the revocation is a row that disappears.

-- +micrate Up

-- Membership is separate from role assignment on purpose. Membership answers "may this person
-- be inside this tenant at all"; roles answer "and what may they do there". A member with no
-- roles is a real state — freshly invited, or with everything revoked during an investigation.
CREATE TABLE auth_tenant_memberships (
  id         TEXT PRIMARY KEY,
  account_id TEXT        NOT NULL,
  tenant_id  TEXT        NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

-- One membership per pair. Two would make "remove them from this tenant" a partial operation.
CREATE UNIQUE INDEX idx_auth_tenant_memberships_pair
  ON auth_tenant_memberships (account_id, tenant_id);

-- "Who is in this tenant", paged, for an administration screen.
CREATE INDEX idx_auth_tenant_memberships_tenant
  ON auth_tenant_memberships (tenant_id, created_at, id);

CREATE TABLE auth_role_assignments (
  id         TEXT PRIMARY KEY,
  account_id TEXT        NOT NULL,
  -- NULL means global: the role applies everywhere, including inside every tenant, and is not
  -- gated by membership. That is what makes a global assignment the dangerous kind, and why
  -- `granted_by` is here.
  tenant_id  TEXT,
  role       TEXT        NOT NULL,
  granted_at TIMESTAMPTZ NOT NULL,
  granted_by TEXT
);

-- Two partial indexes rather than one plain unique index, because a plain one would not
-- collide on NULL tenant_id and the same global role could be granted twice. The same trick
-- docs/03-data-model.md already uses for a nullable tenant on auth_accounts.
CREATE UNIQUE INDEX idx_auth_role_assignments_tenant
  ON auth_role_assignments (account_id, tenant_id, role)
  WHERE tenant_id IS NOT NULL;

CREATE UNIQUE INDEX idx_auth_role_assignments_global
  ON auth_role_assignments (account_id, role)
  WHERE tenant_id IS NULL;

-- The hot path: every authorized request reads one account's assignments.
CREATE INDEX idx_auth_role_assignments_account
  ON auth_role_assignments (account_id);

-- The access review that asks the question the other way round: not "what can this person do"
-- but "who can do this".
CREATE INDEX idx_auth_role_assignments_role
  ON auth_role_assignments (role, tenant_id);

-- +micrate Down
DROP TABLE auth_role_assignments;
DROP TABLE auth_tenant_memberships;
