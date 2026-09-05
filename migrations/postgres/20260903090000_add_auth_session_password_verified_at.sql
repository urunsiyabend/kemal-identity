-- When the password behind this session was last actually typed.
--
-- `authenticated_at` cannot answer that question, because it is restamped by every assurance
-- increase: prove a second factor nine minutes after logging in and a `require_fresh!` window
-- that meant "type your password again" is satisfied by the TOTP instead. Nor can `assurance`,
-- which says one factor was proved and not which one — a federated login sits at `Password`
-- too, so "confirm your password before linking another identity" was unenforceable.
--
-- One dedicated column rather than a general method→timestamp map, which is the shape both
-- Laravel (`auth.password_confirmed_at`) and django-sudo settled on: in practice the only
-- method a policy asks about by name is the password. See blueprints/0031.

-- +micrate Up

-- NULL for every session that exists today, and for every session no password produced — a
-- remembered browser, a federated login, an adopted legacy session. NULL reads as "no password
-- was typed for this session", so a guard refuses rather than assuming.
ALTER TABLE auth_sessions ADD COLUMN password_verified_at TIMESTAMPTZ;

-- +micrate Down
ALTER TABLE auth_sessions DROP COLUMN password_verified_at;
