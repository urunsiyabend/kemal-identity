-- Optional, and only correct if the application actually uses `auth_accounts`.
--
-- The shipped `auth_sessions.account_id` deliberately carries no foreign key: an
-- application implementing AccountRepository over its own `users` table has no
-- `auth_accounts` row to point at. See docs/03-data-model.md.

-- +micrate Up
ALTER TABLE auth_sessions
  ADD CONSTRAINT fk_auth_sessions_account
  FOREIGN KEY (account_id) REFERENCES auth_accounts (id) ON DELETE CASCADE;

-- +micrate Down
ALTER TABLE auth_sessions DROP CONSTRAINT fk_auth_sessions_account;
