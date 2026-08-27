-- External identities: which provider account is which local account.
--
-- SQLite dialect. A sibling of migrations/postgres, not a shared file.
--
-- Keyed on (issuer, subject) and nothing else. docs/06-roadmap.md requires it, and there are
-- two reasons an email column is absent rather than merely unused:
--
--   1. Addresses change. People marry, change surname, leave a company and come back. A row
--      keyed on an address becomes a different person's row, or a stranded orphan.
--   2. Addresses are claimed, not proved. A provider that lets somebody set an unverified
--      address and hands it to you has let them claim to be whoever owns that address at your
--      service. Matching on it is account takeover with extra steps.
--
-- `subject` is stable within an issuer and meaningless outside it, which is why both halves are
-- the key: two providers can hand out the same `sub` and mean two different people.

-- +micrate Up
CREATE TABLE auth_external_identities (
  id                    TEXT PRIMARY KEY,
  account_id            TEXT        NOT NULL,
  -- The provider's `iss`, compared exactly. Not a display name and not a base URL to build
  -- others from: it is the identity of the party whose assertions are believed.
  issuer                TEXT        NOT NULL,
  -- The provider's `sub`.
  subject               TEXT        NOT NULL,
  created_at            TEXT        NOT NULL,
  -- For a management screen, and for noticing a link nobody has used in two years.
  last_authenticated_at TEXT       
);

-- The whole security of this table. Without it one provider account can be attached to two
-- local ones, and whichever row is found first decides who somebody logs in as.
CREATE UNIQUE INDEX idx_auth_external_identities_pair
  ON auth_external_identities (issuer, subject);

-- "Which providers is this account linked to", for a management screen.
CREATE INDEX idx_auth_external_identities_account
  ON auth_external_identities (account_id);

-- +micrate Down
DROP TABLE auth_external_identities;
