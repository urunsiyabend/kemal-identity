-- Attenuation for personal access tokens.
--
-- The original auth_api_tokens migration said "There are deliberately no scopes. A token names
-- an account and nothing else; scopes are authorization, which docs/00-scope.md puts outside
-- this shard permanently." That was true when it was written and there was no authorizer for a
-- scope to intersect with. v0.6 shipped one. See blueprints/0021-credential-reference.md.
--
-- NULL and '' are different answers and the difference is load-bearing:
--
--   NULL          the token is not attenuated -- it carries whatever its owner holds
--   ''            attenuated to nothing: valid, and permits nothing
--   'a.read b.x'  attenuated to exactly these permissions
--
-- Reading NULL as an empty set would break every token issued before this column existed.
-- Reading '' as NULL would hand a deliberately powerless token the run of the application. One
-- is a lockout and the other is a privilege escalation, which is why the column is nullable
-- rather than NOT NULL DEFAULT ''.
--
-- Space-delimited, as RFC 6749 encodes scope. Permission names are lowercase dotted segments,
-- so no name can contain the delimiter, and `ApiTokens::Token` refuses a scope with whitespace
-- in it rather than storing something it could not read back.
--
-- Additive and nullable, so a version N binary reading a row written by N+1 sees a column it
-- does not select. Rolling deployments stay safe (docs/06-roadmap.md, OPS-08).

-- +micrate Up
ALTER TABLE auth_api_tokens ADD COLUMN scopes TEXT;

-- +micrate Down
ALTER TABLE auth_api_tokens DROP COLUMN scopes;
