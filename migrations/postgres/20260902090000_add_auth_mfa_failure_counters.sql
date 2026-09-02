-- A lifetime bound on guessing a second factor, which a rate limiter cannot express.
--
-- NIST SP 800-63B: "the verifier SHALL limit consecutive failed authentication attempts using a
-- specific authenticator on a single subscriber account to no more than 100 by disabling that
-- authenticator." A window that resets grants the same budget again forever — measured at
-- 103,680 attempts in thirty days with a five-minute window of twelve, which is about a 27%
-- chance of guessing a six-digit code. See blueprints/0029 and blueprints/0025 (MFA-04).
--
-- Both columns are per *factor*, not per account: "a specific authenticator" is what the
-- requirement names, and it is where django-otp keeps the same counter.

-- +micrate Up

-- Consecutive, meaning since the last successful verification rather than within any window.
ALTER TABLE auth_mfa_factors ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;

-- When the most recent wrong code was offered for this factor. django-otp keeps the same pair
-- (`throttling_failure_count`, `throttling_failure_timestamp`) for the same reason: the count
-- alone cannot tell an operator whether a factor is failing now or failed months ago, and a
-- deployment that wants a per-factor delay curve needs the timestamp to compute it.
ALTER TABLE auth_mfa_factors ADD COLUMN last_failure_at TIMESTAMPTZ;

-- NULL is the normal state. A disabled factor never authenticates and never counts towards
-- "this account has MFA", like an unconfirmed one, but stays in a management listing so the
-- person can be told which device stopped working.
ALTER TABLE auth_mfa_factors ADD COLUMN disabled_at TIMESTAMPTZ;

-- +micrate Down
ALTER TABLE auth_mfa_factors DROP COLUMN disabled_at;
ALTER TABLE auth_mfa_factors DROP COLUMN last_failure_at;
ALTER TABLE auth_mfa_factors DROP COLUMN consecutive_failures;
