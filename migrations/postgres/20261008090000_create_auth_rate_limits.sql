-- Rate-limit counters every application process can see.
--
-- The in-memory limiters count per process, so behind a load balancer the effective limit is
-- the configured one times the number of processes: 2.2x with six workers, measured in
-- blueprints/0025 (OPS-01). One row per key, counted and judged by a single
-- INSERT ... ON CONFLICT DO UPDATE, so two processes cannot both believe they are under the
-- limit. Optional: only `Postgres::FixedWindowRateLimiter` reads it.

-- +micrate Up

-- `key` arrives already hashed by the caller (blueprints/0007), so the table never holds a
-- login or an address in the clear.
-- `window_ends_at` rather than when the window started: limiters with different windows share
-- this table, and only a row that carries its own deadline can be swept by a limiter that does
-- not know it. A login window of a minute must not forgive a password-reset window of a day.
CREATE TABLE auth_rate_limits (
  key               TEXT        PRIMARY KEY,
  attempts          INTEGER     NOT NULL,
  window_ends_at    TIMESTAMPTZ NOT NULL
);

-- For the sweeper, which deletes elapsed windows; an attacker minting keys is otherwise a way
-- to grow this table without bound.
CREATE INDEX auth_rate_limits_window_ends_at ON auth_rate_limits (window_ends_at);

-- +micrate Down
DROP TABLE auth_rate_limits;
