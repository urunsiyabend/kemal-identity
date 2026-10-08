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
CREATE TABLE auth_rate_limits (
  key               TEXT        PRIMARY KEY,
  attempts          INTEGER     NOT NULL,
  window_started_at TIMESTAMPTZ NOT NULL
);

-- For the sweeper, which deletes elapsed windows; an attacker minting keys is otherwise a way
-- to grow this table without bound.
CREATE INDEX auth_rate_limits_window_started_at ON auth_rate_limits (window_started_at);

-- +micrate Down
DROP TABLE auth_rate_limits;
