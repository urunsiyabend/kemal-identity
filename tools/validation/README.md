# Validation attempts

The consumer-side code behind `blueprints/0025-maturity-validation-results.md`, kept so a later
revision can be validated against the same attempts rather than against a fresh reading.

These are **not** part of this shard's suite and are not run by `crystal spec`. They belong to a
separate project that depends on the shard the way an application does — which is the whole point,
since several scenarios are about what a consumer can reach from outside.

To run them, create a project alongside this one:

```
consumer_app/
  shard.yml          # copy consumer-shard.yml.example, fix the path
  spec/              # copy the *_spec.cr files
  src/               # copy http01_app.cr
```

then `shards install` and `crystal spec`. `http01_app.cr` is a server: build it, run it, and
probe it with `curl` — the HTTP-01 result is about what a client receives, so it was measured
that way rather than in-process.

| File | Scenario |
|---|---|
| `tok01_spec.cr` | TOK-01, AUT-03 — two differently scoped tokens for one account |
| `tok01_lookups_spec.cr` | TOK-01 hot path — counts `find_by_digest` calls per authentication |
| `dev02_attempt1_spec.cr` | DEV-02 — a contract with no dependencies, required directly |
| `dev02_attempt2_spec.cr` | DEV-02 — the same for a repository contract. **Does not compile**, deliberately: it is the evidence |
| `dev02_attempt3_spec.cr` | DEV-02 — the require that works, reaching into the shard's private `spec/` tree |
| `ops02_spec.cr` | OPS-02 — subscribing to events, and the absence of a typed sink |
| `ops02_failure_spec.cr` | OPS-02 — a sink that raises, in both `Log` dispatch modes |
| `http01_app.cr` | HTTP-01 — an API-only Kemal app, including a consumer-written RFC 6750 handler |

`dev02_attempt2_spec.cr` is expected to fail compilation with `undefined constant
KemalIdentity::SpecHelper::FIXED_NOW`. Do not "fix" it; that error is the finding.
