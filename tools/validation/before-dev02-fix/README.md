# Attempts against a state that no longer exists

These three files recorded DEV-02's original result: the shared contracts and test doubles lived
under `spec/`, and the only require that worked reached into this repository's private spec tree.

**They no longer run, and that is the point.** The fix moved everything to
`src/kemal_identity/testing`, so the paths these use — `../lib/kemal_identity/spec/contract/...`
and `../lib/kemal_identity/spec/spec_helper` — were removed by it. `KemalIdentity::SpecHelper` was
renamed to `KemalIdentity::Testing` in the same pass.

Kept because `blueprints/0025-maturity-validation-results.md` quotes what they produced, and a
quotation whose source has been deleted is worth less than one you can see:

| File | What it measured |
|---|---|
| `dev02_attempt1_spec.cr` | A contract with no dependencies, required directly. **Worked** — 2 examples |
| `dev02_attempt2_spec.cr` | The same for a repository contract. Failed to compile: `undefined constant KemalIdentity::SpecHelper::FIXED_NOW` |
| `dev02_attempt3_spec.cr` | Requiring the shard's own `spec_helper`. Worked — 32 examples, and the reason the result was M2 rather than M3 |

The current state is `../dev02_after_spec.cr`, which uses only published requires.
