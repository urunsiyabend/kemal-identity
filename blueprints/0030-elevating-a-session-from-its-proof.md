# 0030 — Elevating a session from its proof, not from the caller's memory

**Status:** accepted
**Date:** 2026-09-03
**Milestone:** v0.12

## Context

A consumer built a full-suite SaaS application against v0.11.1 and wrote down what the
integration cost it. The first item on that list is this one, and it is the only item that
names a way to reach `AssuranceLevel::MFA` without a second factor.

`MFA::Service#verify` and `MFA::Service#redeem_recovery_code` return the **same**
`MFA::Verified`. Which of the two happened is a `by_recovery_code?` boolean inside it, and the
level the session should reach is therefore a choice the *application* makes, between two
methods that look interchangeable at the call site:

```crystal
in KemalIdentity::MFA::Verified
  env.auth.mfa_verified!        # or recovery_verified!, and nothing says which
```

`blueprints/0025` MFA-04 already found this once, from the other end: the documented recovery
flow raised the session to `MFA`, so the strongest gate in the system was reachable through its
weakest path. v0.10.0 fixed the *level* by adding `AssuranceLevel::Recovery` and a second
method to reach it. It did not remove the choice, and a choice between two similar-looking
methods on a success path is a defect waiting for one forgotten branch.

The consumer's own words: the documented warning "is useful, but the compiler cannot stop the
wrong elevation call."

## What everything else does

Worth measuring before changing anything, because a design nobody else has is either an
advantage or a mistake, and reading tells you which.

| System | Recovery code vs. real second factor |
|---|---|
| **ASP.NET Core Identity** | `TwoFactorRecoveryCodeSignInAsync` and `TwoFactorAuthenticatorSignInAsync` both call `DoTwoFactorSignInAsync`, which adds `new Claim("amr", "mfa")`. Identical claim. The only difference is that the recovery path forces `rememberClient: false` |
| **Auth0** | A recovery code is an MFA factor, and the documented step-up check is "does `amr` contain `mfa`" — which a recovery code satisfies |
| **django-otp** | `user.is_verified()` is a boolean. A `StaticDevice` (backup tokens) and a `TOTPDevice` are distinguishable only by inspecting `otp_device.__class__`; there is no assurance concept in the public API |
| **Laravel Fortify** | One `/two-factor-challenge` endpoint takes either `code` or `recovery_code`, and the resulting session is the same |
| **Keycloak** | Recovery codes are another "Alternative" 2FA step. The distinction is *expressible* — a deployment can put them in their own flow step and map that to a lower LoA — but it is realm configuration, not a property of the credential |

So the shard's `Recovery = 25` is already stricter than every one of them, and nobody supplies
prior art for the API shape. Two things follow. Being ahead of the convention means the
convention cannot be leaned on: whatever stops the wrong elevation has to be in this shard's
own types. And it means the *level* was the valuable part of v0.10.0 and is not in question
here — only who decides it.

Two related findings, recorded because they bear on the rest of the consumer's list:

- The IANA `amr` registry (RFC 8176) has 22 values — `face fpt geo hwk iris kba mca mfa otp pin
  pop pwd rba retina sc sms swk tel user vbm wia` — and **none** of them means recovery code,
  backup code or look-up secret. A federated deployment cannot say "recovery" in `amr` at all.
  That is independent evidence for `blueprints/0028`'s decision not to publish `acr_values`:
  the vocabulary genuinely is not there.
- NIST SP 800-63B-4 permits a look-up secret as the physical authenticator at AAL2 alongside a
  password, but handles *recovery* codes separately, in §4.2 on account recovery, rather than as
  an authenticator type. This shard issues recovery codes as the backup for a lost device, which
  is the §4.2 reading, so `Recovery` below `MFA` is consistent with the newest revision rather
  than in tension with it.

## Decisions

### 1. One elevation call, and it reads the level off the result

```crystal
def elevate!(result : MFA::Verified) : Principal
```

`env.auth.elevate!(result)` after `#verify` lands on `MFA`; the identical line after
`#redeem_recovery_code` lands on `Recovery`. The result already knows which happened, and it is
the only party that cannot be mistaken about it.

Taking `MFA::Verified` and not `VerificationResult` keeps the success/failure split where it
already was — `Failed` will not compile as an argument, so the exhaustive `case` remains the
compiler's business rather than a convention.

This is what none of the five systems above does, and it is cheap: no new type, no migration,
no behaviour change for anything already correct.

### 2. Elevation is monotone

A session already at `MFA` that spends a recovery code **stays** at `MFA`.

Prior art is unanimous, though mostly by accident: Keycloak stores the levels reached in a user
session note with their timestamps (`{"1":1701809618}`) and there is no way to step down within
a session; ASP.NET and Spring Security accumulate claims and authorities, and a set never loses
a member. In all three, evidence adds up. The question does not arise for them.

It arose here because `assurance` is a single ordered scalar, so the most recent event
overwrites rather than joins. That is what the old `recovery_verified!` did, and the cost was
real: somebody who proved a device at the start of a session and later spent a recovery code
lost access to everything `minimum_assurance: MFA` guards, having proved *more* than the person
who did not. The device was really proved, and spending a code afterwards does not unprove it.

Only the ceiling is monotone. `mfa_verified_at` is restamped by every second-factor event, so
recency still measures from the latest one. And `redeem_recovery_code` still revokes the
account's other sessions — the security action for "the device may have been taken" is that
revocation, not a downgrade of the session doing the recovering.

`#recovery_verified!` becomes monotone too, rather than being left with the behaviour its
replacement rejects.

### 3. `mfa_verified!` and `recovery_verified!` are deprecated, and removed at v1.0

`@[Deprecated]` on both, so the compiler warns at every remaining call site while nothing
breaks. `env.auth` is on the v1.0 freeze list (`docs/06-roadmap.md`), which makes v1.0 the last
release that may remove them — and the deprecation window is every release before it.

### 4. The result types are **not** split, yet

The consumer's stronger proposal is `MFA::FactorVerified` and `MFA::RecoveryVerified` as
separate types, so that the compiler forces the two paths apart. It is the right idea and it is
deliberately not in this milestone:

- With `#elevate!` as the documented path, the split buys the difference between a compiler
  *error* and a compiler *warning* on a call site that has to be written wrong on purpose.
- It can be made nearly source-compatible — `alias Verified = FactorVerified | RecoveryVerified`
  keeps every existing `in KemalIdentity::MFA::Verified` branch compiling, and breaks only code
  that constructs `Verified.new` — but "nearly" is not "additively", and the payoff above is
  small.

There is a gap to close before it can be scheduled at all: **the v1.0 freeze list names no MFA
type.** Not `MFA::Verified`, not `VerificationResult`, not `MFA::Service`. The "not frozen, on
purpose" line says "TOTP internals", which reads as `Base32` and `TOTP` rather than a service's
result. If those results freeze, the split has a v1.0 deadline; if they do not, it can land in
any later minor. The silence is the problem, and it is worth settling on its own rather than
inside this decision.

## Consequences

- An application that already branched correctly is unaffected, except for two deprecation
  warnings pointing at the shorter way to write it.
- An application that branched *incorrectly* is fixed by switching to `#elevate!`, and its
  recovery sessions stop satisfying `minimum_assurance: MFA`.
- One observable behaviour change beyond that: a session at `MFA` that spends a recovery code no
  longer drops to `Recovery`. An application relying on the downgrade — as a "the device may be
  lost, re-enrol before continuing" gate — must read `mfa_verified_at` and the recovery event
  instead. Nothing in the shard prompted for re-enrolment via the level, and the audit trail
  already carries `mfa.recovery_code_used` at warning level with the number of codes left.
- The consumer's remaining proposals are unaffected by this one, and the largest of them —
  per-method authentication evidence — has a v1.0 deadline of its own, because it changes
  `Principal` and `Sessions::Record`. Keycloak's `{level: timestamp}` session note is the same
  design arrived at from the other direction, and it is what makes decision 2 a non-question
  rather than a choice.
