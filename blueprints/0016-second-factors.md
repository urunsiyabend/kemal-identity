# 0016 — Second factors: TOTP, and the one secret that is not a digest

**Status:** accepted
**Date:** 2026-08-27
**Milestone:** v0.5

## Context

`docs/06-roadmap.md`: "MFA: TOTP plus hashed recovery codes, reflected in `AssuranceLevel`.
Disabling MFA, replacing a factor and using a recovery code all require fresh authentication."

TOTP is a small amount of arithmetic surrounded by a large amount of policy, and almost every
real weakness is in the policy. The decisions below are mostly about the surroundings.

## Decisions

### 1. The TOTP secret is encrypted, not hashed — and that is stated, not hidden

Every other secret in this shard is stored as a SHA-256 digest, because the server only has to
*recognise* it. A TOTP secret is different in kind: the server recomputes a code from it on
every verification, so it must be able to read it back. Hashing is not an option.

`MFA::SecretBox` is the honest version of what is left. Sealed secrets are useless without a
key held in the application's configuration rather than in the table beside them, so a dump, a
backup or a read-only injection yields ciphertext. An attacker holding *both* has the second
factor, and no arrangement of software changes that.

Recovery codes are ordinary bearer secrets and follow the normal token discipline exactly:
CSPRNG, digest-only storage, consumed atomically.

### 2. AES-256-CBC with encrypt-then-MAC, not GCM

GCM would be the obvious choice. Crystal's `OpenSSL::Cipher` does not expose the authentication
tag — no `auth_tag` accessor, no `EVP_CIPHER_CTX_ctrl` binding — so a GCM tag can neither be
read out nor supplied back without binding libcrypto directly, which is a dependency this shard
will not take for one table.

Encrypt-then-MAC over CBC is the construction GCM replaced, and it is secure **in that order**.
The tag covers version, IV and ciphertext, and is verified *before* anything reaches the
cipher: MAC-then-encrypt is what turns CBC into a padding oracle. The blob carries a version
byte, covered by the tag, so a second scheme can be added without a migration.

Key rotation is `reseal` over the table rather than a key id inside the blob. It happens once;
the common path should not pay for it.

### 3. Enrolment is two steps

A factor does not count until a code from it has verified. A secret that was generated but
never proved is a secret nobody may actually hold — a mis-scanned QR code, a clock two minutes
out, an app that silently failed to save — and treating it as a factor immediately is how
somebody locks themselves out of their own account.

An unconfirmed factor never authenticates and never counts towards `enrolled?`.

### 4. What makes TOTP safe is in `Service`, not in `TOTP`

`MFA::TOTP` computes and compares digits and decides nothing. Six digits is one of a million,
and a code is valid for its period plus the drift either side. Three things in `MFA::Service`
are what make that a second factor rather than a formality:

1. **A rate limit consumed before the code is checked.** Counting afterwards means a wrong
   guess that is slow is a free guess — the same rule `RateLimiter` already states for
   passwords. Keyed by account, because by this point the account is known.
2. **Single use.** `Repository#consume_counter` records a counter only if it is strictly
   greater than the last, in one statement. `TOTP.match` therefore returns the *counter* rather
   than a boolean: a boolean cannot express "correct, but already spent".
3. **Confirmation**, as above.

### 5. Drift is bounded at two steps

Each step of tolerance multiplies the number of codes valid at any moment, so a wide window is
an authentication bypass with a limit on it rather than a convenience. One step either side is
the default and three is refused at boot — the same treatment `JWT::Validator` gives `leeway`.

### 6. The factor's parameters travel with the row

`digits`, `period` and `algorithm` are stored per factor rather than read from configuration at
verification time. The app on the phone keeps computing whatever it was given at enrolment, so
a later change of default would otherwise break every factor already enrolled, at once, with no
way to tell the app. Stored per row, a new default applies to new enrolments only.

SHA-1 is the default digest, and not because it is the best available: it is what authenticator
apps overwhelmingly implement, and a second factor nobody can enrol in protects nothing. HMAC
over a counter is unaffected by the SHA-1 collision results.

### 7. Recovery codes get full token entropy

`RandomSource::TOKEN_BYTES`, the same floor as a session token. The usual argument for a shorter
code is that people type these by hand; the answer is to print them in groups, which
`#redeem_recovery_code` strips back out. A recovery code skips the second factor outright, so it
is the last thing that should be granted an exception to the shard's own entropy rule.

Ten codes, issued at the moment a first factor turns MFA on rather than left for the application
to remember: an account with a second factor and no way around it is one lost phone from being
unrecoverable, and "the app was supposed to call `regenerate_recovery_codes`" is not a defence
anybody can offer the person locked out. Adding a *second* device does not reissue them, because
that would silently void a list somebody has already written down.

### 8. Redeeming a code ends the account's other sessions

`docs/02-security-model.md` lists MFA recovery among the events that revoke every session. The
situation that produces one is somebody redeeming a code because the device is gone, and "lost"
and "taken" look identical from here.

`except_session_id` spares the session doing the redeeming — normally one half-way through a
login — because otherwise the way back in signs you out. It is logged at **warning**: a recovery
code being used is either somebody's worst day or an attacker's best one.

### 9. Proving a factor rotates the session

`env.auth.mfa_verified!` starts a new session at `AssuranceLevel::MFA` and revokes the old one.
`docs/02-security-model.md` already listed an assurance increase alongside login among the
events that must produce a new identifier: a session id an attacker learned while it was worth
`Password` must not silently become one worth `MFA`.

Freshness stays the caller's to enforce. `MFA::Service` takes an account id and has no request
to inspect, so `require_fresh!` belongs at the route — which is where the roadmap's requirement
about disabling MFA and replacing a factor is met.

## Consequences

* An application must hold a secret-box key and must not lose it. Losing it invalidates every
  enrolled factor; recovery codes are unaffected, since they are digests.
* `Application` refuses a partial MFA configuration at boot rather than accepting an enrolment
  it cannot store.
* Two properties here are deliberately unasserted, because no behavioural spec can observe them,
  and mutation testing reports both as survivors: `TOTP.match` checking shape before computing
  any HMAC (a cost guard — removing it changes no result), and `AesSecretBox` deriving its two
  keys from different contexts (a statement about a construction, not an output).
  `spec/security/mfa_spec.cr` says so where a reader would otherwise wonder.
* Twenty-seven mutations of the service, the repository double, the codecs and the secret box;
  twenty-five killed and those two surviving. Both database adapters' single-use statements were
  separately mutated into read-then-write and caught by the concurrency examples.
