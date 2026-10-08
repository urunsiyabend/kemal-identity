#!/usr/bin/env bash
# Verifies a tree is fit to be released as <version>. What `.github/workflows/release.yml` runs
# against the tagged commit, and what a maintainer runs before tagging:
#
#   DATABASE_URL=postgres://... tools/release/verify.sh 0.13.0
#
# It needs a reachable, empty-or-migrated PostgreSQL. That is the point rather than a cost:
# until v0.13.0 the release gate ran the database-free subset, and v0.11.0 was published with
# every MFA read raising against PostgreSQL because only CI — which runs after publication —
# had a database (docs/06-roadmap.md). A gate that cannot see the adapter people deploy is a
# gate for a different library.
set -euo pipefail

version="${1:?usage: tools/release/verify.sh <version, e.g. 0.13.0>}"
version="${version#v}"

fail() {
  echo "::error::$*" >&2
  exit 1
}

# -- The version is the same everywhere a reader or a resolver looks for it -------------------

shard=$(grep -E '^version:' shard.yml | awk '{print $2}')
constant=$(grep -oE '"[0-9]+\.[0-9]+\.[0-9]+"' src/kemal_identity/version.cr | tr -d '"')
echo "release=$version shard.yml=$shard VERSION=$constant"

[ "$version" = "$shard" ] || fail "shard.yml says $shard, not $version"
[ "$version" = "$constant" ] || fail "KemalIdentity::VERSION says $constant, not $version"

grep -qE "^## v${version//./\\.} " CHANGELOG.md || fail "CHANGELOG.md has no '## v$version' section"

# The install snippet pins the minor line, so a reader copying it gets this release.
pin="~> ${version%.*}.0"
grep -qF "version: $pin" README.md || fail "README.md does not pin '$pin'"

# -- It builds, as a consumer and as each example --------------------------------------------

crystal build --no-codegen src/kemal_identity.cr
for app in examples/*/app.cr; do
  echo "-- $app"
  crystal build --no-codegen "$app"
done

# -- Every spec, against a real PostgreSQL, with nothing pending -----------------------------

[ -n "${DATABASE_URL:-}" ] || fail "DATABASE_URL is not set; the release gate runs the PostgreSQL adapter"

shards build migrate
bin/migrate up

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

# KEMAL_IDENTITY_REQUIRE_DATABASE turns "skipped for want of a database" into a failure in the
# PostgreSQL and multi-process specs, and the summary check below catches any other pending
# example: `crystal spec` exits zero with pendings, so its status alone is not the answer.
set +e
KEMAL_IDENTITY_REQUIRE_DATABASE=1 crystal spec 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
set -e

[ "$status" -eq 0 ] || fail "the suite failed"

summary=$(grep -E '^[0-9]+ examples, ' "$log" | tail -1)
echo "summary: $summary"
pending=$(echo "$summary" | grep -oE '[0-9]+ pending' | awk '{print $1}')
[ "${pending:-0}" -eq 0 ] || fail "$pending example(s) pending; a release runs everything"

echo "verified $version"
