#!/usr/bin/env bash
# Reports what changed in upstream's MySQL store since the fork's SQLite copy was last reviewed.
#
# Usage: scripts/fork-sync-check.sh [upstream-ref]
#
# Prints the commits and diff for crates/opentunnel-server/src/store.rs, compares SCHEMA_VERSION, and lists the
# Store methods that exist on only one side. Nothing here is applied automatically: read the SQL changes and port
# them to src/fork/sqlite.rs, then update src/fork/UPSTREAM and commit it with the merge.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

store=crates/opentunnel-server/src/store.rs
fork=crates/opentunnel-server/src/fork/sqlite.rs
marker=crates/opentunnel-server/src/fork/UPSTREAM

ref=${1:-}
if [ -z "$ref" ]; then
  for candidate in upstream/main upstream/master origin/HEAD origin/main origin/master; do
    if git rev-parse --verify --quiet "$candidate" >/dev/null; then
      ref=$candidate
      break
    fi
  done
fi
if [ -z "$ref" ]; then
  echo "No upstream branch found; pass a ref as the first argument (e.g. origin/master)." >&2
  exit 1
fi
if ! git rev-parse --verify --quiet "$ref" >/dev/null; then
  echo "No such ref: $ref" >&2
  exit 1
fi

synced=$(sed -n 's/^synced-upstream: *//p' "$marker")
if [ -z "$synced" ]; then
  echo "No synced-upstream line in $marker" >&2
  exit 1
fi
if ! git rev-parse --verify --quiet "$synced" >/dev/null; then
  echo "The recorded commit $synced is not in this clone (fetch, or update $marker)." >&2
  exit 1
fi

echo "recorded upstream commit: $synced"
echo "checking:                 $ref ($(git rev-parse --short "$ref"))"
echo
echo "== commits touching store.rs since then =="
git log --oneline "$synced..$ref" -- "$store" || true
echo
echo "== store.rs diffstat =="
git diff --stat "$synced..$ref" -- "$store" || true
echo
echo "== SCHEMA_VERSION =="
upstream_schema=$(git show "$ref:$store" | sed -n 's/^const SCHEMA_VERSION: i64 = \([0-9][0-9]*\);/\1/p')
fork_schema=$(sed -n 's/^const SCHEMA_VERSION: i64 = \([0-9][0-9]*\);/\1/p' "$fork")
echo "upstream: ${upstream_schema:-?}"
echo "fork:     ${fork_schema:-?}"
if [ -n "$upstream_schema" ] && [ "$upstream_schema" != "$fork_schema" ]; then
  echo "  !! schema changed: update the SQLite tables in $fork and this constant"
fi
echo
# Only the inherent methods of `impl Store` name the storage API; other public helpers are shared as re-exports.
methods() {
  awk '/^impl Store \{/ { inside = 1; next } inside && /^\}/ { exit } inside' \
    | grep -oE '^    pub (async )?fn [a-z_0-9]+' | awk '{print $NF}' | sort -u
}
echo "== Store methods only upstream (add them to $fork) =="
comm -23 <(git show "$ref:$store" | methods) <(methods < "$fork") | sed 's/^/  /'
echo
echo "== Store methods only in the fork (upstream removed them: mirror that) =="
comm -13 <(git show "$ref:$store" | methods) <(methods < "$fork") | sed 's/^/  /'
echo
echo "== next =="
cat <<'EOF'
  1. Read the SQL changes in the diff above and port them to src/fork/sqlite.rs.
  2. cargo test -p opentunnel-server --lib                     # upstream build untouched (skips storage tests
                                                               # without TEST_DATABASE_URL)
  3. cargo test -p opentunnel-server --features sqlite --lib   # the SQLite implementation
  4. Update synced-upstream in crates/opentunnel-server/src/fork/UPSTREAM and commit it with the merge.
EOF
