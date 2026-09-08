#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"

fail() {
  echo "operator-beta AG store-cut audit check failed: $*" >&2
  exit 1
}

runtime=crates/ag-app/src/effect_executor_adapter/systemd_executor_v2.rs
cli=crates/ag-app/src/bin/ag-effectd.rs
contract=docs/operator-beta-ag-store-cut-audit-v1.md

rg -q 'pub fn audit_systemd_effect_store_cut' "$runtime" &&
  rg -q 'SQLITE_OPEN_READ_ONLY' "$runtime" &&
  rg -q 'immutable=1' "$runtime" &&
  rg -q 'MAX_AUDIT_STORE_CUT_BYTES: u64 = 64 \* 1024 \* 1024' "$runtime" ||
  fail "bounded read-only owner reopener is incomplete"
rg -q 'validate_systemd_evidence_guards' "$runtime" &&
  rg -q 'outcome_v2_from_connection' "$runtime" &&
  rg -q 'systemd-audit-store-wal-present' "$runtime" &&
  rg -q 'systemd-audit-store-content-substitution' "$runtime" &&
  rg -q 'systemd-audit-store-pathname-replacement' "$runtime" ||
  fail "owner evidence or pathname custody is not reopened"
rg -q 'Command::AuditStore' "$cli" &&
  rg -q 'store_bytes' "$cli" &&
  rg -q 'store_sha256' "$cli" &&
  rg -q 'audit-store-requires-systemd-v2' "$cli" ||
  fail "query-only CLI surface is missing or not V2-bounded"
rg -q 'systemd-store-qualification-fixture = \[\]' crates/ag-app/Cargo.toml &&
  rg -q 'seed_terminal_systemd_store_for_qualification' \
    crates/ag-app/tests/systemd_executor_v2_cli.rs &&
  ! rg -q 'execute_systemd_effect_attempt' \
    crates/ag-app/tests/systemd_executor_v2_cli.rs ||
  fail "functional CLI audit is not seeded by the no-bus qualification fixture"
rg -q 'does not acquire the live' "$contract" &&
  rg -q 'execution lock' "$contract" &&
  rg -q 'authoritative live attempt store' "$contract" ||
  fail "non-authorizing copied-store boundary is missing"

if [[ "${AG_OPERATOR_BETA_STORE_AUDIT_GATE_INJECT:-0}" == "1" ]]; then
  fail "deterministic injected boundary change"
fi

cargo test -q --locked -p ag-app --features systemd-dbus systemd_executor_v2::tests
cargo test -q --locked -p ag-app \
  --features systemd-dbus,systemd-store-qualification-fixture \
  --test systemd_executor_v2_cli

echo "operator-beta AG store-cut audit boundary: PASS"
