#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"

fail() {
  echo "operator-beta AG store-cut package check failed: $*" >&2
  exit 1
}

contract=docs/operator-beta-ag-store-cut-package-v1.md
qualification=qualification/operator-beta-ag-store-cut-package-v1
install_manifest=debian/agent-governor-ng-systemd-executor.install

[[ -f "$contract" && -f "$qualification/package-qualification.v1.json" && \
   -f "$qualification/package-qualification.v1.schema.json" ]] ||
  fail "package contract or closed qualification receipt is missing"

rg -q '837de287497942c79966aa05c083acee9c312261' "$contract" \
  "$qualification/README.md" "$qualification/package-qualification.v1.json" ||
  fail "accepted AG owner subject is not exact"
rg -q '^target/systemd-dbus/release/ag-effectd usr/libexec/agent-governor-ng$' \
  "$install_manifest" ||
  fail "feature-enabled process-adapter package ownership changed"
rg -q 'installs no service' "$contract" &&
  rg -q 'NQ-ng.*later invoke' "$contract" ||
  fail "inert package or owner-interface boundary is missing"

if [[ "${AG_OPERATOR_BETA_STORE_AUDIT_PACKAGE_GATE_INJECT:-0}" == "1" ]]; then
  fail "deterministic injected package boundary change"
fi

bash scripts/check-operator-beta-ag-store-cut-audit-v1.sh
python3 -m unittest discover \
  -s qualification/operator-beta-ag-store-cut-package-v1 \
  -p 'test_*.py' -q

echo "operator-beta AG store-cut package: PASS"
