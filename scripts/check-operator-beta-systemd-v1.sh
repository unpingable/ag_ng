#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"

fail() {
  echo "operator-beta systemd boundary check failed: $*" >&2
  exit 1
}

contract=docs/operator-beta-systemd-dbus-backend-v1.md
runtime=crates/ag-app/src/effect_executor_adapter/systemd_executor_v2.rs
driver=crates/ag-app/src/effect_executor_adapter/systemd_executor_v2/zbus_driver.rs
tests=crates/ag-app/src/effect_executor_adapter/systemd_executor_v2/qualification_tests.rs
adapter=crates/ag-app/src/effect_executor_adapter.rs
cli=crates/ag-app/src/bin/ag-effectd.rs
manifest=crates/ag-app/Cargo.toml
package_control=debian/control
package_rules=debian/rules
package_install=debian/agent-governor-ng-systemd-executor.install
package_test=debian/tests/systemd-executor-package-contract

[[ -f "$contract" && -f "$runtime" && -f "$driver" ]] ||
  fail "accepted contract or owner implementation is missing"

rg -q '^systemd-dbus = \["dep:async-io", "dep:futures-util", "dep:zbus"\]$' "$manifest" ||
  fail "systemd backend is not an explicit build feature"
rg -q 'ag-effectd\.docket-executor-systemd-plan/v2' "$runtime" &&
  rg -q 'ag-effectd\.docket-executor-systemd-work/v2' "$runtime" &&
  rg -q 'ag-effectd\.systemd-dbus-evidence/v1' "$runtime" ||
  fail "machine-bound plan, work, or evidence schema identity is missing"

v1_plan="$(sed -n '/pub struct EffectExecutorPlanV1/,/^}/p' "$adapter")"
if rg -q 'systemd_machine_identity|execution_lock_timeout_ms|job_timeout_ms' <<<"$v1_plan"; then
  fail "legacy EffectExecutorPlanV1 was reinterpreted"
fi
rg -q 'LoadedEffectExecutorPlan::V1' "$cli" &&
  rg -q 'LoadedEffectExecutorPlan::SystemdV2' "$cli" ||
  fail "CLI does not keep V1 and systemd V2 plan families distinct"

rg -q 'O_NOFOLLOW' "$adapter" &&
  rg -q 'MAX_PLAN_BYTES' "$adapter" &&
  rg -q 'decode_effect_executor_systemd_plan\(&canonical\)' "$adapter" ||
  fail "schema discrimination is not one bounded no-follow acquisition"

subscription_line="$(rg -n 'receive_signal\("JobRemoved"\)' "$driver" | cut -d: -f1)"
start_line="$(rg -n 'call_method\("StartUnit"' "$driver" | cut -d: -f1)"
[[ -n "$subscription_line" && -n "$start_line" && "$subscription_line" -lt "$start_line" ]] ||
  fail "JobRemoved subscription no longer precedes StartUnit"
rg -q 'Connection::system\(\)' "$driver" &&
  rg -q 'call_method\("GetMachineId"' "$driver" &&
  rg -q 'call_method\("RefUnit"' "$driver" &&
  rg -q 'call_method\("GetUnit"' "$driver" ||
  fail "local system-bus machine and unit preflight is incomplete"
rg -q 'live_machine_identity != plan\.systemd_machine_identity' "$driver" ||
  fail "live machine identity is not compared to the sealed plan"
rg -q '"systemd_start_method_error"' "$driver" &&
  rg -q 'transcript\.indeterminate\(' "$driver" ||
  fail "post-transmission manager error is not outcome-unknown"

rg -q 'SYSTEMD_EVIDENCE_UPDATE_TRIGGER_SQL' "$adapter" &&
  rg -q 'SYSTEMD_EVIDENCE_DELETE_TRIGGER_SQL' "$adapter" &&
  rg -q 'normalized_sql\(&sql\) != expected' "$adapter" &&
  rg -q 'TransactionBehavior::Immediate' "$runtime" &&
  rg -q 'systemd-evidence-without-terminal' "$runtime" &&
  rg -q 'same_name_inert_evidence_guards_refuse_before_permitted_mutation_is_trusted' "$tests" ||
  fail "append-only atomic evidence/terminal custody is incomplete"
rg -q '\.systemd-execution-lock' "$runtime" &&
  rg -q 'bind_or_validate_store_anchor' "$runtime" &&
  rg -q 'validate_current_paths' "$runtime" &&
  rg -q 'systemd-store-identity-substitution' "$runtime" &&
  rg -q 'pathname_replacement_cannot_split_concurrent_writers_or_invoke_mechanics' "$tests" ||
  fail "stable attempt-store lock and pathname custody is incomplete"
rg -q 'MAX_MESSAGES: usize = 16' "$runtime" &&
  rg -q 'MAX_MESSAGE_BYTES: usize = 64 \* 1024' "$runtime" &&
  rg -q 'MAX_CUMULATIVE_MESSAGE_BYTES: usize = 256 \* 1024' "$runtime" ||
  fail "evidence count/per-message/cumulative bounds changed"

rg -q 'systemd_attempt_in_progress' "$cli" &&
  rg -q 'std::process::exit\(75\)' "$cli" ||
  fail "bounded lock contention is not the fixed Docket transport refusal"
if rg -q 'Command::new|systemctl|/bin/sh|sh -c' "$runtime" "$driver"; then
  fail "systemd backend acquired a subprocess control path"
fi

rg -q '^Package: agent-governor-ng-systemd-executor$' "$package_control" &&
  rg -q -- '--features systemd-dbus --target-dir target/systemd-dbus' "$package_rules" &&
  rg -q '^target/systemd-dbus/release/ag-effectd usr/libexec/agent-governor-ng$' "$package_install" ||
  fail "dedicated feature-enabled process-adapter package is missing"
if rg -q 'systemctl (start|stop|restart)|deb-systemd-invoke|\.service usr/' "$package_install" "$package_test"; then
  fail "process-adapter package acquired a service lifecycle action"
fi

dependency_graph="$(cargo tree --locked --offline --package ag-app --features systemd-dbus --edges normal,build --prefix none --format '{p}')"
for forbidden_crate in \
  ag-providerd reqwest hyper hyper-util hyper-rustls rustls tokio-rustls \
  native-tls openssl curl ureq surf isahc quinn
do
  if rg -q "^$forbidden_crate v" <<<"$dependency_graph"; then
    fail "feature-enabled effect adapter acquired forbidden dependency $forbidden_crate"
  fi
done

if [[ "${AG_OPERATOR_BETA_SYSTEMD_GATE_INJECT:-0}" == "1" ]]; then
  fail "deterministic injected boundary change"
fi

cargo check -q -p ag-app --all-targets
cargo check -q -p ag-app --all-targets --features systemd-dbus
cargo test -q -p ag-app effect_executor_adapter --lib --features systemd-dbus
cargo test -q -p ag-app --test systemd_executor_v2_cli --features systemd-dbus
python3 -m unittest discover -s qualification/operator-beta-systemd-v1 -p 'test_*.py' -q

echo "operator-beta systemd boundary: PASS"
