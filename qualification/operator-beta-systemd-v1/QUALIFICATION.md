# Operator-beta systemd D-Bus backend V1 qualification

## Result

**QUALIFIED** for the bounded AG-ng M1A owner scope at subject
`4f64dbe551356b7cc891134f51ec03fc3c856c9f`, tree
`9ef6509d8727cb388e86daf20f9226989756a059`.

This result qualifies one machine-bound `SystemdUnit/start` process adapter,
its known-no-effect/known-effect/outcome-unknown boundaries, exact executor
evidence and terminal replay, and its inert target-local Debian 12 binary
package. It does not qualify AG authorization, Docket process integration,
classic NQ observation, Nightshift launch, a real model/provider, production
deployment, other systemd actions, current postcondition after restart, or
literal exactly-once physical execution.

The closed machine result is
[`qualification-receipt.v1.json`](qualification-receipt.v1.json), checked by
[`qualification-receipt.v1.schema.json`](qualification-receipt.v1.schema.json)
and the existing M1A gate.

## Exact implementation and package custody

- accepted contract: `60de056e32b4c070de050dabcc5e836d4c017aad`;
- accepted runtime correction: `3dd6cbd394e05b4ba3ac2504cebd11a75996fcae`;
- accepted package correction/qualified subject:
  `4f64dbe551356b7cc891134f51ec03fc3c856c9f`;
- package: `agent-governor-ng-systemd-executor` `0.1.0-1+m1a3`, SHA-256
  `2852dc8a516980c4a1936d64a3a3f472d95fccf5eb3935f01a1be277f6b24f26`;
- installed adapter: `/usr/libexec/agent-governor-ng/ag-effectd`, SHA-256
  `d2c021892d470d227548bf94ceb943d6b9457592176f289bd9864b40a3aeb460`.

The default `/usr/bin/ag-effectd` package path remains on the unavailable
backend. The new package contains only the feature-enabled process adapter; it
installs no service, configuration, target, authority state, or mutable store.
The controller lacked the declared Debian debhelper/cargo/rustc build packages,
so a full `dpkg-buildpackage` source-package build is explicitly NOT_RUN. The
campaign-owned archive was constructed with `dpkg-deb` from the accepted exact
feature build. Two earlier never-installed archives were rejected because
their payload directory modes followed the controller umask; the admitted
archive has explicit `0755 root:root` directories and executable custody.

## Live Debian 12 qualification

Run-004 used the pinned Debian 12 amd64 cloud image, SHA-512
`490f38e2665bc4c31f1bd4cd66dfab3c7695f652a62862a7034d95f8f05ede4146d6dd55c70cc8b0ac9d9b4f54e18f8860bd5ad5ebfb7a8d5e934f3d12cf3817`,
systemd 252, kernel `6.1.0-52-cloud-amd64`, and exact machine identity
`bb1aa44ac2984af89f6d3ac865cd0004`.

Before package installation, the fixed HTTP fixture was disabled/inactive,
HTTP was absent, and no executor store existed. Package installation changed
none of those facts. One exact Docket-shaped dispatch then selected the sealed
V2 plan and started the target. The adapter returned `success` with receipt
`sha256:05cab6185fc19c509cc1b48d4aae776d7bb406a8e14e31de0af5f9bc87481eed`;
fresh systemd state was active/running and controller HTTP returned the exact
fixture bytes.

Duplicate execute, query-only reconcile, package removal, package reinstall,
and post-reinstall reconcile all preserved the exact invocation ID, monotonic
start times, and zero restart count. Every outcome was byte-identical. The
stable attempt database and lock anchor independently reproduced SHA-256
`093bd31e7712a7da84c9a4b784da31e1ece22a8640571cf515e3e6acd4a509db`
and `48106591f41030a9a457267d77a4c3e2e7f29eab478ccd79f670e8fe76c8b2a3`;
source and campaign-owned copy both reopened with SQLite integrity `ok`, and
the WAL was absent or zero-length at every accepted cut.

After a cold restart of the same overlay, package and store custody remained,
but the disabled target was inactive and HTTP absent. Reconcile initially
refused because reboot had removed the caller-owned plan from `/tmp`; after the
controller resupplied the exact plan, it returned the historical success
receipt without starting the target. Historical enactment and current support
therefore remained distinct.

Final cleanup first stopped on two SQLite auxiliary files created while the
copied database was reopened. A recovery boot observed the exact incomplete
teardown, removed only those campaign-owned files, verified package/unit/data/
store/backup absence, and powered off. No VM process or forwarded listener
remained; the overlay and controller evidence are retained for audit.

## Committed evidence

- [sealed V2 plan](evidence/run-004-systemd-plan-v2.json)
- [Docket-shaped dispatch](evidence/run-004-docket-dispatch-v1.json)
- [executor outcome](evidence/run-004-executor-outcome-v1.json)
- [typed effect receipt](evidence/run-004-effect-receipt-v1.json)
- [raw systemd evidence](evidence/run-004-systemd-evidence-v1.json)
- [final guest teardown observation](evidence/run-004-final-guest-teardown-observation.txt)
- [final host teardown observation](evidence/run-004-final-host-teardown-observation.txt)

The receipt schema and tests bind every artifact length and SHA-256 digest,
recompute the plan/work, canonical receipt, and domain-separated evidence
identities, bind the subject/scope/attempt/marker chain, and retain exact guest
and host teardown observations alongside the distinct post-restart
`NOT_ESTABLISHED_TARGET_INACTIVE_HTTP_ABSENT` fact.

## Qualification gates

- M1A boundary: 24 Rust passed, one fixture emitter intentionally ignored;
- Docket transport CLI: 1 passed;
- schema/runtime/package/receipt: 13 Python passed;
- deterministic injected boundary control: refused as expected;
- default and `systemd-dbus` release builds remained separate;
- run-004 package inventory, execute/replay/reconcile, stable cuts,
  remove/reinstall, cold restart, current-state observation, interruption
  recovery, and teardown: passed.

## Engineering / research / product / drift return

**Observed engineering result.** AG-ng now has a machine-bound, direct D-Bus
adapter that records the exact manager exchange and atomically couples it to a
Docket-shaped terminal receipt. Concurrent delivery and replay cannot produce
a second admitted mechanics occurrence for the same attempt; ambiguous cuts
remain outcome unknown. A separate inert package ran on Debian 12 and survived
remove/reinstall/restart custody tests. Added burden is a feature-specific
binary package, an executor-local SQLite evidence relation, an execution lock,
and explicit package/store lifecycle handling. Docket integration, NQ
postcondition qualification, source-package construction, and production use
remain unqualified.

**Codex research assessment.** This resolved whether a systemd job can be
bounded by exact machine/prestate/job/evidence custody without treating method
return as effect proof. The result is a useful application of established
D-Bus, systemd, SQLite, idempotency, and reconciliation practice; no novel
research contribution is claimed. The cold-restart case gives especially clear
evidence that an enactment receipt is not current-world truth.

**Observed product result.** A release engineer can now install one inert
target-local adapter, execute the fixed service-start case once, inspect its
receipt, and reconcile it after package and machine restart without a second
effect. This has been done in a disposable VM, but not through the intended
AG-to-Docket-to-NQ operator workflow. Product value here is enabling the M1A to
Docket handoff, not yet making the beta usable by a stranger.

**Codex drift assessment.** The campaign closed the missing AG systemd owner
and package prerequisite while adding bounded packaging and evidence custody;
those additions were necessary for the declared beta. The next showing is
closer because target enactment is no longer the missing owner primitive.
Defer general systemd actions, source-package polish, production deployment,
and broader backup machinery. Recommendation: **integrate/show**—move to the
existing Docket composition and NQ observation lanes, rather than expanding
AG-ng further.

`M1A_SYSTEMD_EFFECT_OWNER_QUALIFIED`
