# Governed Campaign Loop V0 contract

Status: implementation contract, 2026-08-27.

## Attachment-point map

Current production ownership was re-established from live source before this
contract was added.

| Fact or decision | Existing owner | V0 attachment |
|---|---|---|
| queued/prepared intent and temporal applicability | Nightshift | exact retained packet/profile references and fresh Q3 applicability |
| deterministic repository qualification | NQ | `nq.campaign-stage-qualification-profile/v1` over factual raw evidence |
| admissibility and one-use authorization | AG | `CampaignEngineV1`, exact V2 catalog basis, existing spend law |
| campaign continuation/program counter | AG | existing distinct-occurrence continuation and mandatory V0 terminal disposition |
| stage standing, attempt custody, settlement, reconciliation | Docket | existing signed issuance and governed executor transport |
| executor-local idempotency | fixed worker/executor | exact one-attempt mechanics and receipt only |
| substrate execution receipts | Porter where selected | factual receipt only; Porter never produces `QUALIFIED` |
| controller coordination | AG application surface | immutable packet validation and authority-free phase reconstruction |

Classic campaign-driver is historical and retains retired authority. CDNG's
current production surface is executor-local (`plan-id`, `execute`, and
`reconcile`) and cannot own continuation. Nightshift's closed production graph
has no Docket or executor edge. The smallest lawful V0 placement is therefore
the AG application surface beside the existing campaign engine. No authority
moves between offices.

## Exact V0 bounds

V0 admits exactly:

- one absolute repository/workspace;
- one Crow host;
- one fixed worker/model/effort/launch configuration;
- one sequential campaign;
- exactly three predeclared stages;
- one exact attempt per stage;
- no dynamic planning, model routing, successor construction, parallelism, or
  automatic repair;
- an unconditional AG `HUMAN_REQUIRED` boundary after Stage 3.

The packet transcript commits every field except its own `packet_id`, the
three nested copies of that identity, and the three derived exact NQ profile
hashes. Those six cycle-forming fields are blanked in the versioned transcript;
all other profile and packet bytes participate. Changing any semantic field
changes the packet identity.

Each stage binds its exact predecessor HEAD/tree and qualification artifacts,
expected result HEAD/tree, attempt, work, instruction, mutation paths,
qualification commands, complete NQ profile, and enumerated successor.
Successor and predecessor chains are validated before Stage 1 admission.

## Sole qualification bridge

The controller requests only factual packet-declared gates. It transports the
retained raw evidence to NQ, transports the exact immutable NQ receipt to
Nightshift, and presents only Nightshift's fresh typed observation to AG.

```text
declared factual gates
  -> retained raw evidence
  -> exact pinned NQ evaluator/profile
  -> immutable historical NQ receipt
  -> Nightshift exact receipt replay and current applicability
  -> ag.governed-loop.observation-resolution/v3
  -> AG exact catalog decision and one-use authorization
```

There is no controller input named `QUALIFIED`. The V0 API has no NQ status
field and no caller-verdict constructor. Its sole positive successor input is
an AG authorization bound to:

- `nightshift.repository-qualification-applicability/v1`;
- the complete opaque basis identity;
- `nightshift.repository-qualification-resolver/v1`;
- `current` observation status;
- the exact source-stage NQ profile;
- the exact enumerated successor and successor work.

`FAILED`, `INDETERMINATE`, absent, stale, superseded, wrong-predecessor,
wrong-profile, raw-command-success, worker assertion, or resolver substitution
cannot form this input and therefore stop.

## Predeclared exact-basis determinism

AG's frozen V2 catalog deliberately matches the complete opaque typed basis,
not merely a basis class or profile. NQ receipts deliberately bind complete
raw evidence, including evidence times. V0 does not weaken either law.

The one synthetic V0 specimen therefore uses a packet-declared bounded coarse
Unix clock bucket and deterministic fixed worker/gates. The factual producer
must execute and finish inside that bucket; otherwise it emits indeterminate
evidence and the campaign stops. This permits every expected result, raw
evidence identity, receipt identity, Nightshift basis, and AG catalog entry to
be declared before Stage 1 without pre-running or self-judging a stage.

This is a V0 limitation, not a general scheduling or policy mechanism. A later
version would need a separately adjudicated way to bind dynamic qualification
occurrences without weakening AG's exact-basis law.

## Admission and resource law

Before every stage, factual admission must establish exact packet/stage,
repository identity, persistent write/read/reopen behavior, exact HEAD/tree,
declared worktree state, predecessor artifact hashes, fixed worker identity,
and resource margin. V0 fixes concurrent campaigns to one and records positive
memory, disk, memory-ceiling, process-ceiling, and CPU-quota bounds.

Any false or missing predicate stops before Docket dispatch. A resource refusal
is not cached as later admission and must be re-established after every frozen
stage.

## Crash/restart law

The controller snapshot is coordination evidence only. Authority remains in
AG and attempt truth remains in Docket.

| Durable phase | Restart action |
|---|---|
| `PREPARED` | rerun complete admission |
| `ADMITTED` | dispatch the one exact packet attempt |
| `EXECUTING` | reconcile that attempt; never create another |
| `QUALIFYING` | replay retained raw evidence/NQ receipt; never repeat effect |
| `FROZEN` | observe only the enumerated successor |
| `HUMAN_REQUIRED` / `STOPPED` | stop |

If exact reconciliation cannot be established, the result is indeterminate.
There is no transparent retry or repair campaign.

## Nonclaims

The V0 controller does not create standing, authorization, qualification,
successor choice, continuation authority, effect authority, or human judgment.
It does not implement V1, a workflow language, a scheduler, model selection, or
a generalized campaign product.
