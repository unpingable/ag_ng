# M2 display fixture browser evidence — 2026-09-08

## Returned controller identity correction

The affected refusal browser case was checked against UI source SHA-256
`63a43bff807849ca8e35048899ab5385ba72fef84cb4daeb3f1a38d0c140ba18` in
`/data/git/.campaign-artifacts/m2-screen-refused-fixture-006`.
It checks the ordinary refusal display, explicit NQ-ng owner / Docket validator,
refresh and reconnect. Browser driver and helper bytes remain unchanged from
the identities in the following section. Broader prior display evidence stays
attached to its original source: this correction changes the subprocess reply
digest check and test fixture, with no HTML/rendering change.

## Owner/validator and executed-source correction

The nine cases below were rerun in
`/data/git/.campaign-artifacts/m2-screen-CASE-fixture-004` against these bytes:

| Subject | SHA-256 |
|---|---|
| `fixed_demo.py` | `3509910082e38d06b3d1ac1be81c7659f651c6ba56364cf95d984f827e2bb4da` |
| `browser_exercise.cjs` | `c01d85a31e62970ec9626260a36b91ec5ef2342eafb2b5eccdd67fca5cf91143` |
| `browser_fixture.py` | `ea0792955a467b359525607cf8c2769e18697ef3eb1cf3239ccc9daf9122936d` |

The browser now checks both owner and validator in each displayed terminal
receipt. Refusal fixtures name NQ-ng as owner and Docket as validator; successful
composition fixtures name Docket in both roles. These remain explicitly labeled
display fixtures, with no live integration or inherited independent acceptance.
All nine cases passed. The uncertainty case's first `fixture-004` attempt
failed because Chromium could not capture a screenshot; that failed capture is
preserved. Its fresh `fixture-005` capture passed against the same source bytes.
The other eight passing captures use `fixture-004`.

## Correction following independent rejection

The corrected source passed nine bounded Chromium cases in
`/data/git/.campaign-artifacts/m2-screen-CASE-fixture-003`, where CASE is
`launch`, `refused`, `failed`, `success`, `uncertain`, `unavailable`,
`no-process`, `active`, or `outage`. Each helper returned zero.
The unavailable case deliberately retains `CAPTURE-FAILED.json` and verifies
its reason. The new outage case starts with a validated fixture receipt, then
loses its source and checks that all thirteen current-value regions clear to
`NOT_OBSERVABLE`, with RUN disabled. Its terminal record is
`GOOD_TO_OUTAGE_ASSERTIONS_PASSED`.

Exact tested correction bytes:

| Subject | SHA-256 |
|---|---|
| `fixed_demo.py` | `19d72bce3c0d692179286e46cfbfa36ab10dde182ef85e10f1f183c1f9cdfd1c` |
| `browser_exercise.cjs` | `37e71092fb9646ae8fbc8451b078e16676b2098c985f1cf7efe2a2a1099ecea5` |
| `browser_fixture.py` | `9dab32ee88ff619b016fb1df561702dfa6d25503ebbde66041faf284d599095d` |

Fixture shapes now pass the actual adapter validator before display. They use
the allowed owner field vocabulary while every browser capture is explicitly
labeled `DISPLAY_FIXTURE`. These results do not establish live integration or
independent acceptance. The earlier evidence below remains attached to the
rejected original source and transfers no acceptance to this correction.

## Prior candidate display evidence (retained history)

**Disposition:** `DISPLAY_FIXTURES_PASSED / LIVE_INTEGRATION_NOT_RUN`.
This record is evidence for the UI candidate, not independent acceptance or a
composed campaign result. Tests used the actual AG demo HTTP handler and system
Chromium `152.0.7977.64` with its sandbox enabled. The controller was an explicit
local fixture; no Docket producer, VM, effect, provider, or deployment was run.

## Exact tested bytes

| Subject | SHA-256 |
|---|---|
| `crates/ag-operator-ui/demo/fixed_demo.py` | `769c92939a7668140e3f2c835f2c0d7d0115748e408de9ae7d2af735a3b4f8bc` |
| `qualification/operator-beta-m2-demo/browser_exercise.cjs` | `a9e2a32be319c1611a0161783c8139f7db505454a5344720530f74b71e33e11e` |
| `qualification/operator-beta-m2-demo/browser_fixture.py` | `f883530745bbb9647161431866928d47c74ca014a612d3a9f1bcbf475332e30e` |

All eight final cases retained these same identities. The fixture helper
executes the retained UI source bytes and records that digest in
`FIXTURE-SOURCES.json`. The browser driver records its digest, host/cwd/PID,
tool version and launcher identity in `CAPTURE-INPUTS.json`. Raw owner HTTP
bytes, rendered text, timestamped observations and fixture-marked screenshots
are retained in each capture directory. Earlier `fixture-001` captures remain
development history and do not substitute for this final byte set.

## Results

Each command was `python3 -B qualification/operator-beta-m2-demo/browser_fixture.py
CASE --out /data/git/.campaign-artifacts/m2-screen-CASE-fixture-002`, with one
bounded case per invocation. Every helper exited 0. Each ordinary browser
capture passed rendered durable/live/custody/terminal agreement, same subject,
refresh, and a new browser context. The launch case also made three deliberate
start requests and observed one fixture occurrence. This proves adapter
delegation only; Docket's real one-intent property requires its own tests.

| CASE | Observed display result | SHA-256 of capture terminal record |
|---|---|---|
| `launch` | One fixture launch; repeated requests/refresh/reconnect preserve subject | `dc3f68215c221fb8f729d94406e657c397fb2be5e3149de64ba76268eea64ade` |
| `refused` | Refusal and actual fixture evidence reference render normally | `4a390db5a682daf557a2555bb2fee8fa807f0d295dbe3e2b5aec1db1f05d715d` |
| `failed` | Owner effect failure reason remains a refusal | `8de8c582c19b4226989efb3d1690bc67785a6f80189452036f03e83996b0cf16` |
| `success` | Exact fixture disposition and receipt reference | `ad86e62df488574cc82c317e1ba719014fc8cba5f0f12397d5eafd6ab4f783b9` |
| `uncertain` | Missing acceptance disagreement; disabled RUN; no terminal claim | `3189a4b11659d3799b7333d4608c0069169c25d422d7a981927fd2d39d0d213f` |
| `unavailable` | NOT_OBSERVABLE notice/live state and disabled RUN; recorder refuses completion | `959b884e345d3d26670b9aae0bc2bd47ffe2b845f4c2b255ba4431126db0e290` |
| `no-process` | Nonterminal collecting-observations state with PROCESS_EXITED | `3189a4b11659d3799b7333d4608c0069169c25d422d7a981927fd2d39d0d213f` |
| `active` | Same nonterminal phase with PROCESS_ACTIVE | `3189a4b11659d3799b7333d4608c0069169c25d422d7a981927fd2d39d0d213f` |

Terminal record is `CAPTURE-COMPLETED.json` except `unavailable`, which
deliberately produced `CAPTURE-FAILED.json`; its helper checked the exact
unavailable-source reason before passing. Equal completion-record hashes in
three rows do not imply equal projections; those compact records report
nonterminal browser assertions while the per-case raw statuses retain the
different live/custody states.

## Boundaries still pending

Controller acceptance, installation/admission, original owner-interface
execution, producer/code custody, real lifecycle interruption, fresh composed
M1 witness on final dependencies, real browser → controller → effect →
observation journey, exact owner terminal reopening, teardown and integrated
independent acceptance remain separate requirements. The fixture server closes
its own HTTP/browser resources on completion; that is not VM teardown evidence.

The cached Playwright browser could not initialize its host sandbox. The
installed system Chromium passed under approved host execution with
`chromiumSandbox:true`; no permission control or browser sandbox was bypassed.
No production or unrelated successor campaign is qualified by this record.
