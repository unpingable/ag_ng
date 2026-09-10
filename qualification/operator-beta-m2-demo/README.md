# M2 browser observation driver

This bounded Playwright client exercises the existing AG demo and records what
the browser saw. It supplies no campaign state, retry, terminal validator, or
qualification acceptance. `CAPTURE-COMPLETED.json` means browser assertions
passed; Docket owner reopening and independent review are still required.

Use the existing Playwright installation or set `M2_PLAYWRIGHT_MODULE` to its
absolute module directory. The defaults are the module observed on `crow` and
system Chromium `/snap/bin/chromium`; override the browser with `--browser` or
`M2_BROWSER_EXECUTABLE`. The cached Playwright Chromium cannot initialize its
host sandbox here; system Chromium 152.0.7977.64 passed a bounded about:blank
launch with the sandbox enabled after platform execution approval.
No package installation or browser download occurs. Chromium runs with its
sandbox enabled; a host permission failure is reported rather than bypassed.

Against a **separately started and explicitly labeled fixture** demo:

```bash
node qualification/operator-beta-m2-demo/browser_exercise.cjs \
  --url http://127.0.0.1:8765/ --out /tmp/m2-fixture-capture-001 \
  --mode DISPLAY_FIXTURE --action observe --max-seconds 60 \
  --expect-state REFUSED --expect-live PROCESS_EXITED
```

For the **accepted, admitted live installation**, after primary integration
prerequisite clearance, use a fresh output directory and the actual recorded URL:

```bash
node qualification/operator-beta-m2-demo/browser_exercise.cjs \
  --url http://127.0.0.1:8765/ --out /data/git/.campaign-artifacts/m2-browser-run-001 \
  --mode LIVE_INTEGRATION --action launch --repeat-run --wait-terminal \
  --max-seconds 7200
```

This invocation is a template, not clearance to start an unaccepted controller.
Launch is explicit; the default action only observes. `--repeat-run` deliberately
checks that duplicate owner requests preserve the same admitted occurrence.
The driver does not implement duplicate suppression. The controller's negative
controls and custody records must establish the one-manager-call property.

Run long captures through the campaign's approved durable execution mechanism.
First retain exact UI/controller/spec/revisions, capture command/unit identity,
logs/output, terminal filenames and next lawful action in the recovery
checkpoint. Reconnect to a continuing producer with `--action observe`; never
rerun launch merely because the browser supervisor disappeared.

The driver records exact HTTP projection bytes, screenshots, rendered text,
timestamped browser observations, tool/input identity, and a completed or failed
capture record. The output directory must be new; existing captures are never
overwritten. Fixture screenshots are marked `DISPLAY FIXTURE`. Browser logs do
not replace domain evidence. A bound expiring, query error, missing terminal or
assertion failure writes `CAPTURE-FAILED.json` and returns nonzero without
stopping, resetting or restarting the producer.

The source bytes now come from the page's own observed responses and are paired
with a matching atomic DOM observation; independent queries cannot demand that
an advancing page return to an older phase. Screenshot timing is recorded as a
subsequent visual observation. See `RECORDER-CORRECTION.md` for the retained
first-live-capture failure, bounded transition/mismatch controls and the
observe-only continuation boundary.

Cases covered: real RUN when explicitly selected, deliberate duplicate requests,
refresh, new browser context/reconnect, stable run/spec/observed producer identity,
independent durable/live rendering, and exact optional expected terminal result.
Refusal/uncertainty/failed-owner projections require separate labeled fixtures
or owner-controlled qualification occurrences. One successful capture does not
claim coverage of all outcomes. Retain the final Docket check-run/check-refusal
and reviewer evidence separately, bound to the same run and exact dependencies.

`browser_fixture.py CASE --out ABSOLUTE_NEW_DIRECTORY` runs one local display
fixture through the actual demo HTTP server and browser driver, bounded to
45 seconds. Available cases are launch, active, no-process, uncertain, refused,
failed, success, unavailable and outage. The outage case starts with a valid
terminal receipt, then loses its source and asserts that every current-value
region clears to `NOT_OBSERVABLE`. It never loads the real controller or starts
VMs. The unavailable case expects `CAPTURE-FAILED.json`, verifies the explicit
unavailable reason, and reports that negative check as passed. The launch case
asserts three deliberate start requests resolve to one fixture occurrence;
real one-intent custody still requires the Docket owner qualification.

For a human review of the same explicitly synthetic projection, keep one
bounded loopback fixture visible instead of invoking the headless capture:

```bash
python3 -B qualification/operator-beta-m2-demo/display_fixture_server.py refused \
  --port 8767 --max-seconds 7200
```

Open `http://127.0.0.1:8767/`. Stop that exact process before selecting another
case. This server is labeled `DISPLAY_FIXTURE`, never loads Docket, and cannot
establish integration or human-usability acceptance by itself.
