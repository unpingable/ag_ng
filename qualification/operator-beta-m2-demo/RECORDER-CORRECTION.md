# Browser response / DOM correspondence correction

The first real browser capture remains preserved at
`/data/git/.campaign-artifacts/m2-browser-run-001`. It performed RUN and repeated
requests, then failed its recorder assertion. Its final sampled owner response
records phase `created`; the old recorder required the independently sampled
response to equal a browser view that could already have advanced. A newer
phase cannot satisfy that old-snapshot equality. The missing intermediate
screenshots remain missing. This correction neither repairs that capture nor
restarts the producer.

The corrected qualification driver observes the actual GET responses consumed
by the page. It retains at most eight bounded responses and pairs an atomic DOM
observation with matching source bytes. Matching covers durable/live state,
custody, terminal receipt owner/validator, execution identity, source testimony,
limitations and individual evidence rows. A ten-second matching bound remains;
an incorrect view cannot pass simply because time elapsed. Each paired capture
retains raw response bytes, rendered text, response/DOM timestamps and a
correspondence record. The screenshot is explicitly a subsequent visual
observation: state can advance after the atomic text observation.

This changes only the qualification recorder and its controls. The running
screen remains the exact `13a9120da697217d1e12ac4351739ce6a2f0a8a6` implementation,
source SHA-256 `63a43bff807849ca8e35048899ab5385ba72fef84cb4daeb3f1a38d0c140ba18`.
No controller, screen executable, producer or enrolled occurrence was changed.

## Bounded local evidence

- `node --test qualification/operator-beta-m2-demo/test_browser_coherence.cjs`
  passed: advancing responses, mixed/incorrect rendering, and source-loss
  matching controls.
- `node --check qualification/operator-beta-m2-demo/browser_exercise.cjs` passed.
- `/data/git/.campaign-artifacts/m2-browser-transition-control-001` passed with
  three distinct phases on three browser reads and zero RUN requests. Every
  query advances phase, so independently sampling a different request would
  reintroduce the original mismatch.
- `/data/git/.campaign-artifacts/m2-browser-render-mismatch-control-001` passed
  its negative-control expectation: the deliberately incorrect fixture phase
  caused `CAPTURE-FAILED.json`, never successful capture completion.
- Refusal and successful-terminal display regressions passed at
  `/data/git/.campaign-artifacts/m2-recorder-refused-fixture-001` and
  `/data/git/.campaign-artifacts/m2-recorder-success-fixture-001`.

Exact driver SHA-256:
`84ed87c38b7e780349407a242ef5b4c1717c34aa7a2872448d3bc6b26e33a2b9`.
Matching helper SHA-256:
`2a343d86a8620c5f62ff7ecd7f5494ee54fddf893383dd63a9359ba11d2b987a`.

These are display/recorder controls, not live integration acceptance. After
independent review, primary may start a fresh **observe-only** capture against
the existing occurrence using `--action observe --wait-terminal`. It must use
the approved durable supervision mechanism and a new artifact directory.
RUN, reset, restart, and replacement are not recovery actions for this failure.
