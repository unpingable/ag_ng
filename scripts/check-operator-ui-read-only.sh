#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ui="$root/crates/ag-operator-ui"

if rg -n '"(init|record-proposal|require-standing|decide|authorize|dispatch|poll-docket|recover|open-continuation|halt|complete|reconcile|accept|execute|request-probe|request-successor|request-halt|request-reconciliation|submit-intervention|prepare-intervention-request|package-intervention-submission|apply-disposition)"' "$ui/src"; then
  echo "operator UI contains a mutation-capable command verb" >&2
  exit 1
fi

if rg -n 'rusqlite|ag-app' "$ui/Cargo.toml"; then
  echo "operator UI links a runtime mutation or database surface" >&2
  exit 1
fi

if ! rg -q 'b"GET" => Some\(false\)' "$ui/src/server.rs" || ! rg -q 'b"HEAD" => Some\(true\)' "$ui/src/server.rs"; then
  echo "operator UI HTTP method allowlist is missing" >&2
  exit 1
fi

if rg -n '"(POST|PUT|PATCH|DELETE)" =>' "$ui/src/server.rs"; then
  echo "operator UI exposes a mutation HTTP method" >&2
  exit 1
fi

if rg -ni '<(form|button)|method=' "$ui/src/render.rs"; then
  echo "operator UI presentation exposes an action control" >&2
  exit 1
fi

if rg -ni '<script|application/javascript|\bfetch\s*\(|XMLHttpRequest|WebSocket' "$ui/src"; then
  echo "operator UI introduced a browser execution or network mutation surface" >&2
  exit 1
fi

if rg -ni '<(input|textarea|select)' "$ui/src/render.rs"; then
  echo "operator UI presentation exposes an input surface" >&2
  exit 1
fi

if rg -n 'pub (authorization|spend|issuance|signature|capability|secret|token):' "$ui/src/links.rs"; then
  echo "Phosphor-ng navigation link carries authority-bearing material" >&2
  exit 1
fi

if ! rg -q 'campaign: Digest' "$ui/src/links.rs" \
  || ! rg -q 'occurrence: OccurrenceId' "$ui/src/links.rs" \
  || ! rg -q 'proposal: Option<Digest>' "$ui/src/links.rs"; then
  echo "Phosphor-ng semantic link identity set drifted" >&2
  exit 1
fi

for verb in inspect status replay history refusals intervention-submissions export-observation export-authoring-context export-authoring-custody external-observation; do
  if ! rg -q "$verb" "$ui/src/source.rs"; then
    echo "operator UI closed read-command surface lost $verb" >&2
    exit 1
  fi
done

if rg -n 'ExternalObservation(Custody|Claim|Export).*::(new|mint|seal)' "$ui/src"; then
  echo "operator UI can construct owner-side external observation/custody" >&2
  exit 1
fi

if rg -n 'AuthoringContextProvenanceV1::(new|mint|seal)|AuthoringContextCustodyProvenanceV1::(new|mint|seal)|MaudeAuthoringContext(Input|Handoff)V1|HmacAuthenticationV1' "$ui/src"; then
  echo "operator UI can construct owner-side authoring provenance" >&2
  exit 1
fi

echo "operator UI read-only structure: PASS"
