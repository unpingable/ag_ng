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

for verb in inspect status replay history refusals intervention-submissions export-observation export-authoring-context export-authoring-custody external-observation export-occurrence; do
  if ! rg -q "$verb" "$ui/src/source.rs"; then
    echo "operator UI closed read-command surface lost $verb" >&2
    exit 1
  fi
done

if ! rg -Fq 'Acquisition mechanics may cause observation; only Nightshift determines custody composition/currentness.' "$ui/src/render.rs"; then
  echo "operator UI lost acquisition/currentness owner distinction" >&2
  exit 1
fi

if rg -n 'ExternalObservation(Custody|Claim|Export).*::(new|mint|seal)' "$ui/src"; then
  echo "operator UI can construct owner-side external observation/custody" >&2
  exit 1
fi

if ! rg -q 'age is not currentness' "$ui/src/render.rs" \
  || rg -n 'evidence_age.*(Current|currentness)|observed_at.*fresh_until|fresh_until.*observed_at' "$ui/src"; then
  echo "Phosphor-ng display-age projection drifted into canonical currentness" >&2
  exit 1
fi

for owner_projection in \
  'Historical application/world evidence' \
  'Evidence age (display only)' \
  'Nightshift currentness at governed evaluation' \
  'Historical qualification' \
  'Current steady-state' \
  'No new failure test was performed.'; do
  if ! rg -Fq "$owner_projection" "$ui/src/render.rs"; then
    echo "operator UI lost the custody/age/currentness distinction: $owner_projection" >&2
    exit 1
  fi
done

if rg -n 'AuthoringContextProvenanceV1::(new|mint|seal)|AuthoringContextCustodyProvenanceV1::(new|mint|seal)|MaudeAuthoringContext(Input|Handoff)V1|HmacAuthenticationV1' "$ui/src"; then
  echo "operator UI can construct owner-side authoring provenance" >&2
  exit 1
fi

echo "operator UI read-only structure: PASS"
