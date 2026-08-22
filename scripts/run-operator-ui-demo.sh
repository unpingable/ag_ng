#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
demo_directory=$(mktemp -d)
demo_corpus="$demo_directory/operator-demo-corpus.json"

cleanup_demo() {
  rm -f -- "$demo_corpus"
  rmdir -- "$demo_directory" 2>/dev/null || true
}
trap cleanup_demo EXIT INT TERM

cd "$repo_root"
AG_OPERATOR_DEMO_OUTPUT="$demo_corpus" \
  cargo test --locked -p ag-app --test governed_loop_engine \
  write_operator_demo_corpus_from_production_engine_fixtures -- \
  --ignored --exact
cargo build --locked -p ag-operator-ui

printf 'deterministic corpus: %s\n' "$demo_corpus"
printf 'open Phosphor-ng: http://127.0.0.1:8417/phosphor-ng\n'
target/debug/ag-operator-ui --demo-corpus "$demo_corpus" "$@"
