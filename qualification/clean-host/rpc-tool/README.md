# Clean-host signed-RPC qualification fixture

`ag-clean-host-rpc` is qualification tooling, not an AG-ng production
interface. It is deliberately a standalone Cargo workspace beneath
`qualification/clean-host`; the root workspace build does not select it and
`debian/agent-governor-ng.install` does not install it.

It performs only three qualification operations by reusing the production
`ag-app` protocol and signed-transport types:

1. Generate a `ring` Ed25519 PKCS#8-v2 private key with mode `0600`, refusing
   to replace an existing path, and emit its non-secret canonical public
   enrollment record.
2. Perform authenticated `agd` or direct `ag-effectd` health RPC. The effectd
   form retains the complete activation status which installed `agctl health`
   intentionally projects away.
3. Submit one bounded strict `ProposalIntentV1` through the authenticated agd
   ingress, printing the exact typed response before returning failure for a
   refusal or indeterminate result.

Build and test it explicitly; never add it to the Debian install manifest:

```sh
cargo test --locked --offline \
  --manifest-path qualification/clean-host/rpc-tool/Cargo.toml
cargo build --locked --offline --release \
  --manifest-path qualification/clean-host/rpc-tool/Cargo.toml
```

Generate one key and its enrollment evidence:

```sh
ag-clean-host-rpc generate-key \
  --principal sha256:<64-lowercase-hex> \
  --key-id agd.v1 \
  --private-key-output /root/qualification/agd-rpc.pkcs8 \
  --credential-path /run/credentials/agd.service/rpc-ed25519-pkcs8 \
  > /root/qualification/agd-rpc-enrollment.json
```

The private output is plaintext qualification staging material. Encrypt it
with the host's normal `systemd-creds` enrollment path, verify the public half
against the emitted record, and remove plaintext according to the recorded
qualification procedure. Never place private-key bytes or their content hash
in the evidence bundle.

Authenticated commands require the same root-custodied single-role agctl TOML
and systemd credential context as installed `agctl`:

```sh
ag-clean-host-rpc health --config /etc/agent-governor/agctl-proposer.toml agd
ag-clean-host-rpc health --config /etc/agent-governor/agctl.toml ag-effectd
ag-clean-host-rpc submit-proposal \
  --config /etc/agent-governor/agctl-proposer.toml \
  --intent /srv/agent-governor/intents/change.json
```

Hash the exact fixture executable separately in qualification evidence. It is
permitted as transferred inspection tooling, but it is not part of the
candidate package and cannot support a claim that the production package
contains a key-enrollment command.
