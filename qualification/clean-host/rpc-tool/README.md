# Clean-host signed-RPC qualification fixture

`ag-clean-host-rpc` is qualification tooling, not an AG-ng production
interface. It is deliberately a standalone Cargo workspace beneath
`qualification/clean-host`; the root workspace build does not select it and
`debian/agent-governor-ng.install` does not install it.

It performs only four qualification operations by reusing the production
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
4. Forward one synthetic, single-effect managed-pointer intent directly to
   effectd's governor-facing proposal socket. This constructs the exact nested
   proposer-to-governor proof and governor-to-effectd signed exchange used by
   production, transfers one descriptor-stable bounded artifact, and prints
   the complete typed `ApiResultV1<EffectProposalResponseV1>`.

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

The direct managed-pointer forwarder is a narrow layer-2 qualification aid for
an already reviewed effectd configuration. It must start as root so it can
open both protected plaintext qualification credentials and the root-owned
configuration. Before connecting, it clears every supplementary group, sets
real/effective/saved GID and UID to the exact `agd_peer` values, and verifies
all six IDs plus the empty group set. It additionally requires the connected
effectd peer to be UID/GID 0, matching the packaged service:

```sh
sudo ag-clean-host-rpc forward-managed-pointer \
  --effectd-config /etc/agent-governor/effectd.toml \
  --governor-credential /root/qualification/agd-rpc.pkcs8 \
  --proposer-credential /root/qualification/proposer-rpc.pkcs8 \
  --artifact /root/qualification/candidate.bundle \
  --target service-repository \
  --intent-id clean-host-pointer-1 \
  --judgment sha256:<64-lowercase-hex>
```

`--effectd-skew-ms` may override the default 30,000 ms response-verification
window. The command exits successfully only for `canonicalized`; semantic
refusals, operationally indeterminate results, and API errors remain in the
canonical standard output but produce a nonzero exit status.

This operation deliberately holds the proposer and governor qualification
keys in one short-lived process and accepts an explicitly supplied judgment
digest. It proves effectd's existing authenticated forwarding, artifact, and
managed-pointer preparation boundary. It does **not** prove agd's judgment
store, admission decision, durable forwarding outbox, or role separation and
must never be represented as the ordinary production proposal path.

Hash the exact fixture executable separately in qualification evidence. It is
permitted as transferred inspection tooling, but it is not part of the
candidate package and cannot support a claim that the production package
contains a key-enrollment command.
