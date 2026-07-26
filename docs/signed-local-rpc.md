# Signed local RPC integration

The production local transport is a three-frame, mutually authenticated
exchange on one Unix connection:

1. the server signs a fresh challenge for the enrolled caller;
2. the caller signs the strict request, its exact body digest, and that
   challenge, then half-closes the connection;
3. the server signs the exact request echo, the complete signed-request digest,
   and the canonical response-body digest.

All signatures use Ed25519 through `ring`. Signed statements bind protocol
version, request ID, direction, signer and audience principal/key identities,
fresh 256-bit nonces, and bounded Unix timestamps. Verification records each
accepted nonce in an explicitly sized fail-closed replay guard. The per-socket
server challenge prevents a captured request from becoming usable after a
daemon restart even though the replay guard is process-local.

## Enrollment and credentials

Each daemon configuration has a mandatory `rpc_signing_identity` table. Its
`private_key_credential` is the absolute file created by an explicit systemd
`LoadCredential=` mapping and contains Ed25519 PKCS#8 v2 bytes. The loader uses
`O_NOFOLLOW`, accepts only a protected regular file with one link, limits input
to 4096 bytes, and verifies that the derived public key equals root-owned
configuration. Secret bytes are never serializable or included in an error.

Each `PeerPolicyV1` has a mandatory `rpc_key` table containing the exact signed
leaf principal, key ID, Ed25519 public key, and non-zero clock-skew bound. The
peer's enrollment-chain root is `stable_principal_root`; current one-node
enrollments set leaf and root equal, while a future launcher lineage may not.
UID, GID, PID, executable, and cgroup observations do not establish either
identity.

The packaged units map the credential name `rpc-ed25519-pkcs8`. Therefore the
corresponding configuration paths are, for example:

```text
/run/credentials/agd.service/rpc-ed25519-pkcs8
/run/credentials/ag-effectd.service/rpc-ed25519-pkcs8
/run/credentials/ag-providerd.service/rpc-ed25519-pkcs8
```

Key generation and enrollment are deployment operations. Never copy the
placeholder public keys from the example configuration into a real host.

## Server integration

At startup, load one `RpcSignerV1`, build each allowed caller as an
`RpcPeerEnrollmentV1`, and create an explicitly bounded
`RpcReplayGuardV1`. For every accepted stream, call
`accept_signed_request`; dispatch only after it returns successfully, then call
`write_signed_response` with the retained accepted request. A server must keep
the same accepted wrapper through dispatch because the response proof binds
its exact digest.

## Client integration

Load the client's signer and construct the expected server enrollment from
root-owned configuration. `call_signed` performs the entire exchange and
returns the method-specific response body. The caller owns a persistent replay
guard rather than creating one per request.

`SocketPeerCheckV1::ObserveOnly` never opens `/proc` and treats `SO_PEERCRED` as
diagnostic context. `RequireUidGid` adds an explicit fail-closed kernel
credential check, but a matching UID/GID still cannot replace a valid
signature. Every daemon listener in the current production-shaped startup uses
the UID/GID enrolled for that exact signed peer; the role-specific `agctl`
profile makes its daemon-side check explicit and the shipped examples require
it. There is no legacy `authenticate_peer` path to avoid: the process-observation
routine that once served the unsigned bootstrap transport has been removed, and
no symbol by that name exists in the tree. Peer authentication is the signed
three-frame exchange described above; nothing else authenticates a peer.

Clock synchronization is an availability prerequisite. A proof outside its
peer policy's skew window is rejected, including timestamps too far in the
future. Replay capacity exhaustion also rejects traffic; it never evicts an
unexpired entry to accommodate new input.
