//! Stable principal-chain construction from verified signed RPC identities.

use ag_primitives::{AuthorityDomain, Epoch, PrincipalChainNodeV1, PrincipalChainV1, PrincipalId};
use thiserror::Error;

use crate::config::PeerPolicyV1;
use crate::rpc_auth::VerifiedRpcPrincipalV1;

/// Peer authentication errors.
#[derive(Debug, Error)]
pub enum PeerError {
    /// Signed principal/key do not match the configured enrollment.
    #[error("peer does not satisfy configured role {0}")]
    Policy(String),
    /// Stable identity construction failed.
    #[error("cannot construct peer identity: {0}")]
    Identity(String),
}

/// Reconstructs the configured principal chain from a verified Ed25519 peer.
///
/// The root comes from root-owned enrollment policy and the leaf is the exact
/// principal named by the enrolled signing key. Kernel UID/PID observations
/// never enter this stable lineage.
///
/// # Errors
///
/// Returns an error unless the signed principal/key matches policy and the
/// resulting root-to-leaf chain is structurally valid.
pub fn signed_principal_chain(
    peer: &VerifiedRpcPrincipalV1,
    policy: &PeerPolicyV1,
    authority_domain: AuthorityDomain,
    epoch: Epoch,
) -> Result<PrincipalChainV1, PeerError> {
    if peer.principal != policy.rpc_key.principal || peer.key_id != policy.rpc_key.key_id {
        return Err(PeerError::Policy(policy.role.clone()));
    }
    let root = PrincipalId::new(policy.stable_principal_root.clone());
    let leaf = PrincipalId::new(peer.principal.clone());
    let nodes = if root == leaf {
        vec![PrincipalChainNodeV1::root(root, policy.principal_kind)]
    } else {
        vec![
            PrincipalChainNodeV1::root(root.clone(), policy.principal_kind),
            PrincipalChainNodeV1::child(leaf, policy.principal_kind, root),
        ]
    };
    PrincipalChainV1::new(authority_domain, epoch, nodes)
        .map_err(|error| PeerError::Identity(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_auth::{RpcKeyIdV1, RpcPeerKeyPolicyV1, RpcPublicKeyV1};
    use ag_primitives::Digest;

    #[test]
    fn signed_chain_uses_configured_root_and_verified_leaf() {
        let root = Digest::hash_bytes(b"operator-enrollment-root");
        let leaf = Digest::hash_bytes(b"operator-signing-principal");
        let key_id = RpcKeyIdV1::new("operator-key-v1").expect("key id");
        let policy = PeerPolicyV1 {
            role: "operator_control".to_owned(),
            uid: 1000,
            gid: 1000,
            executable_identity: None,
            cgroup_contains: None,
            stable_principal_root: root.clone(),
            principal_kind: ag_primitives::PrincipalKindV1::Operator,
            rpc_key: RpcPeerKeyPolicyV1 {
                principal: leaf.clone(),
                key_id: key_id.clone(),
                public_key: RpcPublicKeyV1::from_base64url(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                )
                .expect("public key"),
                maximum_clock_skew_ms: 30_000,
            },
        };
        let peer = VerifiedRpcPrincipalV1 {
            principal: leaf.clone(),
            key_id,
        };
        let chain = signed_principal_chain(
            &peer,
            &policy,
            AuthorityDomain::parse("test-host").expect("domain"),
            Epoch::parse("1").expect("epoch"),
        )
        .expect("chain");
        assert_eq!(chain.root().principal_id.digest(), &root);
        assert_eq!(chain.leaf().principal_id.digest(), &leaf);

        let wrong_peer = VerifiedRpcPrincipalV1 {
            principal: Digest::hash_bytes(b"attacker"),
            key_id: peer.key_id,
        };
        assert!(
            signed_principal_chain(
                &wrong_peer,
                &policy,
                AuthorityDomain::parse("test-host").expect("domain"),
                Epoch::parse("1").expect("epoch"),
            )
            .is_err()
        );
    }
}
