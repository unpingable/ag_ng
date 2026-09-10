//! Strict signed client and offline transaction builder for `ag-providerd`.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::path::PathBuf;

use ag_app::api::{ApiResultV1, OpaqueBytesV1, ProviderRequestV1, ProviderResponseV1};
use ag_app::config::{
    AgctlDaemonPeerV1, AgctlLimitsV1, AgctlSocketPeerCheckV1, ProviderdConfigV1, load_config,
};
use ag_app::rpc_auth::{
    RpcPeerEnrollmentV1, RpcReplayGuardV1, RpcSignerV1, RpcSigningIdentityConfigV1,
    SystemRpcClockV1,
};
use ag_app::signed_transport::{SocketPeerCheckV1, call_signed_with_timeout};
use ag_primitives::{
    AuthorityDomain, Digest, Epoch, InferenceBudgetV1, InferenceCapabilityId,
    InferenceCapabilityV1, InferenceEnvelopeV1, InferenceMethodId, LifecycleNonce, ModelId,
    PrincipalId, PrincipalKindV1, ProjectId, ProviderEndpointId, SessionId,
};
use ag_protocol::{RequestId, canonical_json, strict_json_from_slice};
use ag_session::ProviderRequestCustodyV1;
use anyhow::{Context as _, bail};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Operation {
    Call,
    Prepare,
    Execute,
}

#[derive(Debug, Parser)]
#[command(
    name = "ag-providerctl",
    version,
    about = "Authenticated crash-safe client for ag-providerd"
)]
struct Arguments {
    /// Root-custodied service identity, enrollment, and provider policy reference.
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    /// Validate configuration without loading a credential or connecting.
    #[arg(long)]
    check_config: bool,
    /// Strict operation; `call` sends a raw ProviderRequestV1.
    #[arg(value_enum, default_value = "call")]
    operation: Operation,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderctlConfigV1 {
    schema: String,
    rpc_signing_identity: RpcSigningIdentityConfigV1,
    providerd_socket: PathBuf,
    providerd_peer: AgctlDaemonPeerV1,
    providerd_policy_config: PathBuf,
    limits: AgctlLimitsV1,
}

impl ProviderctlConfigV1 {
    fn validate(&self) -> anyhow::Result<ProviderdConfigV1> {
        if self.schema != "ag.config.providerctl.v1" {
            bail!("unsupported providerctl configuration schema");
        }
        for path in [&self.providerd_socket, &self.providerd_policy_config] {
            if !path.is_absolute() || path.components().collect::<PathBuf>() != *path {
                bail!("providerctl paths must be absolute and normalized");
            }
        }
        self.rpc_signing_identity
            .validate()
            .context("invalid providerctl signing identity")?;
        self.providerd_peer
            .rpc_key
            .validate()
            .context("invalid providerd peer enrollment")?;
        if self.rpc_signing_identity.principal == self.providerd_peer.rpc_key.principal
            || self.rpc_signing_identity.public_key == self.providerd_peer.rpc_key.public_key
            || self.limits.max_control_frame_bytes < 4096
            || self.limits.rpc_replay_capacity < 2
        {
            bail!("providerctl roles or limits are unsafe");
        }
        let policy: ProviderdConfigV1 = load_config(&self.providerd_policy_config, true)
            .context("cannot load providerd policy config")?;
        policy
            .validate()
            .context("invalid providerd policy config")?;
        if policy.caller_peer.principal_kind != PrincipalKindV1::Service
            || policy.caller_peer.rpc_key.principal != self.rpc_signing_identity.principal
            || policy.socket != self.providerd_socket
            || policy.rpc_signing_identity.principal != self.providerd_peer.rpc_key.principal
            || policy.rpc_signing_identity.public_key != self.providerd_peer.rpc_key.public_key
        {
            bail!("providerctl identity or socket does not match providerd policy");
        }
        Ok(policy)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrepareInferenceV1 {
    schema: String,
    project: String,
    session: String,
    session_nonce: String,
    capability_nonce: String,
    not_before_unix_ms: u64,
    expires_at_unix_ms: u64,
    endpoint: String,
    model: String,
    method: String,
    #[serde(default)]
    sanitized_headers: BTreeMap<String, String>,
    request_bytes: OpaqueBytesV1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderTransactionV1 {
    schema: String,
    capability: InferenceCapabilityV1,
    request: ProviderRequestCustodyV1,
    request_bytes: OpaqueBytesV1,
    dispatch: Digest,
}

fn socket_check(peer: &AgctlDaemonPeerV1) -> SocketPeerCheckV1 {
    match peer.socket_peer {
        AgctlSocketPeerCheckV1::ObserveOnly => SocketPeerCheckV1::ObserveOnly,
        AgctlSocketPeerCheckV1::RequireUidGid { uid, gid } => {
            SocketPeerCheckV1::RequireUidGid { uid, gid }
        }
    }
}

fn read_stdin<T: DeserializeOwned + Serialize>(maximum: u32) -> anyhow::Result<T> {
    let maximum = usize::try_from(maximum)?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(u64::try_from(maximum)?.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        bail!("provider request exceeds the configured frame bound");
    }
    strict_json_from_slice(&bytes).context("invalid strict provider request")
}

fn policy_digest(policy: &ProviderdConfigV1) -> anyhow::Result<Digest> {
    let mut endpoints = BTreeMap::new();
    for endpoint in &policy.endpoints {
        if endpoints.insert(endpoint.id.clone(), endpoint).is_some() {
            bail!("duplicate endpoint in providerd policy");
        }
    }
    Ok(Digest::from_serializable(&endpoints)?)
}

fn prepare(
    config: &ProviderctlConfigV1,
    policy: &ProviderdConfigV1,
    input: PrepareInferenceV1,
) -> anyhow::Result<ProviderTransactionV1> {
    if input.schema != "ag.providerctl.prepare-inference/v1" {
        bail!("unsupported prepare-inference schema");
    }
    let endpoint = policy
        .endpoints
        .iter()
        .find(|candidate| candidate.id == input.endpoint)
        .context("endpoint is not in providerd policy")?;
    let model_policy = endpoint
        .models
        .iter()
        .find(|candidate| candidate.id == input.model)
        .context("model is not in providerd policy")?;
    if !endpoint
        .methods
        .iter()
        .any(|method| method == &input.method)
    {
        bail!("method is not in providerd policy");
    }
    let envelope = InferenceEnvelopeV1 {
        endpoint: ProviderEndpointId::new(input.endpoint)?,
        model: ModelId::new(input.model)?,
        method: InferenceMethodId::new(input.method)?,
        protocol_digest: Digest::hash_bytes(endpoint.protocol.as_bytes()),
    };
    let capability = InferenceCapabilityV1::new(
        AuthorityDomain::parse(&policy.authority_domain)?,
        Epoch::parse(&policy.epoch)?,
        ProjectId::new(input.project)?,
        SessionId::new(input.session)?,
        LifecycleNonce::parse(&input.session_nonce)?,
        PrincipalId::new(config.rpc_signing_identity.principal.clone()),
        policy_digest(policy)?,
        envelope.clone(),
        InferenceBudgetV1 {
            requests: 1,
            input_bytes: input.request_bytes.len() as u64,
            output_bytes: model_policy.max_event_stream_bytes,
            cost_microunits: model_policy.worst_case_cost_microunits,
        },
        input.not_before_unix_ms,
        input.expires_at_unix_ms,
        LifecycleNonce::parse(&input.capability_nonce)?,
    )?;
    let capability_id = capability.id();
    let exact_request = Digest::hash_bytes(input.request_bytes.as_slice());
    #[derive(Serialize)]
    struct CustodyBinding<'a> {
        capability_id: &'a InferenceCapabilityId,
        exact_request: &'a Digest,
        sanitized_headers: &'a BTreeMap<String, String>,
        envelope: &'a InferenceEnvelopeV1,
    }
    let custody_record = Digest::from_serializable(&CustodyBinding {
        capability_id: &capability_id,
        exact_request: &exact_request,
        sanitized_headers: &input.sanitized_headers,
        envelope: &envelope,
    })?;
    let request = ProviderRequestCustodyV1 {
        capability_id: capability_id.clone(),
        exact_request,
        sanitized_headers: input.sanitized_headers,
        envelope,
        custody_record: custody_record.clone(),
    };
    let dispatch = Digest::from_serializable(&(
        "ag.provider.dispatch-id/v1",
        AuthorityDomain::parse(&policy.authority_domain)?,
        Epoch::parse(&policy.epoch)?,
        capability_id,
        custody_record,
    ))?;
    Ok(ProviderTransactionV1 {
        schema: "ag.providerctl.transaction/v1".to_owned(),
        capability,
        request,
        request_bytes: input.request_bytes,
        dispatch,
    })
}

struct SignedClient<'a> {
    config: &'a ProviderctlConfigV1,
    signer: RpcSignerV1,
    peer: RpcPeerEnrollmentV1,
    replay: RpcReplayGuardV1,
}

impl<'a> SignedClient<'a> {
    fn new(config: &'a ProviderctlConfigV1) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            signer: RpcSignerV1::from_systemd_credential(&config.rpc_signing_identity)?,
            peer: RpcPeerEnrollmentV1::new(
                config.providerd_peer.rpc_key.principal.clone(),
                config.providerd_peer.rpc_key.clone(),
            )?,
            replay: RpcReplayGuardV1::new(config.limits.rpc_replay_capacity as usize)?,
        })
    }

    fn call(
        &mut self,
        request: ProviderRequestV1,
    ) -> anyhow::Result<ApiResultV1<ProviderResponseV1>> {
        call_signed_with_timeout(
            &self.config.providerd_socket,
            RequestId::new(format!("providerctl-{}", uuid::Uuid::new_v4()))?,
            request,
            self.config.limits.max_control_frame_bytes,
            &self.signer,
            &self.peer,
            &self.replay,
            &SystemRpcClockV1,
            socket_check(&self.config.providerd_peer),
            std::time::Duration::from_millis(self.policy_deadline()?.saturating_add(10_000)),
        )
        .context("authenticated ag-providerd RPC failed")
    }

    fn policy_deadline(&self) -> anyhow::Result<u64> {
        let policy: ProviderdConfigV1 = load_config(&self.config.providerd_policy_config, true)?;
        Ok(policy.limits.provider_deadline_ms)
    }
}

fn validate_transaction(transaction: &ProviderTransactionV1) -> anyhow::Result<()> {
    let expected_dispatch = Digest::from_serializable(&(
        "ag.provider.dispatch-id/v1",
        &transaction.capability.authority_domain,
        transaction.capability.epoch,
        transaction.capability.id(),
        &transaction.request.custody_record,
    ))?;
    if transaction.schema != "ag.providerctl.transaction/v1"
        || transaction.request.capability_id != transaction.capability.id()
        || transaction.request.exact_request
            != Digest::hash_bytes(transaction.request_bytes.as_slice())
        || transaction.dispatch != expected_dispatch
    {
        bail!("provider transaction binding is invalid");
    }
    transaction.request.verify()?;
    Ok(())
}

fn execute(
    client: &mut SignedClient<'_>,
    transaction: ProviderTransactionV1,
) -> anyhow::Result<ApiResultV1<ProviderResponseV1>> {
    validate_transaction(&transaction)?;
    let registered = client.call(ProviderRequestV1::RegisterCapability {
        worker_principal: transaction.capability.worker_principal.clone(),
        capability: Box::new(transaction.capability.clone()),
    })?;
    if !matches!(
        registered,
        ApiResultV1::Ok {
            response: ProviderResponseV1::CapabilityRegistered { .. }
        }
    ) {
        return Ok(registered);
    }
    client.call(ProviderRequestV1::Infer {
        capability: Box::new(transaction.capability),
        request: Box::new(transaction.request),
        request_bytes: transaction.request_bytes,
    })
}

fn write_result<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&canonical_json(value)?)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let config: ProviderctlConfigV1 = load_config(&arguments.config, true)?;
    let policy = config.validate()?;
    if arguments.check_config {
        return Ok(());
    }
    match arguments.operation {
        Operation::Prepare => write_result(&prepare(
            &config,
            &policy,
            read_stdin(config.limits.max_control_frame_bytes)?,
        )?),
        Operation::Call => {
            let mut client = SignedClient::new(&config)?;
            write_result(&client.call(read_stdin(config.limits.max_control_frame_bytes)?)?)
        }
        Operation::Execute => {
            let transaction = read_stdin(config.limits.max_control_frame_bytes)?;
            let mut client = SignedClient::new(&config)?;
            write_result(&execute(&mut client, transaction)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_config() -> ProviderctlConfigV1 {
        toml::from_str(
            r#"
schema = "ag.config.providerctl.v1"
providerd_socket = "/run/agent-governor/providerd/provider.sock"
providerd_policy_config = "/etc/agent-governor/providerd.toml"

[rpc_signing_identity]
principal = "sha256:6111111111111111111111111111111111111111111111111111111111111111"
key_id = "agd.v1"
public_key = "ptVL7WK6le_cWbyxf76wk7-gkyAE8dO2_Xt2JfmnfSg"
private_key_credential = "/run/credentials/marginalia-generation-worker/rpc.pk8"

[providerd_peer.rpc_key]
principal = "sha256:c111111111111111111111111111111111111111111111111111111111111111"
key_id = "providerd.v1"
public_key = "Wt87MtR1fgf8L7BTeSAEkSps5V8ka2JdFbRxzFC-x6w"
maximum_clock_skew_ms = 30000

[providerd_peer.socket_peer]
mode = "observe_only"

[limits]
max_control_frame_bytes = 94371840
rpc_replay_capacity = 4096
"#,
        )
        .unwrap()
    }

    fn policy() -> ProviderdConfigV1 {
        let mut policy: ProviderdConfigV1 =
            toml::from_str(include_str!("../../../../config/providerd.example.toml")).unwrap();
        policy.caller_peer.principal_kind = PrincipalKindV1::Service;
        policy
    }

    fn input() -> PrepareInferenceV1 {
        PrepareInferenceV1 {
            schema: "ag.providerctl.prepare-inference/v1".to_owned(),
            project: "marginalia-project".to_owned(),
            session: "marginalia-session".to_owned(),
            session_nonce: "11111111111111111111111111111111".to_owned(),
            capability_nonce: "22222222222222222222222222222222".to_owned(),
            not_before_unix_ms: 1,
            expires_at_unix_ms: 9_000_000_000_000,
            endpoint: "primary".to_owned(),
            model: "production-model".to_owned(),
            method: "responses.create".to_owned(),
            sanitized_headers: BTreeMap::from([(
                "content-type".to_owned(),
                "application/json".to_owned(),
            )]),
            request_bytes: OpaqueBytesV1::new(
                br#"{"model":"production-model","messages":[]}"#.to_vec(),
            ),
        }
    }

    #[test]
    fn prepare_is_deterministic_and_binds_every_provider_selection() {
        let config = client_config();
        let policy = policy();
        let first = prepare(&config, &policy, input()).unwrap();
        let second = prepare(&config, &policy, input()).unwrap();
        assert_eq!(first.dispatch, second.dispatch);
        first.request.verify().unwrap();

        let mut changed = input();
        changed.capability_nonce = "33333333333333333333333333333333".to_owned();
        assert_ne!(
            first.dispatch,
            prepare(&config, &policy, changed).unwrap().dispatch
        );
    }

    #[test]
    fn execute_rejects_a_substituted_precomputed_dispatch_before_rpc() {
        let config = client_config();
        let mut transaction = prepare(&config, &policy(), input()).unwrap();
        transaction.dispatch = Digest::hash_bytes(b"substituted");
        assert!(validate_transaction(&transaction).is_err());
    }
}
