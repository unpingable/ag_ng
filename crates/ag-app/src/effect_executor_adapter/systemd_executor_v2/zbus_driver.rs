//! Linux system-bus transport for the machine-bound V2 executor.

use std::future::Future;
use std::time::{Duration, Instant};

use async_io::Timer;
use futures_util::future::{select, Either};
use futures_util::pin_mut;
use futures_util::StreamExt as _;
use zbus::zvariant::OwnedObjectPath;
use zbus::{Connection, Message, Proxy};

use super::{
    wall_clock_ms, DriverMessageV2, DriverObservationV2, DriverTerminalV2,
    EffectExecutorSystemdPlanV2, MAX_CUMULATIVE_MESSAGE_BYTES, MAX_MESSAGES, MAX_MESSAGE_BYTES,
};

const SYSTEMD_SERVICE: &str = "org.freedesktop.systemd1";
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
const PEER_INTERFACE: &str = "org.freedesktop.DBus.Peer";

pub(super) struct ZbusSystemdDriverV2;

impl super::SystemdOperationDriverV2 for ZbusSystemdDriverV2 {
    fn run(&self, plan: &EffectExecutorSystemdPlanV2) -> DriverObservationV2 {
        async_io::block_on(run(plan))
    }
}

struct Transcript {
    wall_started: u64,
    monotonic_started: Instant,
    messages: Vec<DriverMessageV2>,
    cumulative_bytes: usize,
    live_machine_identity: Option<String>,
    unit_object_path: Option<String>,
    previous_active_state: Option<String>,
    previous_unit_file_state: Option<String>,
    job_path: Option<String>,
    job_result: Option<String>,
}

impl Transcript {
    fn new() -> Self {
        Self {
            wall_started: wall_clock_ms(),
            monotonic_started: Instant::now(),
            messages: Vec::new(),
            cumulative_bytes: 0,
            live_machine_identity: None,
            unit_object_path: None,
            previous_active_state: None,
            previous_unit_file_state: None,
            job_path: None,
            job_result: None,
        }
    }

    fn elapsed_ms(&self) -> u64 {
        self.monotonic_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    fn record(&mut self, kind: &str, message: &Message) -> Result<(), &'static str> {
        let bytes = message.data().bytes();
        let cumulative = self
            .cumulative_bytes
            .checked_add(bytes.len())
            .ok_or("dbus_evidence_size_overflow")?;
        if self.messages.len() >= MAX_MESSAGES {
            return Err("dbus_evidence_message_count");
        }
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err("dbus_evidence_message_too_large");
        }
        if cumulative > MAX_CUMULATIVE_MESSAGE_BYTES {
            return Err("dbus_evidence_cumulative_too_large");
        }
        self.messages.push(DriverMessageV2 {
            kind: kind.to_owned(),
            elapsed_ms: self.elapsed_ms(),
            bytes: bytes.to_vec(),
        });
        self.cumulative_bytes = cumulative;
        Ok(())
    }

    fn finish(
        self,
        terminal: DriverTerminalV2,
        resulting_active_state: Option<String>,
        resulting_unit_file_state: Option<String>,
    ) -> DriverObservationV2 {
        let elapsed_ms = self.elapsed_ms();
        DriverObservationV2 {
            started_at_unix_ms: self.wall_started,
            finished_at_unix_ms: wall_clock_ms().max(self.wall_started),
            elapsed_ms,
            live_machine_identity: self.live_machine_identity,
            unit_object_path: self.unit_object_path,
            previous_active_state: self.previous_active_state,
            previous_unit_file_state: self.previous_unit_file_state,
            job_path: self.job_path,
            job_result: self.job_result,
            messages: self.messages,
            terminal: match terminal {
                DriverTerminalV2::Success { .. } => DriverTerminalV2::Success {
                    resulting_active_state: resulting_active_state.unwrap_or_default(),
                    resulting_unit_file_state: resulting_unit_file_state.unwrap_or_default(),
                },
                other => other,
            },
        }
    }

    fn failure(self, code: &str, detail: &str) -> DriverObservationV2 {
        self.finish(
            DriverTerminalV2::Failure {
                code: code.to_owned(),
                detail: detail.to_owned(),
            },
            None,
            None,
        )
    }

    fn indeterminate(self, code: &str, detail: &str) -> DriverObservationV2 {
        self.finish(
            DriverTerminalV2::Indeterminate {
                code: code.to_owned(),
                detail: detail.to_owned(),
            },
            None,
            None,
        )
    }
}

async fn within<T>(duration: Duration, future: impl Future<Output = T>) -> Option<T> {
    let timer = Timer::after(duration);
    pin_mut!(future);
    pin_mut!(timer);
    match select(future, timer).await {
        Either::Left((value, _)) => Some(value),
        Either::Right(_) => None,
    }
}

async fn until<T>(deadline: Instant, future: impl Future<Output = T>) -> Option<T> {
    within(deadline.saturating_duration_since(Instant::now()), future).await
}

#[allow(
    clippy::manual_let_else,
    clippy::too_many_lines,
    reason = "the ordered D-Bus uncertainty cuts stay visible in one protocol"
)]
async fn run(plan: &EffectExecutorSystemdPlanV2) -> DriverObservationV2 {
    let mut transcript = Transcript::new();
    let preflight_timeout = Duration::from_millis(plan.job_timeout_ms);

    let Some(connection) = within(preflight_timeout, Connection::system()).await else {
        return transcript.failure(
            "system_bus_connection_timeout",
            "system bus connection did not complete before the plan bound",
        );
    };
    let connection = match connection {
        Ok(connection) => connection,
        Err(_) => {
            return transcript.failure(
                "system_bus_unavailable",
                "system bus connection was unavailable before StartUnit",
            );
        }
    };

    let peer = match Proxy::new(&connection, SYSTEMD_SERVICE, MANAGER_PATH, PEER_INTERFACE).await {
        Ok(proxy) => proxy,
        Err(_) => {
            return transcript.failure(
                "systemd_peer_proxy_unavailable",
                "systemd peer interface was unavailable before StartUnit",
            );
        }
    };
    let Some(machine_reply) =
        within(preflight_timeout, peer.call_method("GetMachineId", &())).await
    else {
        return transcript.failure(
            "systemd_machine_identity_timeout",
            "systemd machine identity was not returned before StartUnit",
        );
    };
    let machine_reply = match machine_reply {
        Ok(message) => message,
        Err(_) => {
            return transcript.failure(
                "systemd_machine_identity_unavailable",
                "systemd machine identity was unavailable before StartUnit",
            );
        }
    };
    if let Err(code) = transcript.record("get_machine_id_reply", &machine_reply) {
        return transcript.failure(code, "machine identity reply exceeded evidence bounds");
    }
    let live_machine_identity: String = match machine_reply.body().deserialize() {
        Ok(value) => value,
        Err(_) => {
            return transcript.failure(
                "systemd_machine_identity_malformed",
                "systemd machine identity reply was malformed",
            );
        }
    };
    transcript.live_machine_identity = Some(live_machine_identity.clone());
    if live_machine_identity != plan.systemd_machine_identity {
        return transcript.failure(
            "systemd_machine_identity_mismatch",
            "live systemd machine identity differs from the sealed plan",
        );
    }

    let manager = match Proxy::new(
        &connection,
        SYSTEMD_SERVICE,
        MANAGER_PATH,
        MANAGER_INTERFACE,
    )
    .await
    {
        Ok(proxy) => proxy,
        Err(_) => {
            return transcript.failure(
                "systemd_manager_proxy_unavailable",
                "systemd manager interface was unavailable before StartUnit",
            );
        }
    };

    let unit = match &plan.effect {
        ag_effect::CanonicalEffectV1::SystemdUnit { unit, .. } => unit,
        _ => {
            return transcript.failure(
                "systemd_effect_family",
                "V2 plan did not contain one SystemdUnit effect",
            );
        }
    };

    let Some(unit_reply) =
        within(preflight_timeout, manager.call_method("GetUnit", &(unit,))).await
    else {
        return transcript.failure(
            "systemd_unit_lookup_timeout",
            "unit lookup did not complete before StartUnit",
        );
    };
    let unit_reply = match unit_reply {
        Ok(message) => message,
        Err(_) => {
            return transcript.failure(
                "systemd_unit_lookup_failed",
                "unit lookup failed before StartUnit",
            );
        }
    };
    if let Err(code) = transcript.record("get_unit_reply", &unit_reply) {
        return transcript.failure(code, "unit lookup reply exceeded evidence bounds");
    }
    let unit_path: OwnedObjectPath = match unit_reply.body().deserialize() {
        Ok(value) => value,
        Err(_) => {
            return transcript.failure(
                "systemd_unit_lookup_malformed",
                "unit lookup reply was malformed",
            );
        }
    };
    transcript.unit_object_path = Some(unit_path.to_string());

    let active = match get_string_property(
        &connection,
        unit_path.as_str(),
        "ActiveState",
        preflight_timeout,
        &mut transcript,
        "pre_active_state_reply",
    )
    .await
    {
        Ok(value) => value,
        Err((code, detail)) => return transcript.failure(code, detail),
    };
    transcript.previous_active_state = Some(active.clone());

    let unit_file = match manager_string_call(
        &manager,
        "GetUnitFileState",
        &(unit,),
        preflight_timeout,
        &mut transcript,
        "pre_unit_file_state_reply",
    )
    .await
    {
        Ok(value) => value,
        Err((code, detail)) => return transcript.failure(code, detail),
    };
    transcript.previous_unit_file_state = Some(unit_file.clone());

    let (expected_active, expected_file) = match &plan.effect {
        ag_effect::CanonicalEffectV1::SystemdUnit {
            expected_active_state,
            expected_unit_file_state,
            ..
        } => (expected_active_state, expected_unit_file_state),
        _ => unreachable!(),
    };
    if &active != expected_active || &unit_file != expected_file {
        return transcript.failure(
            "systemd_prestate_mismatch",
            "live unit prestate differs from the sealed effect",
        );
    }

    let mut job_signals = match manager.receive_signal("JobRemoved").await {
        Ok(stream) => stream,
        Err(_) => {
            return transcript.failure(
                "systemd_job_subscription_failed",
                "JobRemoved subscription failed before StartUnit",
            );
        }
    };

    let job_deadline = Instant::now() + Duration::from_millis(plan.job_timeout_ms);
    let Some(start_reply) = until(
        job_deadline,
        manager.call_method("StartUnit", &(unit, "replace")),
    )
    .await
    else {
        return transcript.indeterminate(
            "systemd_start_reply_timeout",
            "StartUnit transmission began but no reply arrived before the job deadline",
        );
    };
    let start_reply = match start_reply {
        Ok(message) => message,
        Err(_) => {
            return transcript.indeterminate(
                "systemd_start_method_error",
                "StartUnit returned a manager error after transmission began",
            );
        }
    };
    if let Err(code) = transcript.record("start_unit_reply", &start_reply) {
        return transcript.indeterminate(code, "StartUnit reply exceeded evidence bounds");
    }
    let job_path: OwnedObjectPath = match start_reply.body().deserialize() {
        Ok(value) => value,
        Err(_) => {
            return transcript.indeterminate(
                "systemd_start_reply_malformed",
                "StartUnit reply did not contain one job path",
            );
        }
    };
    transcript.job_path = Some(job_path.to_string());

    loop {
        let Some(next) = until(job_deadline, job_signals.next()).await else {
            return transcript.indeterminate(
                "systemd_job_timeout",
                "matching JobRemoved testimony was absent at the job deadline",
            );
        };
        let Some(next) = next else {
            return transcript.indeterminate(
                "systemd_job_stream_ended",
                "JobRemoved subscription ended before the matching job result",
            );
        };
        let message = next;
        if let Err(code) = transcript.record("job_removed_signal", &message) {
            return transcript.indeterminate(code, "JobRemoved evidence exceeded bounds");
        }
        let parsed: (u32, OwnedObjectPath, String, String) = match message.body().deserialize() {
            Ok(value) => value,
            Err(_) => {
                return transcript.indeterminate(
                    "systemd_job_signal_malformed",
                    "JobRemoved testimony was malformed",
                );
            }
        };
        if parsed.1 != job_path {
            continue;
        }
        if parsed.2 != *unit {
            return transcript.indeterminate(
                "systemd_job_unit_mismatch",
                "matching job path named another unit",
            );
        }
        transcript.job_result = Some(parsed.3.clone());
        if parsed.3 != "done" {
            return transcript.indeterminate(
                "systemd_job_result_not_done",
                "matching systemd job did not report done",
            );
        }
        break;
    }

    let active = match get_string_property_until(
        &connection,
        unit_path.as_str(),
        "ActiveState",
        job_deadline,
        &mut transcript,
        "post_active_state_reply",
    )
    .await
    {
        Ok(value) => value,
        Err((code, detail)) => return transcript.indeterminate(code, detail),
    };
    let unit_file = match manager_string_call_until(
        &manager,
        "GetUnitFileState",
        &(unit,),
        job_deadline,
        &mut transcript,
        "post_unit_file_state_reply",
    )
    .await
    {
        Ok(value) => value,
        Err((code, detail)) => return transcript.indeterminate(code, detail),
    };

    transcript.finish(
        DriverTerminalV2::Success {
            resulting_active_state: active.clone(),
            resulting_unit_file_state: unit_file.clone(),
        },
        Some(active),
        Some(unit_file),
    )
}

async fn get_string_property(
    connection: &Connection,
    path: &str,
    property: &str,
    timeout: Duration,
    transcript: &mut Transcript,
    label: &str,
) -> Result<String, (&'static str, &'static str)> {
    let Some(reply) = within(
        timeout,
        connection.call_method(
            Some(SYSTEMD_SERVICE),
            path,
            Some(PROPERTIES_INTERFACE),
            "Get",
            &(UNIT_INTERFACE, property),
        ),
    )
    .await
    else {
        return Err((
            "systemd_property_timeout",
            "unit property read timed out before StartUnit",
        ));
    };
    decode_property_reply(reply, transcript, label)
}

async fn get_string_property_until(
    connection: &Connection,
    path: &str,
    property: &str,
    deadline: Instant,
    transcript: &mut Transcript,
    label: &str,
) -> Result<String, (&'static str, &'static str)> {
    let Some(reply) = until(
        deadline,
        connection.call_method(
            Some(SYSTEMD_SERVICE),
            path,
            Some(PROPERTIES_INTERFACE),
            "Get",
            &(UNIT_INTERFACE, property),
        ),
    )
    .await
    else {
        return Err((
            "systemd_poststate_timeout",
            "unit poststate read exceeded the job deadline",
        ));
    };
    decode_property_reply(reply, transcript, label)
}

fn decode_property_reply(
    reply: zbus::Result<Message>,
    transcript: &mut Transcript,
    label: &str,
) -> Result<String, (&'static str, &'static str)> {
    let message = reply.map_err(|_| {
        (
            "systemd_property_failed",
            "unit property read failed at the system bus",
        )
    })?;
    transcript.record(label, &message).map_err(|_| {
        (
            "dbus_evidence_message_bound",
            "unit property reply exceeded evidence bounds",
        )
    })?;
    let value: zbus::zvariant::OwnedValue = message.body().deserialize().map_err(|_| {
        (
            "systemd_property_malformed",
            "unit property reply was malformed",
        )
    })?;
    String::try_from(value).map_err(|_| {
        (
            "systemd_property_not_string",
            "unit property reply was not a string",
        )
    })
}

async fn manager_string_call<B>(
    manager: &Proxy<'_>,
    method: &str,
    body: &B,
    timeout: Duration,
    transcript: &mut Transcript,
    label: &str,
) -> Result<String, (&'static str, &'static str)>
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
{
    let Some(reply) = within(timeout, manager.call_method(method, body)).await else {
        return Err((
            "systemd_manager_call_timeout",
            "manager property call timed out before StartUnit",
        ));
    };
    decode_string_reply(reply, transcript, label)
}

async fn manager_string_call_until<B>(
    manager: &Proxy<'_>,
    method: &str,
    body: &B,
    deadline: Instant,
    transcript: &mut Transcript,
    label: &str,
) -> Result<String, (&'static str, &'static str)>
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
{
    let Some(reply) = until(deadline, manager.call_method(method, body)).await else {
        return Err((
            "systemd_poststate_timeout",
            "manager poststate read exceeded the job deadline",
        ));
    };
    decode_string_reply(reply, transcript, label)
}

fn decode_string_reply(
    reply: zbus::Result<Message>,
    transcript: &mut Transcript,
    label: &str,
) -> Result<String, (&'static str, &'static str)> {
    let message = reply.map_err(|_| {
        (
            "systemd_manager_call_failed",
            "manager property call failed at the system bus",
        )
    })?;
    transcript.record(label, &message).map_err(|_| {
        (
            "dbus_evidence_message_bound",
            "manager reply exceeded evidence bounds",
        )
    })?;
    message.body().deserialize().map_err(|_| {
        (
            "systemd_manager_reply_malformed",
            "manager reply was malformed",
        )
    })
}
