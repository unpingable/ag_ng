//! Feature-gated live worker fixture.
//!
//! This executable is deliberately absent from default release builds and packaging. It
//! exercises the same descriptor-only bootstrap and candidate-only protocol a
//! generic worker uses, without adding a production command surface.

use std::error::Error;
use std::fs::OpenOptions;
use std::io::{self, Cursor};
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;

use ag_app::worker::{FIRST_WORKER_INPUT_DESCRIPTOR, receive_worker_activation};
use ag_app::worker_protocol::{
    CANDIDATE_BOOTSTRAP_PURPOSE, CANDIDATE_INGRESS_CREDENTIAL_PURPOSE, read_worker_bootstrap,
    write_signed_worker_candidate,
};

fn main() {
    if run().is_err() {
        let _ = std::fs::write("/work/fixture-error", b"fixture-refusal-v1");
        std::process::exit(1);
    }
}

struct FixturePlanV1 {
    candidate: Vec<u8>,
    semantic_override: Option<String>,
    delay_before_emit: Option<Duration>,
}

fn parse_fixed_plan(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<FixturePlanV1, Box<dyn Error>> {
    let mode = arguments
        .next()
        .ok_or("fixture worker requires one fixed mode")?;
    let plan = match mode.as_str() {
        "--emit" => FixturePlanV1 {
            candidate: arguments
                .next()
                .ok_or("fixture worker requires one fixed candidate argument")?
                .into_bytes(),
            semantic_override: None,
            delay_before_emit: None,
        },
        "--emit-base64" => {
            let encoded = arguments
                .next()
                .ok_or("fixture worker requires one fixed base64 candidate argument")?;
            let candidate = base64::engine::general_purpose::STANDARD.decode(&encoded)?;
            if candidate.is_empty()
                || base64::engine::general_purpose::STANDARD.encode(&candidate) != encoded
            {
                return Err("fixture worker candidate was not canonical padded base64".into());
            }
            FixturePlanV1 {
                candidate,
                semantic_override: None,
                delay_before_emit: None,
            }
        }
        "--emit-semantic" => FixturePlanV1 {
            semantic_override: Some(
                arguments
                    .next()
                    .ok_or("fixture worker requires one fixed semantic type")?,
            ),
            candidate: arguments
                .next()
                .ok_or("fixture worker requires one fixed candidate argument")?
                .into_bytes(),
            delay_before_emit: None,
        },
        "--sleep-then-emit" => {
            let delay_ms = arguments
                .next()
                .ok_or("fixture worker requires one fixed delay")?
                .parse::<u64>()?;
            if delay_ms == 0 || delay_ms > 5_000 {
                return Err("fixture worker delay is outside the test bound".into());
            }
            FixturePlanV1 {
                candidate: arguments
                    .next()
                    .ok_or("fixture worker requires one fixed candidate argument")?
                    .into_bytes(),
                semantic_override: None,
                delay_before_emit: Some(Duration::from_millis(delay_ms)),
            }
        }
        "--probe-governed-target" => {
            let target = PathBuf::from(
                arguments
                    .next()
                    .ok_or("fixture worker requires one governed target probe")?,
            );
            if target.exists() || OpenOptions::new().write(true).open(&target).is_ok() {
                return Err("governed target was visible or writable to fixture worker".into());
            }
            if arguments.next().as_deref() != Some("--emit") {
                return Err("fixture worker target probe requires fixed --emit mode".into());
            }
            FixturePlanV1 {
                candidate: arguments
                    .next()
                    .ok_or("fixture worker requires one fixed candidate argument")?
                    .into_bytes(),
                semantic_override: None,
                delay_before_emit: None,
            }
        }
        _ => return Err("fixture worker received an unknown fixed mode".into()),
    };
    if arguments.next().is_some() {
        return Err("fixture worker received unexpected arguments".into());
    }
    Ok(plan)
}

fn run() -> Result<(), Box<dyn Error>> {
    let environment = std::env::vars_os().collect::<Vec<_>>();
    let expected_environment = [("PWD".into(), "/work".into())];
    if environment.as_slice() != expected_environment {
        return Err("fixture worker environment was not exactly sanitized".into());
    }

    let mut arguments = std::env::args();
    let _argv_zero = arguments
        .next()
        .ok_or("fixture worker did not receive argv zero")?;
    let FixturePlanV1 {
        candidate,
        semantic_override,
        delay_before_emit,
    } = parse_fixed_plan(&mut arguments)?;

    let mut credential = None;
    let mut bootstrap_frame = None;
    for input in receive_worker_activation()? {
        match (input.descriptor, input.purpose.as_str()) {
            (FIRST_WORKER_INPUT_DESCRIPTOR, CANDIDATE_INGRESS_CREDENTIAL_PURPOSE)
                if credential.is_none() =>
            {
                credential = Some(input.read_to_end()?);
            }
            (descriptor, CANDIDATE_BOOTSTRAP_PURPOSE)
                if descriptor == FIRST_WORKER_INPUT_DESCRIPTOR + 1 && bootstrap_frame.is_none() =>
            {
                bootstrap_frame = Some(input.read_to_end()?);
            }
            _ => return Err("fixture worker activation manifest was not exact".into()),
        }
    }

    let mut credential = Cursor::new(credential.ok_or("missing candidate ingress credential")?);
    let bootstrap_frame = bootstrap_frame.ok_or("missing public candidate bootstrap")?;
    let mut bootstrap = read_worker_bootstrap(&mut bootstrap_frame.as_slice())?;
    if let Some(semantic) = semantic_override {
        bootstrap.semantic_type = semantic;
    }
    if let Some(delay) = delay_before_emit {
        std::thread::sleep(delay);
    }
    let stdout = io::stdout();
    let mut output = stdout.lock();
    write_signed_worker_candidate(&mut credential, &bootstrap, candidate, &mut output)?;
    Ok(())
}
