//! Frame discipline for the external-authorization socket.
//!
//! One request frame and one response frame per connection, each a
//! big-endian u32 length prefix followed by a JSON payload — the same
//! framing discipline as the Codex external reviewer. Framing reuses
//! [`ag_protocol::FrameCodec`]; this module only pins the deployment limits.

use std::io::{Read, Write};

use ag_protocol::{FrameCodec, ProtocolError};

/// Maximum request frame payload: 4 MiB.
pub const MAX_REQUEST_FRAME_BYTES: u32 = 4 * 1024 * 1024;
/// Maximum response frame payload: 64 KiB.
pub const MAX_RESPONSE_FRAME_BYTES: u32 = 64 * 1024;

/// The request-side codec.
///
/// # Panics
///
/// Never panics: the pinned request limit is a nonzero constant.
#[must_use]
pub fn request_codec() -> FrameCodec {
    FrameCodec::new(MAX_REQUEST_FRAME_BYTES).expect("the request frame limit is nonzero")
}

/// The response-side codec.
///
/// # Panics
///
/// Never panics: the pinned response limit is a nonzero constant.
#[must_use]
pub fn response_codec() -> FrameCodec {
    FrameCodec::new(MAX_RESPONSE_FRAME_BYTES).expect("the response frame limit is nonzero")
}

/// Reads exactly one bounded request frame.
///
/// # Errors
///
/// Returns a protocol error for an oversized declaration, truncation, or an
/// I/O failure; the caller must fail the connection closed.
pub fn read_request_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, ProtocolError> {
    request_codec().read_frame(reader)
}

/// Writes exactly one bounded response frame and flushes.
///
/// # Errors
///
/// Returns a protocol error when the payload exceeds the response limit or
/// the write fails; response payloads are far below the limit by
/// construction (reason strings are bounded by
/// [`crate::protocol::bounded_reason`]).
pub fn write_response_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), ProtocolError> {
    response_codec().write_frame(writer, payload)
}
