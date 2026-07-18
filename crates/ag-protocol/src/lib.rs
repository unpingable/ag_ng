//! Strict, bounded, canonical protocol building blocks.
//!
//! The protocol crate deliberately does not provide a permissive JSON mode.
//! Every decoder rejects duplicate object keys, ignored/unknown fields,
//! trailing JSON, malformed UTF-8, and frames larger than the configured
//! bound. Values are encoded using RFC 8785 JSON Canonicalization Scheme
//! (JCS) bytes before they are framed or hashed.

use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt;
use std::io::{self, Read, Write};
use std::rc::Rc;

pub use ag_primitives::Digest;
use ag_primitives::JcsDocument;
use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Number, Value};
use thiserror::Error;

/// Current wire protocol version.
pub const CURRENT_PROTOCOL_VERSION: &str = "ag-local/v1";

/// Conservative default maximum frame size (one mebibyte).
pub const DEFAULT_MAX_FRAME_LEN: u32 = 1024 * 1024;

/// Compatibility spelling emphasizing a digest of canonical protocol bytes.
/// The implementation is the single workspace-wide strict [`Digest`] type.
pub type CanonicalDigestV1 = Digest;

/// A protocol version that must exactly equal [`CURRENT_PROTOCOL_VERSION`].
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProtocolVersionV1(String);

impl ProtocolVersionV1 {
    /// Construct the current version.
    #[must_use]
    pub fn current() -> Self {
        Self(CURRENT_PROTOCOL_VERSION.to_owned())
    }

    /// Validate and construct an exact current version.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnsupportedVersion`] for every other value.
    pub fn parse(value: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = value.into();
        if value != CURRENT_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(value));
        }
        Ok(Self(value))
    }

    /// Return the exact version string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ProtocolVersionV1 {
    fn default() -> Self {
        Self::current()
    }
}

impl<'de> Deserialize<'de> for ProtocolVersionV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// An opaque request identifier with a bounded wire representation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RequestId(String);

impl RequestId {
    /// Validate a caller-generated request identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidRequestId`] for an empty, oversized, or
    /// non-canonical identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(ProtocolError::InvalidRequestId);
        }
        Ok(Self(value))
    }

    /// Return the exact identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Exact context echoed from a request into its response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEchoV1 {
    /// Exact protocol version.
    pub protocol_version: ProtocolVersionV1,
    /// Exact caller request identifier.
    pub request_id: RequestId,
    /// Digest of the canonical request body.
    pub request_digest: CanonicalDigestV1,
}

/// Strict request envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelopeV1<T> {
    /// Version and request binding.
    pub echo: RequestEchoV1,
    /// Request-specific body.
    pub body: T,
}

impl<T: Serialize> RequestEnvelopeV1<T> {
    /// Construct a request and bind its canonical body bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the body cannot be represented as strict JCS.
    pub fn new(request_id: RequestId, body: T) -> Result<Self, ProtocolError> {
        let request_digest = canonical_json_digest("ag-protocol-request-body-v1", &body)?;
        Ok(Self {
            echo: RequestEchoV1 {
                protocol_version: ProtocolVersionV1::current(),
                request_id,
                request_digest,
            },
            body,
        })
    }

    /// Verify the version and exact request-body digest.
    ///
    /// # Errors
    ///
    /// Returns an error for version drift, non-canonical bodies, or a digest
    /// mismatch.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.echo.protocol_version.as_str() != CURRENT_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(
                self.echo.protocol_version.as_str().to_owned(),
            ));
        }
        let actual = canonical_json_digest("ag-protocol-request-body-v1", &self.body)?;
        if actual != self.echo.request_digest {
            return Err(ProtocolError::RequestDigestMismatch {
                expected: self.echo.request_digest.clone(),
                actual,
            });
        }
        Ok(())
    }
}

/// Strict response envelope which echoes an exact request binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelopeV1<T> {
    /// Exact request context being answered.
    pub echo: RequestEchoV1,
    /// Response-specific body.
    pub body: T,
}

impl<T> ResponseEnvelopeV1<T> {
    /// Construct a response from a validated request context.
    #[must_use]
    pub fn for_request<U>(request: &RequestEnvelopeV1<U>, body: T) -> Self {
        Self {
            echo: request.echo.clone(),
            body,
        }
    }

    /// Require an exact version, ID, and digest echo.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::ResponseEchoMismatch`] for any changed field.
    pub fn validate_echo<U>(&self, request: &RequestEnvelopeV1<U>) -> Result<(), ProtocolError> {
        if self.echo != request.echo {
            return Err(ProtocolError::ResponseEchoMismatch);
        }
        Ok(())
    }
}

/// Path-free description of an immutable protocol artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptorV1 {
    /// Digest of the exact artifact bytes.
    pub content_digest: CanonicalDigestV1,
    /// Exact artifact size in bytes.
    pub byte_length: u64,
    /// Bounded IANA-style media type.
    pub media_type: String,
    /// Application-defined, versioned semantic kind.
    pub semantic_type: String,
}

impl ArtifactDescriptorV1 {
    /// Validate bounded, path-free metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidArtifactDescriptor`] for invalid media
    /// or semantic tokens.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if !valid_token(&self.media_type, 128) || !self.media_type.contains('/') {
            return Err(ProtocolError::InvalidArtifactDescriptor(
                "invalid media_type".to_owned(),
            ));
        }
        if !valid_token(&self.semantic_type, 128) {
            return Err(ProtocolError::InvalidArtifactDescriptor(
                "invalid semantic_type".to_owned(),
            ));
        }
        Ok(())
    }
}

fn valid_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+' | b'/')
        })
}

/// Failures emitted by strict protocol encoding and decoding.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// The configured frame limit is zero.
    #[error("frame limit must be non-zero")]
    InvalidFrameLimit,
    /// A frame length exceeds its configured bound.
    #[error("frame length {actual} exceeds configured maximum {maximum}")]
    FrameTooLarge {
        /// Received or requested frame length.
        actual: u64,
        /// Configured maximum length.
        maximum: u32,
    },
    /// The byte slice does not contain a complete frame.
    #[error("truncated frame: expected {expected} payload bytes, received {actual}")]
    TruncatedFrame {
        /// Length declared in the header.
        expected: u32,
        /// Available payload length.
        actual: usize,
    },
    /// Bytes remain after the one allowed frame.
    #[error("{0} trailing bytes follow the frame")]
    TrailingFrameBytes(usize),
    /// Payload is not valid UTF-8.
    #[error("payload is not valid UTF-8")]
    InvalidUtf8,
    /// JSON syntax or data-model decoding failed.
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    /// An object contains the same key more than once.
    #[error("duplicate JSON key {key:?} at {path}")]
    DuplicateKey {
        /// JSON Pointer path of the containing object.
        path: String,
        /// Repeated key.
        key: String,
    },
    /// Deserialization ignored fields unknown to the destination type.
    #[error("unknown JSON fields: {0:?}")]
    UnknownFields(Vec<String>),
    /// Canonical serialization failed.
    #[error("canonical JSON serialization failed: {0}")]
    Canonicalization(String),
    /// An unsupported protocol version was supplied.
    #[error("unsupported protocol version {0:?}")]
    UnsupportedVersion(String),
    /// A request body does not match its declared digest.
    #[error("request digest mismatch: expected {expected}, computed {actual}")]
    RequestDigestMismatch {
        /// Declared request digest.
        expected: CanonicalDigestV1,
        /// Computed request digest.
        actual: CanonicalDigestV1,
    },
    /// Response context does not exactly echo the request context.
    #[error("response does not exactly echo request version, id, and digest")]
    ResponseEchoMismatch,
    /// Digest text is malformed or non-canonical.
    #[error("invalid canonical SHA-256 digest")]
    InvalidDigest,
    /// Request identifier is malformed or too long.
    #[error("invalid request identifier")]
    InvalidRequestId,
    /// Artifact metadata is malformed.
    #[error("invalid artifact descriptor: {0}")]
    InvalidArtifactDescriptor(String),
    /// An I/O operation failed.
    #[error("protocol I/O failed: {0}")]
    Io(#[from] io::Error),
}

/// Encode a serializable value as RFC 8785 JCS bytes.
///
/// # Errors
///
/// Returns an error if the value is not representable as strict JCS, including
/// any floating-point value.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    JcsDocument::canonicalize(value)
        .map(|document| document.as_bytes().to_vec())
        .map_err(|error| ProtocolError::Canonicalization(error.to_string()))
}

/// Hash the RFC 8785 representation of a value under a domain separator.
///
/// # Errors
///
/// Returns an error if canonicalization fails.
pub fn canonical_json_digest<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<CanonicalDigestV1, ProtocolError> {
    Ok(Digest::hash_domain(domain, &canonical_json(value)?))
}

/// Strictly decode exactly one UTF-8 JSON value.
///
/// Unlike `serde_json::from_slice`, this rejects duplicate object keys and any
/// fields ignored by the destination `Deserialize` implementation.
///
/// # Errors
///
/// Returns a specific protocol error for malformed UTF-8/JSON, duplicate keys,
/// floating-point values, ignored fields, or destination-schema mismatch.
pub fn strict_json_from_slice<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, ProtocolError> {
    std::str::from_utf8(bytes).map_err(|_| ProtocolError::InvalidUtf8)?;
    let value = parse_duplicate_free_value(bytes)?;
    let decoded: T = serde_json::from_value(value.clone())
        .map_err(|error| ProtocolError::InvalidJson(error.to_string()))?;
    let normalized = serde_json::to_value(&decoded)
        .map_err(|error| ProtocolError::Canonicalization(error.to_string()))?;
    let mut unknown = Vec::new();
    collect_unknown_paths(&value, &normalized, "", &mut unknown);

    unknown.sort();
    unknown.dedup();
    if !unknown.is_empty() {
        return Err(ProtocolError::UnknownFields(unknown));
    }
    Ok(decoded)
}

/// Blocking codec for exactly one bounded frame at a time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameCodec {
    maximum: u32,
}

impl FrameCodec {
    /// Construct a codec with a non-zero maximum payload length.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidFrameLimit`] for zero.
    pub fn new(maximum: u32) -> Result<Self, ProtocolError> {
        if maximum == 0 {
            return Err(ProtocolError::InvalidFrameLimit);
        }
        Ok(Self { maximum })
    }

    /// Return the configured maximum payload length.
    #[must_use]
    pub fn maximum(&self) -> u32 {
        self.maximum
    }

    /// Add a four-byte unsigned big-endian length prefix.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::FrameTooLarge`] when the payload exceeds the
    /// configured bound.
    pub fn encode_frame(&self, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.check_size(payload.len())?;
        let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge {
            actual: payload.len() as u64,
            maximum: self.maximum,
        })?;
        let mut frame = Vec::with_capacity(payload.len() + 4);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(payload);
        Ok(frame)
    }

    /// Decode exactly one complete frame from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized, truncated, or trailing-byte frame.
    pub fn decode_frame<'a>(&self, frame: &'a [u8]) -> Result<&'a [u8], ProtocolError> {
        if frame.len() < 4 {
            return Err(ProtocolError::TruncatedFrame {
                expected: 0,
                actual: frame.len(),
            });
        }
        let mut header = [0_u8; 4];
        header.copy_from_slice(&frame[..4]);
        let length = u32::from_be_bytes(header);
        self.check_size(length as usize)?;
        let available = frame.len() - 4;
        if available < length as usize {
            return Err(ProtocolError::TruncatedFrame {
                expected: length,
                actual: available,
            });
        }
        if available > length as usize {
            return Err(ProtocolError::TrailingFrameBytes(
                available - length as usize,
            ));
        }
        Ok(&frame[4..])
    }

    /// Read one frame from a blocking stream.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized declaration or an I/O failure.
    pub fn read_frame<R: Read>(&self, reader: &mut R) -> Result<Vec<u8>, ProtocolError> {
        let mut header = [0_u8; 4];
        reader.read_exact(&mut header)?;
        let length = u32::from_be_bytes(header);
        self.check_size(length as usize)?;
        let mut payload = vec![0_u8; length as usize];
        reader.read_exact(&mut payload)?;
        Ok(payload)
    }

    /// Write one frame to a blocking stream and flush it.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized payload or an I/O failure.
    pub fn write_frame<W: Write>(
        &self,
        writer: &mut W,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        self.check_size(payload.len())?;
        let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge {
            actual: payload.len() as u64,
            maximum: self.maximum,
        })?;
        writer.write_all(&length.to_be_bytes())?;
        writer.write_all(payload)?;
        writer.flush()?;
        Ok(())
    }

    /// Canonicalize and frame a JSON value.
    ///
    /// # Errors
    ///
    /// Returns an error when canonicalization or bounded framing fails.
    pub fn encode_json<T: Serialize>(&self, value: &T) -> Result<Vec<u8>, ProtocolError> {
        self.encode_frame(&canonical_json(value)?)
    }

    /// Decode one framed strict JSON value.
    ///
    /// # Errors
    ///
    /// Returns an error when framing, strict JSON, or schema validation fails.
    pub fn decode_json<T: DeserializeOwned + Serialize>(
        &self,
        frame: &[u8],
    ) -> Result<T, ProtocolError> {
        strict_json_from_slice(self.decode_frame(frame)?)
    }

    fn check_size(self, size: usize) -> Result<(), ProtocolError> {
        if size > self.maximum as usize {
            return Err(ProtocolError::FrameTooLarge {
                actual: size as u64,
                maximum: self.maximum,
            });
        }
        Ok(())
    }
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self {
            maximum: DEFAULT_MAX_FRAME_LEN,
        }
    }
}

#[derive(Clone)]
struct UniqueValueSeed {
    path: String,
    duplicate: Rc<RefCell<Option<(String, String)>>>,
}

impl<'de> DeserializeSeed<'de> for UniqueValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor {
            path: self.path,
            duplicate: self.duplicate,
        })
    }
}

struct UniqueValueVisitor {
    path: String,
    duplicate: Rc<RefCell<Option<(String, String)>>>,
}

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("floating-point JSON numbers are forbidden"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueValueSeed {
            path: self.path,
            duplicate: self.duplicate,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(UniqueValueSeed {
            path: format!("{}/{}", self.path, values.len()),
            duplicate: Rc::clone(&self.duplicate),
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let mut object = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                *self.duplicate.borrow_mut() = Some((self.path.clone(), key));
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let child_path = format!("{}/{}", self.path, json_pointer_escape(&key));
            let value = map.next_value_seed(UniqueValueSeed {
                path: child_path,
                duplicate: Rc::clone(&self.duplicate),
            })?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

fn parse_duplicate_free_value(bytes: &[u8]) -> Result<Value, ProtocolError> {
    let duplicate = Rc::new(RefCell::new(None));
    let seed = UniqueValueSeed {
        path: String::new(),
        duplicate: Rc::clone(&duplicate),
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let parsed = seed.deserialize(&mut deserializer);
    if let Some((path, key)) = duplicate.borrow_mut().take() {
        return Err(ProtocolError::DuplicateKey { path, key });
    }
    let value = parsed.map_err(|error| ProtocolError::InvalidJson(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| ProtocolError::InvalidJson(error.to_string()))?;
    Ok(value)
}

fn json_pointer_escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn collect_unknown_paths(input: &Value, normalized: &Value, path: &str, unknown: &mut Vec<String>) {
    match (input, normalized) {
        (Value::Object(input), Value::Object(normalized)) => {
            for (key, value) in input {
                let child_path = format!("{path}/{}", json_pointer_escape(key));
                if let Some(normalized_value) = normalized.get(key) {
                    collect_unknown_paths(value, normalized_value, &child_path, unknown);
                } else {
                    unknown.push(child_path);
                }
            }
        }
        (Value::Array(input), Value::Array(normalized)) => {
            for (index, (value, normalized_value)) in
                input.iter().zip(normalized.iter()).enumerate()
            {
                collect_unknown_paths(value, normalized_value, &format!("{path}/{index}"), unknown);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct Body {
        action: String,
        count: u64,
    }

    #[test]
    fn framing_is_four_byte_big_endian_and_exact() {
        let codec = FrameCodec::new(64).unwrap();
        let encoded = codec.encode_frame(b"hello").unwrap();
        assert_eq!(&encoded[..4], &[0, 0, 0, 5]);
        assert_eq!(codec.decode_frame(&encoded).unwrap(), b"hello");

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            codec.decode_frame(&trailing),
            Err(ProtocolError::TrailingFrameBytes(1))
        ));
    }

    #[test]
    fn frame_limit_is_checked_before_allocation_or_write() {
        let codec = FrameCodec::new(4).unwrap();
        assert!(matches!(
            codec.encode_frame(b"12345"),
            Err(ProtocolError::FrameTooLarge {
                actual: 5,
                maximum: 4
            })
        ));

        let oversized_header = 5_u32.to_be_bytes();
        assert!(matches!(
            codec.decode_frame(&oversized_header),
            Err(ProtocolError::FrameTooLarge {
                actual: 5,
                maximum: 4
            })
        ));
    }

    #[test]
    fn read_and_write_frame_round_trip() {
        let codec = FrameCodec::default();
        let mut wire = Vec::new();
        codec.write_frame(&mut wire, b"payload").unwrap();
        assert_eq!(codec.read_frame(&mut wire.as_slice()).unwrap(), b"payload");
    }

    #[test]
    fn duplicate_keys_are_rejected_at_any_depth() {
        let result = strict_json_from_slice::<Value>(br#"{"outer":{"same":1,"same":2}}"#);
        assert!(matches!(
            result,
            Err(ProtocolError::DuplicateKey { path, key })
                if path == "/outer" && key == "same"
        ));
    }

    #[test]
    fn unknown_fields_are_rejected_even_without_deny_unknown_fields() {
        #[derive(Debug, Deserialize, Serialize)]
        struct Loose {
            _known: Option<String>,
        }

        let result = strict_json_from_slice::<Loose>(br#"{"surprise":true}"#);
        assert!(matches!(
            result,
            Err(ProtocolError::UnknownFields(fields)) if fields == ["/surprise"]
        ));
    }

    #[test]
    fn malformed_utf8_and_trailing_json_are_rejected() {
        assert!(matches!(
            strict_json_from_slice::<Value>(&[b'"', 0xff, b'"']),
            Err(ProtocolError::InvalidUtf8)
        ));
        assert!(matches!(
            strict_json_from_slice::<Value>(b"{} {}"),
            Err(ProtocolError::InvalidJson(_))
        ));
        assert!(matches!(
            strict_json_from_slice::<Value>(b"1.25"),
            Err(ProtocolError::InvalidJson(message))
                if message.contains("floating-point")
        ));
    }

    #[test]
    fn jcs_is_stable_across_object_insertion_order() {
        let first: Value = serde_json::from_str(r#"{"z":1,"a":2}"#).unwrap();
        let second: Value = serde_json::from_str(r#"{"a":2,"z":1}"#).unwrap();
        assert_eq!(
            canonical_json(&first).unwrap(),
            canonical_json(&second).unwrap()
        );
        assert_eq!(
            canonical_json_digest("test", &first).unwrap(),
            canonical_json_digest("test", &second).unwrap()
        );
    }

    #[test]
    fn request_digest_and_response_echo_are_exact() {
        let request = RequestEnvelopeV1::new(
            RequestId::new("request-1").unwrap(),
            Body {
                action: "inspect".to_owned(),
                count: 1,
            },
        )
        .unwrap();
        request.validate().unwrap();

        let response = ResponseEnvelopeV1::for_request(&request, "ok");
        response.validate_echo(&request).unwrap();

        let mut wrong = response;
        wrong.echo.request_id = RequestId::new("request-2").unwrap();
        assert!(matches!(
            wrong.validate_echo(&request),
            Err(ProtocolError::ResponseEchoMismatch)
        ));
    }

    #[test]
    fn mutated_request_body_fails_its_original_binding() {
        let mut request = RequestEnvelopeV1::new(
            RequestId::new("r").unwrap(),
            Body {
                action: "inspect".to_owned(),
                count: 1,
            },
        )
        .unwrap();
        request.body.count = 2;
        assert!(matches!(
            request.validate(),
            Err(ProtocolError::RequestDigestMismatch { .. })
        ));
    }

    #[test]
    fn envelope_unknown_fields_fail_through_frame_codec() {
        let codec = FrameCodec::default();
        let json = br#"{
            "echo": {
              "protocol_version": "ag-local/v1",
              "request_id": "r",
              "request_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "body": {"action":"x","count":1},
            "ambient_authority": true
        }"#;
        let frame = codec.encode_frame(json).unwrap();
        let result = codec.decode_json::<RequestEnvelopeV1<Body>>(&frame);
        assert!(matches!(
            result,
            Err(ProtocolError::UnknownFields(_) | ProtocolError::InvalidJson(_))
        ));
    }

    #[test]
    fn artifact_descriptor_has_no_path_and_validates_tokens() {
        let descriptor = ArtifactDescriptorV1 {
            content_digest: Digest::hash_bytes(b"bytes"),
            byte_length: 5,
            media_type: "application/octet-stream".to_owned(),
            semantic_type: "source-bundle/v1".to_owned(),
        };
        descriptor.validate().unwrap();
    }
}
