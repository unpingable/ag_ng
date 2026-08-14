//! Strict SHA-256 and JSON Canonicalization Scheme helpers.

use core::fmt;
use core::str::FromStr;
use std::collections::HashSet;

use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Smallest integer represented exactly by the RFC 8785 / ECMAScript number
/// model used by AG's cross-repository canonical JSON contracts.
pub const MIN_JCS_SAFE_INTEGER: i64 = -9_007_199_254_740_991;
/// Largest integer represented exactly by the RFC 8785 / ECMAScript number
/// model used by AG's cross-repository canonical JSON contracts.
pub const MAX_JCS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_JCS_SAFE_SIGNED_INTEGER: i64 = 9_007_199_254_740_991;

const SHA256_PREFIX: &str = "sha256:";
const SHA256_HEX_LENGTH: usize = 64;
const SHA256_TEXT_LENGTH: usize = SHA256_PREFIX.len() + SHA256_HEX_LENGTH;

/// A canonical, algorithm-qualified SHA-256 digest.
///
/// Text and Serde representations are exactly `sha256:` followed by 64
/// lowercase hexadecimal characters. Alternate algorithms, uppercase hex,
/// whitespace, and bare hexadecimal values are rejected.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest(String);

impl Digest {
    /// Hashes `bytes` with SHA-256.
    #[must_use]
    pub fn hash_bytes(bytes: &[u8]) -> Self {
        let raw = Sha256::digest(bytes);
        Self(format!("{SHA256_PREFIX}{}", hex::encode(raw)))
    }

    /// Compatibility spelling for [`Self::hash_bytes`].
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self::hash_bytes(bytes)
    }

    /// Hashes an explicitly domain-separated payload.
    ///
    /// The encoding is unambiguous: a fixed AG-ng prefix, the big-endian
    /// domain length, the domain bytes, the big-endian payload length, and the
    /// payload bytes. Callers should use a stable versioned domain such as
    /// `ag-ng/principal/v1`.
    #[must_use]
    pub fn hash_domain(domain: &str, payload: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"ag-ng\0digest\0v1\0");
        hasher.update((domain.len() as u128).to_be_bytes());
        hasher.update(domain.as_bytes());
        hasher.update((payload.len() as u128).to_be_bytes());
        hasher.update(payload);
        let raw = hasher.finalize();
        Self(format!("{SHA256_PREFIX}{}", hex::encode(raw)))
    }

    /// Canonicalizes a serializable value with JCS and hashes the result.
    ///
    /// # Errors
    ///
    /// Returns [`JcsError`] when the value cannot be serialized as strict,
    /// integer-only canonical JSON.
    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Result<Self, JcsError> {
        Ok(JcsDocument::canonicalize(value)?.digest())
    }

    /// Parses the strict algorithm-qualified representation.
    ///
    /// # Errors
    ///
    /// Returns [`DigestParseError`] unless the input is the exact canonical
    /// SHA-256 representation.
    pub fn parse(value: &str) -> Result<Self, DigestParseError> {
        value.parse()
    }

    /// Returns the canonical textual representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the raw 32 digest bytes.
    ///
    /// # Panics
    ///
    /// This method cannot panic through the public API: every constructor and
    /// deserializer establishes the exact prefix, length, and hex invariant.
    #[must_use]
    pub fn raw_bytes(&self) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        // Construction and deserialization both pass through strict parsing.
        hex::decode_to_slice(&self.0[SHA256_PREFIX.len()..], &mut bytes)
            .expect("a Digest always contains validated hexadecimal text");
        bytes
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Digest {
    type Err = DigestParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != SHA256_TEXT_LENGTH {
            return Err(DigestParseError::Length {
                actual: value.len(),
            });
        }
        if !value.starts_with(SHA256_PREFIX) {
            return Err(DigestParseError::Algorithm);
        }

        let encoded = &value[SHA256_PREFIX.len()..];
        if let Some((index, character)) = encoded
            .char_indices()
            .find(|(_, character)| !matches!(character, '0'..='9' | 'a'..='f'))
        {
            return Err(DigestParseError::Hex { index, character });
        }

        // Decode as an additional invariant check even though the alphabet and
        // exact length checks already imply a valid byte sequence.
        let mut raw = [0_u8; 32];
        hex::decode_to_slice(encoded, &mut raw)
            .map_err(|_| DigestParseError::InternalHexInvariant)?;
        Ok(Self(value.to_owned()))
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DigestVisitor;

        impl Visitor<'_> for DigestVisitor {
            type Value = Digest;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a canonical sha256:<64 lowercase hex> digest")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Digest::parse(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(DigestVisitor)
    }
}

/// A strict digest parsing failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DigestParseError {
    /// The representation has the wrong byte length.
    #[error("SHA-256 digest must be {SHA256_TEXT_LENGTH} bytes; got {actual}")]
    Length {
        /// Actual input length.
        actual: usize,
    },
    /// The algorithm prefix is not exactly `sha256:`.
    #[error("digest algorithm must be exactly `sha256:`")]
    Algorithm,
    /// The hexadecimal suffix is not canonical lowercase hexadecimal.
    #[error("invalid lowercase hexadecimal character {character:?} at digest offset {index}")]
    Hex {
        /// Byte offset within the hexadecimal suffix.
        index: usize,
        /// Rejected character.
        character: char,
    },
    /// An internal invariant in the checked hexadecimal input failed.
    #[error("validated hexadecimal digest could not be decoded")]
    InternalHexInvariant,
}

/// An immutable canonical JSON document.
///
/// Parsing rejects duplicate object keys, floating-point values, invalid
/// Unicode/JSON, and trailing input before applying RFC 8785 JCS ordering and
/// escaping. Integer-only documents keep protocol digests independent from
/// language-specific floating-point behavior.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct JcsDocument(Vec<u8>);

impl JcsDocument {
    /// Serializes a value to canonical, integer-only JCS.
    ///
    /// # Errors
    ///
    /// Returns [`JcsError`] for unsupported values (including floats), custom
    /// serialization failures, or duplicate map keys.
    pub fn canonicalize<T: Serialize + ?Sized>(value: &T) -> Result<Self, JcsError> {
        let encoded = serde_jcs::to_vec(value).map_err(JcsError::Serialization)?;
        // Reparse with the strict visitor to reject floats emitted by a
        // serializable value and to keep one policy for all constructors.
        let strict_value = parse_strict_value(&encoded)?;
        let canonical = serde_jcs::to_vec(&strict_value).map_err(JcsError::Serialization)?;
        Ok(Self(canonical))
    }

    /// Parses JSON strictly and returns its canonical JCS representation.
    ///
    /// # Errors
    ///
    /// Returns [`JcsError`] for malformed JSON, duplicate keys, floats, or
    /// trailing data.
    pub fn parse(input: &[u8]) -> Result<Self, JcsError> {
        let value = parse_strict_value(input)?;
        let canonical = serde_jcs::to_vec(&value).map_err(JcsError::Serialization)?;
        Ok(Self(canonical))
    }

    /// Accepts input only if it is already the exact canonical representation.
    ///
    /// # Errors
    ///
    /// Returns [`JcsError`] if input is invalid strict JSON or differs from its
    /// RFC 8785 canonical representation.
    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, JcsError> {
        let document = Self::parse(input)?;
        if document.as_bytes() != input {
            return Err(JcsError::NotCanonical);
        }
        Ok(document)
    }

    /// Returns the canonical UTF-8 JSON bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the canonical JSON as UTF-8 text.
    ///
    /// # Panics
    ///
    /// This method cannot panic through the public API because all constructors
    /// obtain bytes from a UTF-8 JSON parser or JCS serializer.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // serde_jcs always produces UTF-8 JSON.
        std::str::from_utf8(&self.0).expect("a JCS document is always UTF-8")
    }

    /// Hashes the exact canonical document bytes.
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::hash_bytes(self.as_bytes())
    }

    /// Decodes the canonical document into a typed value.
    ///
    /// # Errors
    ///
    /// Returns [`JcsError`] when the canonical document does not match `T`.
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, JcsError> {
        serde_json::from_slice(&self.0).map_err(JcsError::Deserialization)
    }
}

/// A canonical JSON construction or validation error.
#[derive(Debug, Error)]
pub enum JcsError {
    /// JSON could not be parsed under the strict policy.
    #[error("strict JSON parse failed: {0}")]
    Parse(#[source] serde_json::Error),
    /// A Rust value could not be serialized canonically.
    #[error("JCS serialization failed: {0}")]
    Serialization(#[source] serde_json::Error),
    /// A canonical document could not be decoded into the requested type.
    #[error("canonical JSON deserialization failed: {0}")]
    Deserialization(#[source] serde_json::Error),
    /// The input is valid strict JSON but is not already exact JCS.
    #[error("JSON input is not in canonical JCS form")]
    NotCanonical,
}

fn parse_strict_value(input: &[u8]) -> Result<serde_json::Value, JcsError> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = serde::Deserializer::deserialize_any(&mut deserializer, StrictValueVisitor)
        .map_err(JcsError::Parse)?;
    deserializer.end().map_err(JcsError::Parse)?;
    Ok(value)
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON without duplicate keys or floating-point values")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if !(MIN_JCS_SAFE_INTEGER..=MAX_JCS_SAFE_SIGNED_INTEGER).contains(&value) {
            return Err(E::custom("integer is outside the exact JCS range"));
        }
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value > MAX_JCS_SAFE_INTEGER {
            return Err(E::custom("integer is outside the exact JCS range"));
        }
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("floating-point JSON values are forbidden"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValueSeed)? {
            values.push(value);
        }
        Ok(serde_json::Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format_args!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            let value = map.next_value_seed(StrictValueSeed)?;
            values.insert(key, value);
        }
        Ok(serde_json::Value::Object(values))
    }
}

struct StrictValueSeed;

impl<'de> de::DeserializeSeed<'de> for StrictValueSeed {
    type Value = serde_json::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::*;

    #[derive(Serialize)]
    struct NestedIntegers {
        values: Vec<i64>,
    }

    #[test]
    fn sha256_known_answer_and_roundtrip() {
        let digest = Digest::hash_bytes(b"abc");
        assert_eq!(
            digest.as_str(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(Digest::parse(digest.as_str()).unwrap(), digest);
        assert_eq!(digest.raw_bytes()[0..4], [0xba, 0x78, 0x16, 0xbf]);
    }

    #[test]
    fn digest_parser_rejects_noncanonical_forms() {
        let valid = Digest::hash_bytes(b"abc").to_string();
        assert!(Digest::parse(&valid[7..]).is_err());
        assert!(Digest::parse(&valid.to_uppercase()).is_err());
        assert!(Digest::parse(&format!("SHA256:{}", &valid[7..])).is_err());
        assert!(Digest::parse(&format!("{valid} ")).is_err());
        let invalid = format!("sha256:{}g", "0".repeat(63));
        assert!(matches!(
            Digest::parse(&invalid),
            Err(DigestParseError::Hex { .. })
        ));
    }

    #[test]
    fn digest_serde_is_a_strict_string() {
        let digest = Digest::hash_bytes(b"serde");
        let encoded = serde_json::to_string(&digest).unwrap();
        assert_eq!(serde_json::from_str::<Digest>(&encoded).unwrap(), digest);
        assert!(serde_json::from_str::<Digest>("42").is_err());
    }

    #[test]
    fn domain_separation_is_unambiguous() {
        assert_ne!(
            Digest::hash_domain("ab", b"c"),
            Digest::hash_domain("a", b"bc")
        );
        assert_ne!(
            Digest::hash_domain("principal/v1", b"same"),
            Digest::hash_domain("capability/v1", b"same")
        );
    }

    #[test]
    fn jcs_canonicalizes_keys_and_whitespace() {
        let document = JcsDocument::parse(br#" { "z": 2, "a": [true, null, 1] } "#).unwrap();
        assert_eq!(document.as_str(), r#"{"a":[true,null,1],"z":2}"#);
        assert_eq!(
            JcsDocument::from_canonical_bytes(document.as_bytes()).unwrap(),
            document
        );
    }

    #[test]
    fn strict_json_rejects_duplicate_keys_floats_and_trailing_data() {
        assert!(JcsDocument::parse(br#"{"a":1,"a":2}"#).is_err());
        assert!(JcsDocument::parse(br#"{"a":1.0}"#).is_err());
        assert!(JcsDocument::parse(br"{} {}").is_err());
    }

    #[test]
    fn canonical_constructor_rejects_merely_valid_json() {
        assert!(matches!(
            JcsDocument::from_canonical_bytes(br#"{"z":1,"a":2}"#),
            Err(JcsError::NotCanonical)
        ));
    }

    #[test]
    fn serializable_values_and_typed_decode_roundtrip() {
        #[derive(Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
        struct Example {
            label: String,
            count: u64,
        }

        let value = Example {
            label: "work".to_owned(),
            count: 7,
        };
        let document = JcsDocument::canonicalize(&value).unwrap();
        assert_eq!(document.decode::<Example>().unwrap(), value);
        assert_eq!(
            Digest::from_serializable(&value).unwrap(),
            document.digest()
        );
    }

    #[test]
    fn serializable_floats_are_rejected() {
        #[derive(Serialize)]
        struct HasFloat {
            value: f64,
        }

        assert!(JcsDocument::canonicalize(&HasFloat { value: 1.25 }).is_err());
    }

    #[test]
    fn every_constructor_recursively_enforces_the_exact_jcs_integer_range() {
        let minimum = format!(r#"{{"nested":[{{"value":{MIN_JCS_SAFE_INTEGER}}}]}}"#);
        let maximum = format!(r#"{{"nested":[{{"value":{MAX_JCS_SAFE_INTEGER}}}]}}"#);
        assert!(JcsDocument::parse(minimum.as_bytes()).is_ok());
        assert!(JcsDocument::parse(maximum.as_bytes()).is_ok());
        assert!(JcsDocument::from_canonical_bytes(minimum.as_bytes()).is_ok());
        assert!(JcsDocument::from_canonical_bytes(maximum.as_bytes()).is_ok());

        let below = format!(r#"{{"nested":[{{"value":{}}}]}}"#, MIN_JCS_SAFE_INTEGER - 1);
        let above = format!(r#"{{"nested":[{{"value":{}}}]}}"#, MAX_JCS_SAFE_INTEGER + 1);
        assert!(JcsDocument::parse(below.as_bytes()).is_err());
        assert!(JcsDocument::parse(above.as_bytes()).is_err());
        assert!(JcsDocument::from_canonical_bytes(below.as_bytes()).is_err());
        assert!(JcsDocument::from_canonical_bytes(above.as_bytes()).is_err());

        assert!(
            JcsDocument::canonicalize(&NestedIntegers {
                values: vec![MIN_JCS_SAFE_INTEGER, MAX_JCS_SAFE_SIGNED_INTEGER],
            })
            .is_ok()
        );
        assert!(
            JcsDocument::canonicalize(&NestedIntegers {
                values: vec![MIN_JCS_SAFE_INTEGER - 1],
            })
            .is_err()
        );
        assert!(
            JcsDocument::canonicalize(&serde_json::json!({
                "nested": [{"value": MAX_JCS_SAFE_INTEGER + 1}]
            }))
            .is_err()
        );
        for unsafe_integer in [9_223_372_036_854_775_807_u64, u64::MAX] {
            assert!(
                JcsDocument::canonicalize(&serde_json::json!({
                    "nested": [{"value": unsafe_integer}]
                }))
                .is_err(),
                "unsafe integer {unsafe_integer} must refuse before any digest can be derived"
            );
            assert!(
                Digest::from_serializable(&serde_json::json!({
                    "nested": [{"value": unsafe_integer}]
                }))
                .is_err(),
                "unsafe integer {unsafe_integer} must not produce a Digest"
            );
        }
    }
}
