//! Authority-domain, epoch, lifecycle, and book-reference identities.

use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;

use rand::Rng as _;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const MAX_IDENTIFIER_LENGTH: usize = 128;

macro_rules! impl_text_newtype {
    ($type:ident) => {
        impl fmt::Display for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $type {
            type Err = IdentifierError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct TextVisitor;

                impl Visitor<'_> for TextVisitor {
                    type Value = $type;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a canonical AG-ng identifier")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        $type::parse(value).map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(TextVisitor)
            }
        }
    };
}

/// A canonical configured authority-domain identifier.
///
/// Authority domains are administrative namespaces, not DNS names and not
/// network endpoints.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityDomainId(String);

impl AuthorityDomainId {
    /// Validates and constructs an authority-domain identifier.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] for an empty, overlong, or noncanonical ID.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        validate_identifier("authority domain", &value)?;
        Ok(Self(value))
    }

    /// Parses an authority-domain identifier.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] unless `value` is canonical.
    pub fn parse(value: &str) -> Result<Self, IdentifierError> {
        Self::new(value)
    }

    /// Returns the canonical identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl_text_newtype!(AuthorityDomainId);

/// Short compatibility alias for [`AuthorityDomainId`].
pub type AuthorityDomain = AuthorityDomainId;

/// A nonzero authority epoch.
///
/// Epoch changes invalidate capabilities and pending authority. Epoch zero is
/// reserved to make uninitialized/default state unrepresentable.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct EpochId(u64);

impl EpochId {
    /// Constructs a nonzero epoch.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::ZeroEpoch`] for the reserved epoch zero.
    pub const fn new(value: u64) -> Result<Self, IdentifierError> {
        if value == 0 {
            Err(IdentifierError::ZeroEpoch)
        } else {
            Ok(Self(value))
        }
    }

    /// Parses a decimal, nonzero epoch without signs or leading zeroes.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] unless `value` is canonical nonzero decimal.
    pub fn parse(value: &str) -> Result<Self, IdentifierError> {
        if value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err(IdentifierError::InvalidEpochText);
        }
        let epoch = value
            .parse::<u64>()
            .map_err(|_| IdentifierError::InvalidEpochText)?;
        Self::new(epoch)
    }

    /// Returns the integer epoch value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Computes the next epoch, failing on exhaustion.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::EpochExhausted`] at [`u64::MAX`].
    pub const fn checked_next(self) -> Result<Self, IdentifierError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(IdentifierError::EpochExhausted),
        }
    }
}

impl fmt::Display for EpochId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl<'de> Deserialize<'de> for EpochId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Short compatibility alias for [`EpochId`].
pub type Epoch = EpochId;

/// A daemon-allocated, 128-bit lifecycle nonce.
///
/// The text representation is exactly 32 lowercase hexadecimal characters.
/// This is intentionally not an ambient UUID: its meaning comes only from the
/// authority domain and epoch in [`LifecycleOrigin`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LifecycleNonce([u8; 16]);

impl LifecycleNonce {
    /// Constructs a nonce from exact bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Alias for [`Self::new`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self::new(bytes)
    }

    /// Allocates a nonce from the operating system random source.
    #[must_use]
    pub fn random() -> Self {
        let mut bytes = [0_u8; 16];
        rand::rng().fill(&mut bytes);
        Self(bytes)
    }

    /// Parses the strict lowercase hexadecimal representation.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleNonceParseError`] unless `value` is exactly 32
    /// lowercase hexadecimal characters.
    pub fn parse(value: &str) -> Result<Self, LifecycleNonceParseError> {
        value.parse()
    }

    /// Returns the raw nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for LifecycleNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl FromStr for LifecycleNonce {
    type Err = LifecycleNonceParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 32 {
            return Err(LifecycleNonceParseError::Length {
                actual: value.len(),
            });
        }
        if let Some((index, character)) = value
            .char_indices()
            .find(|(_, character)| !matches!(character, '0'..='9' | 'a'..='f'))
        {
            return Err(LifecycleNonceParseError::Hex { index, character });
        }
        let mut bytes = [0_u8; 16];
        hex::decode_to_slice(value, &mut bytes)
            .map_err(|_| LifecycleNonceParseError::InternalHexInvariant)?;
        Ok(Self(bytes))
    }
}

impl Serialize for LifecycleNonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for LifecycleNonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NonceVisitor;

        impl Visitor<'_> for NonceVisitor {
            type Value = LifecycleNonce;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("32 lowercase hexadecimal nonce characters")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                LifecycleNonce::parse(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(NonceVisitor)
    }
}

/// A lifecycle nonce parse failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LifecycleNonceParseError {
    /// The nonce has the wrong byte length.
    #[error("lifecycle nonce must be 32 bytes of lowercase hexadecimal; got {actual}")]
    Length {
        /// Actual text length.
        actual: usize,
    },
    /// The nonce contains a noncanonical hexadecimal character.
    #[error("invalid lowercase hexadecimal character {character:?} at nonce offset {index}")]
    Hex {
        /// Byte offset.
        index: usize,
        /// Rejected character.
        character: char,
    },
    /// A checked hexadecimal invariant unexpectedly failed.
    #[error("validated lifecycle nonce could not be decoded")]
    InternalHexInvariant,
}

/// The complete origin of one admitted lifecycle.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleOrigin {
    /// Administrative authority domain.
    pub authority_domain: AuthorityDomainId,
    /// Authority epoch.
    pub epoch: EpochId,
    /// Daemon-allocated lifecycle nonce.
    pub lifecycle_nonce: LifecycleNonce,
}

impl LifecycleOrigin {
    /// Constructs a lifecycle origin from its non-convertible components.
    #[must_use]
    pub const fn new(
        authority_domain: AuthorityDomainId,
        epoch: EpochId,
        lifecycle_nonce: LifecycleNonce,
    ) -> Self {
        Self {
            authority_domain,
            epoch,
            lifecycle_nonce,
        }
    }
}

/// A canonical local identifier within one lifecycle book.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BookLocalId(String);

impl BookLocalId {
    /// Validates and constructs a book-local identifier.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] for an empty, overlong, or noncanonical ID.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        validate_identifier("book local ID", &value)?;
        Ok(Self(value))
    }

    /// Parses a book-local identifier.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] unless `value` is canonical.
    pub fn parse(value: &str) -> Result<Self, IdentifierError> {
        Self::new(value)
    }

    /// Returns the canonical identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl_text_newtype!(BookLocalId);

/// The four non-convertible lifecycle books.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookKind {
    /// Standing/admissibility records.
    Standing,
    /// Evidence custody records.
    Custody,
    /// Outstanding obligation records.
    Obligation,
    /// Bounded capacity/permit records.
    Capacity,
}

mod sealed {
    pub trait Sealed {}
}

/// A sealed compile-time book tag.
pub trait BookTag: sealed::Sealed + Clone + Copy + fmt::Debug + Eq + Ord {
    /// Runtime discriminator written into the wire representation.
    const KIND: BookKind;
}

macro_rules! define_book_tag {
    ($name:ident, $kind:ident, $reference:ident) => {
        #[doc = concat!("Compile-time marker for the ", stringify!($kind), " book.")]
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name;

        impl sealed::Sealed for $name {}

        impl BookTag for $name {
            const KIND: BookKind = BookKind::$kind;
        }

        #[doc = concat!("A typed ", stringify!($kind), " book reference.")]
        pub type $reference = BookRef<$name>;
    };
}

define_book_tag!(StandingBook, Standing, StandingBookRef);
define_book_tag!(CustodyBook, Custody, CustodyBookRef);
define_book_tag!(ObligationBook, Obligation, ObligationBookRef);
define_book_tag!(CapacityBook, Capacity, CapacityBookRef);

/// A book-kind-safe reference into one lifecycle.
///
/// `BookRef<StandingBook>` and `BookRef<CustodyBook>` are distinct Rust types
/// and have no conversion between them. The runtime book discriminator is also
/// serialized and verified, preventing forged outer type labels on the wire.
#[derive(Debug)]
pub struct BookRef<K: BookTag> {
    origin: LifecycleOrigin,
    local_id: BookLocalId,
    marker: PhantomData<K>,
}

impl<K: BookTag> BookRef<K> {
    /// Constructs a typed book reference.
    #[must_use]
    pub const fn new(origin: LifecycleOrigin, local_id: BookLocalId) -> Self {
        Self {
            origin,
            local_id,
            marker: PhantomData,
        }
    }

    /// Returns the compile-time-checked book kind.
    #[must_use]
    pub const fn kind(&self) -> BookKind {
        K::KIND
    }

    /// Returns the full lifecycle origin.
    #[must_use]
    pub const fn origin(&self) -> &LifecycleOrigin {
        &self.origin
    }

    /// Returns the book-local identifier.
    #[must_use]
    pub const fn local_id(&self) -> &BookLocalId {
        &self.local_id
    }

    /// Converts to the intentionally tagged, type-erased representation.
    #[must_use]
    pub fn erase(&self) -> AnyBookRef {
        AnyBookRef {
            book: K::KIND,
            origin: self.origin.clone(),
            local_id: self.local_id.clone(),
        }
    }
}

impl<K: BookTag> Clone for BookRef<K> {
    fn clone(&self) -> Self {
        Self::new(self.origin.clone(), self.local_id.clone())
    }
}

impl<K: BookTag> PartialEq for BookRef<K> {
    fn eq(&self, other: &Self) -> bool {
        self.origin == other.origin && self.local_id == other.local_id
    }
}

impl<K: BookTag> Eq for BookRef<K> {}

impl<K: BookTag> std::hash::Hash for BookRef<K> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.origin.hash(state);
        self.local_id.hash(state);
    }
}

impl<K: BookTag> Serialize for BookRef<K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        BookRefWire {
            book: K::KIND,
            origin: self.origin.clone(),
            local_id: self.local_id.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de, K: BookTag> Deserialize<'de> for BookRef<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = BookRefWire::deserialize(deserializer)?;
        if wire.book != K::KIND {
            return Err(de::Error::custom(format_args!(
                "expected {:?} book reference, got {:?}",
                K::KIND,
                wire.book
            )));
        }
        Ok(Self::new(wire.origin, wire.local_id))
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BookRefWire {
    book: BookKind,
    origin: LifecycleOrigin,
    local_id: BookLocalId,
}

/// An explicitly type-erased book reference which retains its runtime tag.
///
/// This is useful at protocol/storage boundaries. Callers must use
/// [`Self::try_typed`] to recover a specific book type; there is no implicit
/// conversion.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnyBookRef {
    /// Retained book discriminator.
    pub book: BookKind,
    /// Full lifecycle origin.
    pub origin: LifecycleOrigin,
    /// Local identifier in `book`.
    pub local_id: BookLocalId,
}

impl AnyBookRef {
    /// Attempts to recover a compile-time typed reference, checking the tag.
    ///
    /// # Errors
    ///
    /// Returns [`BookKindMismatch`] when the retained runtime tag differs from
    /// `K`.
    pub fn try_typed<K: BookTag>(&self) -> Result<BookRef<K>, BookKindMismatch> {
        if self.book != K::KIND {
            return Err(BookKindMismatch {
                expected: K::KIND,
                actual: self.book,
            });
        }
        Ok(BookRef::new(self.origin.clone(), self.local_id.clone()))
    }
}

/// A rejected attempt to reinterpret one book reference as another.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("expected {expected:?} book reference, got {actual:?}")]
pub struct BookKindMismatch {
    /// Required kind.
    pub expected: BookKind,
    /// Observed kind.
    pub actual: BookKind,
}

/// A strict identifier validation failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IdentifierError {
    /// Empty identifiers are not admitted.
    #[error("{kind} must not be empty")]
    Empty {
        /// Identifier family.
        kind: &'static str,
    },
    /// Identifier exceeds the protocol limit.
    #[error("{kind} exceeds {maximum} bytes (got {actual})")]
    TooLong {
        /// Identifier family.
        kind: &'static str,
        /// Maximum admitted byte length.
        maximum: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// Identifier contains a noncanonical character or separator placement.
    #[error("{kind} is not a canonical lowercase AG-ng identifier")]
    NonCanonical {
        /// Identifier family.
        kind: &'static str,
    },
    /// Epoch zero is reserved.
    #[error("authority epoch must be nonzero")]
    ZeroEpoch,
    /// Text epoch is not canonical decimal.
    #[error("authority epoch must be canonical unsigned decimal without leading zeroes")]
    InvalidEpochText,
    /// The epoch counter cannot advance.
    #[error("authority epoch is exhausted")]
    EpochExhausted,
}

fn validate_identifier(kind: &'static str, value: &str) -> Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::Empty { kind });
    }
    if value.len() > MAX_IDENTIFIER_LENGTH {
        return Err(IdentifierError::TooLong {
            kind,
            maximum: MAX_IDENTIFIER_LENGTH,
            actual: value.len(),
        });
    }

    let bytes = value.as_bytes();
    let endpoint_is_alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let admitted = |byte: u8| {
        endpoint_is_alphanumeric(byte) || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
    };
    if !endpoint_is_alphanumeric(bytes[0])
        || !endpoint_is_alphanumeric(bytes[bytes.len() - 1])
        || !bytes.iter().copied().all(admitted)
    {
        return Err(IdentifierError::NonCanonical { kind });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> LifecycleOrigin {
        LifecycleOrigin::new(
            AuthorityDomainId::new("site:primary").unwrap(),
            EpochId::new(7).unwrap(),
            LifecycleNonce::new([0xab; 16]),
        )
    }

    #[test]
    fn identifiers_are_canonical_and_bounded() {
        assert_eq!(
            AuthorityDomainId::new("example:prod/site-a")
                .unwrap()
                .as_str(),
            "example:prod/site-a"
        );
        for invalid in ["", "Upper", "-prefix", "suffix-", "has space", "é"] {
            assert!(AuthorityDomainId::new(invalid).is_err(), "{invalid:?}");
        }
        assert!(AuthorityDomainId::new("a".repeat(129)).is_err());
    }

    #[test]
    fn epochs_reject_zero_and_noncanonical_text() {
        assert!(EpochId::new(0).is_err());
        assert!(EpochId::parse("01").is_err());
        assert!(EpochId::parse("+1").is_err());
        assert_eq!(
            EpochId::parse("41").unwrap().checked_next().unwrap().get(),
            42
        );
        assert!(EpochId::new(u64::MAX).unwrap().checked_next().is_err());
        assert!(serde_json::from_str::<EpochId>("0").is_err());
    }

    #[test]
    fn nonce_is_strict_lowercase_hex() {
        let nonce = LifecycleNonce::new([0xab; 16]);
        assert_eq!(nonce.to_string(), "abababababababababababababababab");
        assert_eq!(LifecycleNonce::parse(&nonce.to_string()).unwrap(), nonce);
        assert!(LifecycleNonce::parse("ABABABABABABABABABABABABABABABAB").is_err());
        assert!(LifecycleNonce::parse("00").is_err());
    }

    #[test]
    fn typed_book_wire_retains_and_checks_tag() {
        let standing = StandingBookRef::new(origin(), BookLocalId::new("record-1").unwrap());
        let encoded = serde_json::to_string(&standing).unwrap();
        assert!(encoded.contains(r#""book":"standing""#));
        assert_eq!(
            serde_json::from_str::<StandingBookRef>(&encoded).unwrap(),
            standing
        );

        let forged = encoded.replace("standing", "custody");
        assert!(serde_json::from_str::<StandingBookRef>(&forged).is_err());
    }

    #[test]
    fn erased_book_ref_requires_exact_kind_to_recover() {
        let standing = StandingBookRef::new(origin(), BookLocalId::new("same-id").unwrap());
        let erased = standing.erase();
        assert_eq!(erased.try_typed::<StandingBook>().unwrap(), standing);
        assert!(erased.try_typed::<CustodyBook>().is_err());
    }

    #[test]
    fn same_local_id_in_different_origins_does_not_alias() {
        let one = StandingBookRef::new(origin(), BookLocalId::new("same").unwrap());
        let mut other_origin = origin();
        other_origin.lifecycle_nonce = LifecycleNonce::new([0xcd; 16]);
        let two = StandingBookRef::new(other_origin, BookLocalId::new("same").unwrap());
        assert_ne!(one, two);
    }
}
