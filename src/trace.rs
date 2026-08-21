use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use lenso_kernel::{InvocationContext, InvocationContextError, SealedInvocationExtension};
use sha2::Sha256;

/// Registered sealed extension key for W3C Trace Context propagation.
pub const TRACE_CONTEXT_EXTENSION_KEY: &str = "lenso.otel.trace-context";

/// Default provenance name used by an explicitly configured `OTel` Module.
pub const DEFAULT_TRACE_CONTEXT_ISSUER: &str = "lenso.otel";

type HmacSha256 = Hmac<Sha256>;

/// W3C Trace Context carried by an Lenso Invocation Context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceContext {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    trace_flags: u8,
    tracestate: Option<String>,
}

impl TraceContext {
    /// Parses a W3C version-zero `traceparent` and optional `tracestate`.
    pub fn from_traceparent(
        traceparent: &str,
        tracestate: Option<&str>,
    ) -> Result<Self, TraceContextParseError> {
        let mut fields = traceparent.split('-');
        let version = fields.next();
        let trace_id = fields.next();
        let span_id = fields.next();
        let flags = fields.next();
        if version.is_none()
            || trace_id.is_none()
            || span_id.is_none()
            || flags.is_none()
            || fields.next().is_some()
        {
            return Err(TraceContextParseError::InvalidTraceparent);
        }
        if version != Some("00") {
            return Err(TraceContextParseError::UnsupportedVersion);
        }
        let trace_id = decode_hex::<16>(trace_id.expect("trace id was checked"))?;
        let span_id = decode_hex::<8>(span_id.expect("span id was checked"))?;
        let trace_flags = decode_hex::<1>(flags.expect("flags were checked"))?[0];
        if trace_id.iter().all(|byte| *byte == 0) {
            return Err(TraceContextParseError::ZeroTraceId);
        }
        if span_id.iter().all(|byte| *byte == 0) {
            return Err(TraceContextParseError::ZeroSpanId);
        }
        if let Some(tracestate) = tracestate {
            validate_tracestate(tracestate)?;
        }
        Ok(Self {
            trace_id,
            span_id,
            trace_flags,
            tracestate: tracestate.map(str::to_owned),
        })
    }

    /// Parses the portable extension bytes emitted by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TraceContextParseError> {
        let wire =
            std::str::from_utf8(bytes).map_err(|_| TraceContextParseError::InvalidWireEncoding)?;
        let (traceparent, tracestate) = wire
            .split_once('\n')
            .map_or((wire, None), |(traceparent, tracestate)| {
                (traceparent, Some(tracestate))
            });
        Self::from_traceparent(traceparent, tracestate)
    }

    /// Serializes the trace context as a standard `traceparent` line followed
    /// by an optional `tracestate` line.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut wire = self.traceparent().into_bytes();
        if let Some(tracestate) = &self.tracestate {
            wire.push(b'\n');
            wire.extend_from_slice(tracestate.as_bytes());
        }
        wire
    }

    /// Returns the canonical W3C `traceparent` value.
    pub fn traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            encode_hex(&self.trace_id),
            encode_hex(&self.span_id),
            self.trace_flags
        )
    }

    /// Returns the optional W3C `tracestate` value.
    pub fn tracestate(&self) -> Option<&str> {
        self.tracestate.as_deref()
    }

    /// Returns the 16-byte trace identity.
    pub const fn trace_id(&self) -> [u8; 16] {
        self.trace_id
    }

    /// Returns the 8-byte span identity.
    pub const fn span_id(&self) -> [u8; 8] {
        self.span_id
    }

    /// Returns the W3C trace flags.
    pub const fn trace_flags(&self) -> u8 {
        self.trace_flags
    }

    /// Returns a copy with a new span identity for an explicitly created child span.
    #[must_use]
    pub const fn with_span_id(mut self, span_id: [u8; 8]) -> Self {
        self.span_id = span_id;
        self
    }
}

/// Configuration failure for a registered trace-context issuer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TraceContextConfigError {
    /// An issuer provenance name is required.
    EmptyIssuer,
    /// A signing key is required for provenance verification.
    EmptySigningKey,
}

impl fmt::Display for TraceContextConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIssuer => formatter.write_str("trace-context issuer is empty"),
            Self::EmptySigningKey => formatter.write_str("trace-context signing key is empty"),
        }
    }
}

impl std::error::Error for TraceContextConfigError {}

/// Failure while parsing or validating a W3C Trace Context value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TraceContextParseError {
    /// The value does not have the four required version-zero fields.
    InvalidTraceparent,
    /// Only the W3C version-zero wire form is accepted by this Module.
    UnsupportedVersion,
    /// One field contains the wrong number or shape of hexadecimal digits.
    InvalidHex,
    /// Trace identity cannot be all zeroes.
    ZeroTraceId,
    /// Span identity cannot be all zeroes.
    ZeroSpanId,
    /// The optional `tracestate` value contains invalid control or separator data.
    InvalidTracestate,
    /// Extension bytes are not UTF-8.
    InvalidWireEncoding,
}

impl fmt::Display for TraceContextParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidTraceparent => "invalid W3C traceparent",
            Self::UnsupportedVersion => "unsupported W3C traceparent version",
            Self::InvalidHex => "invalid W3C hexadecimal field",
            Self::ZeroTraceId => "W3C trace id is all zeroes",
            Self::ZeroSpanId => "W3C span id is all zeroes",
            Self::InvalidTracestate => "invalid W3C tracestate",
            Self::InvalidWireEncoding => "trace context extension is not UTF-8",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for TraceContextParseError {}

/// Failure while attaching or extracting the registered sealed extension.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TraceContextError {
    /// The underlying Kernel context rejected the extension.
    Context(InvocationContextError),
    /// The selected target audience is empty or contains an empty identity.
    InvalidAudience,
    /// The extension was established by another issuer.
    IssuerMismatch { expected: String, actual: String },
    /// The extension proof does not match the registered issuer and payload.
    InvalidProof,
    /// The extension payload is not valid Trace Context.
    InvalidTraceContext(TraceContextParseError),
}

impl fmt::Display for TraceContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Context(error) => error.fmt(formatter),
            Self::InvalidAudience => formatter.write_str("trace-context audience is empty"),
            Self::IssuerMismatch { expected, actual } => {
                write!(
                    formatter,
                    "trace-context issuer `{actual}` is not `{expected}`"
                )
            }
            Self::InvalidProof => formatter.write_str("trace-context proof is invalid"),
            Self::InvalidTraceContext(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TraceContextError {}

impl From<InvocationContextError> for TraceContextError {
    fn from(error: InvocationContextError) -> Self {
        Self::Context(error)
    }
}

/// Registered issuer and verifier for one `OTel` trace-context extension.
#[derive(Clone)]
pub struct TraceContextPropagator {
    issuer: String,
    signing_key: Vec<u8>,
}

impl fmt::Debug for TraceContextPropagator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TraceContextPropagator")
            .field("issuer", &self.issuer)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl TraceContextPropagator {
    /// Registers one issuer provenance and its private proof key.
    pub fn new(
        issuer: impl Into<String>,
        signing_key: impl AsRef<[u8]>,
    ) -> Result<Self, TraceContextConfigError> {
        let issuer = issuer.into();
        if issuer.is_empty() {
            return Err(TraceContextConfigError::EmptyIssuer);
        }
        if signing_key.as_ref().is_empty() {
            return Err(TraceContextConfigError::EmptySigningKey);
        }
        Ok(Self {
            issuer,
            signing_key: signing_key.as_ref().to_vec(),
        })
    }

    /// Returns the registered issuer provenance name.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Attaches a target-scoped, sealed Trace Context without replacing an
    /// existing ordinary or sealed extension under the registered key.
    pub fn inject<I, S>(
        &self,
        context: InvocationContext,
        trace_context: &TraceContext,
        audience: I,
    ) -> Result<InvocationContext, TraceContextError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let audience: Vec<String> = audience.into_iter().map(Into::into).collect();
        if audience.is_empty() || audience.iter().any(String::is_empty) {
            return Err(TraceContextError::InvalidAudience);
        }
        let value = trace_context.to_bytes();
        let proof = self.proof(&audience, &value);
        context
            .with_sealed_extension(SealedInvocationExtension::signed(
                TRACE_CONTEXT_EXTENSION_KEY,
                self.issuer.clone(),
                audience,
                value,
                proof,
            ))
            .map_err(TraceContextError::Context)
    }

    /// Extracts the context only when the sealed audience covers one target.
    pub fn extract_for_target(
        &self,
        context: &InvocationContext,
        capability_id: &str,
        operation: &str,
    ) -> Result<Option<TraceContext>, TraceContextError> {
        let Some(extension) = context.sealed_extension(TRACE_CONTEXT_EXTENSION_KEY) else {
            return Ok(None);
        };
        if !extension.covers(capability_id, operation) {
            return Ok(None);
        }
        self.verify_extension(extension)
    }

    fn verify_extension(
        &self,
        extension: &SealedInvocationExtension,
    ) -> Result<Option<TraceContext>, TraceContextError> {
        if extension.issuer() != self.issuer {
            return Err(TraceContextError::IssuerMismatch {
                expected: self.issuer.clone(),
                actual: extension.issuer().to_owned(),
            });
        }
        let expected = self.proof(extension.audience(), extension.value());
        if !constant_time_eq(expected.as_bytes(), extension.proof().as_bytes()) {
            return Err(TraceContextError::InvalidProof);
        }
        TraceContext::from_bytes(extension.value())
            .map(Some)
            .map_err(TraceContextError::InvalidTraceContext)
    }

    fn proof(&self, audience: &[String], value: &[u8]) -> String {
        let payload = signing_payload(&self.issuer, audience, value);
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .expect("HMAC-SHA256 accepts every non-empty key");
        mac.update(&payload);
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }
}

fn signing_payload(issuer: &str, audience: &[String], value: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    append_length_prefixed(&mut payload, issuer.as_bytes());
    for audience in audience {
        append_length_prefixed(&mut payload, audience.as_bytes());
    }
    payload.extend_from_slice(&(value.len() as u64).to_be_bytes());
    payload.extend_from_slice(value);
    payload
}

fn append_length_prefixed(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(&(value.len() as u64).to_be_bytes());
    buffer.extend_from_slice(value);
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], TraceContextParseError> {
    if value.len() != N * 2 {
        return Err(TraceContextParseError::InvalidHex);
    }
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = hex_digit(value.as_bytes()[index * 2])?;
        let low = hex_digit(value.as_bytes()[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(bytes)
}

fn hex_digit(value: u8) -> Result<u8, TraceContextParseError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(TraceContextParseError::InvalidHex),
    }
}

fn encode_hex<const N: usize>(value: &[u8; N]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(N * 2);
    for byte in value {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn validate_tracestate(value: &str) -> Result<(), TraceContextParseError> {
    if value.is_empty()
        || value.len() > 512
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\n' || byte == b'\r' || byte == b'\t')
    {
        return Err(TraceContextParseError::InvalidTracestate);
    }
    Ok(())
}
