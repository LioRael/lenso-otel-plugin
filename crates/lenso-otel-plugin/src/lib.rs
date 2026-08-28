//! Optional OpenTelemetry propagation and export Module for Lenso vNext.

mod export;
mod plugin;
mod signal;
mod trace;

pub use export::{
    ExportError, NoopExporter, OtelExportStats, OtelExporter, TelemetryAdmission, TelemetryError,
    TelemetryHandle,
};
pub use plugin::{
    DEFAULT_DIAGNOSTIC_QUEUE_CAPACITY, DEFAULT_TELEMETRY_QUEUE_CAPACITY, OTEL_PLUGIN_PACKAGE_ID,
    OTEL_TELEMETRY_CAPABILITY_ID, OTEL_TELEMETRY_DESCRIPTOR_VERSION, OTEL_TELEMETRY_OPERATION,
    OtelPluginConfig, OtelPluginFactory, OtelTelemetry, OtelTelemetryClient,
    TelemetryInvocationError, TelemetryResponse,
};
pub use signal::{OtelLog, OtelMetric, OtelSeverity, OtelSignal, OtelSpan, diagnostic_to_signal};
pub use trace::{
    DEFAULT_TRACE_CONTEXT_ISSUER, TRACE_CONTEXT_EXTENSION_KEY, TraceContext,
    TraceContextConfigError, TraceContextError, TraceContextParseError, TraceContextPropagator,
};
