use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    fmt,
    rc::Rc,
    task::{Poll, Waker},
};

use futures::{
    FutureExt,
    future::{Either, LocalBoxFuture, poll_fn, select},
    pin_mut,
};
use lenso_kernel::{CancellationToken, DiagnosticObserver};

use crate::{OtelSignal, diagnostic_to_signal};

/// Maximum conservative encoded size of one queued `OTel` signal.
pub const MAX_OTEL_SIGNAL_ENCODED_BYTES: usize = 64 * 1024;
/// Maximum UTF-8 size of a span or metric name.
pub const MAX_OTEL_SIGNAL_NAME_BYTES: usize = 256;
/// Maximum UTF-8 size of a log body.
pub const MAX_OTEL_LOG_BODY_BYTES: usize = 16 * 1024;
/// Maximum UTF-8 size of a metric unit.
pub const MAX_OTEL_METRIC_UNIT_BYTES: usize = 128;
/// Maximum attribute cardinality on one signal.
pub const MAX_OTEL_ATTRIBUTES: usize = 64;
/// Maximum UTF-8 size of one attribute key.
pub const MAX_OTEL_ATTRIBUTE_KEY_BYTES: usize = 256;
/// Maximum UTF-8 size of one attribute value.
pub const MAX_OTEL_ATTRIBUTE_VALUE_BYTES: usize = 4 * 1024;

const MAX_TRACE_STATE_BYTES: usize = 512;
// Admission accounts for a conservative fixed structural envelope and an
// eight-byte length prefix per UTF-8 field. Exporter protocol framing is not
// retained in the in-process queue and remains exporter-owned.
const ENCODED_SIGNAL_FIXED_BYTES: usize = 64;
const ENCODED_STRING_OVERHEAD_BYTES: usize = 8;

/// Failure reported by an `OTel` exporter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportError {
    /// The exporter rejected a signal without changing App behavior.
    Rejected,
    /// The exporter is currently unavailable.
    Unavailable,
}

/// Exporter seam implemented by an OTLP, console, test, or host-specific Module Adapter.
pub trait OtelExporter: fmt::Debug + 'static {
    /// Exports one already-sanitized or explicitly authored `OTel` signal.
    fn export(&self, signal: OtelSignal) -> LocalBoxFuture<'static, Result<(), ExportError>>;
}

/// A no-op exporter useful for compositions that only need propagation.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopExporter;

impl OtelExporter for NoopExporter {
    fn export(&self, _signal: OtelSignal) -> LocalBoxFuture<'static, Result<(), ExportError>> {
        Box::pin(futures::future::ready(Ok(())))
    }
}

/// Admission result for one explicit application signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryAdmission {
    /// The signal entered the bounded `OTel` Module queue.
    Accepted,
    /// The queue was full and the signal was intentionally dropped.
    Dropped,
    /// The Module generation has closed its queue.
    Closed,
}

/// Invalid explicit application signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryError {
    /// A required field was invalid or the signal exceeded an admission bound.
    InvalidSignal,
}

/// Non-blocking handle for explicit application signals supplied by the host.
#[derive(Clone, Debug)]
pub struct TelemetryHandle {
    route: Rc<TelemetryRoute>,
}

impl TelemetryHandle {
    pub(crate) fn new() -> Self {
        Self {
            route: Rc::new(TelemetryRoute::default()),
        }
    }

    /// Attempts to enqueue a signal without awaiting exporter or queue progress.
    pub fn try_emit(&self, signal: OtelSignal) -> Result<TelemetryAdmission, TelemetryError> {
        validate_signal(&signal)?;
        Ok(self.route.enqueue(signal))
    }

    /// Returns drops recorded by the currently active generation, or zero while inactive.
    pub fn dropped_count(&self) -> u64 {
        self.route
            .active
            .borrow()
            .as_ref()
            .map_or(0, |queue| queue.dropped.get())
    }

    /// Returns pending signals for the currently active generation, or zero while inactive.
    pub fn pending_count(&self) -> usize {
        self.route
            .active
            .borrow()
            .as_ref()
            .map_or(0, |queue| queue.state.borrow().pending.len())
    }

    /// Returns the active generation's queue capacity, or zero while inactive.
    pub fn capacity(&self) -> usize {
        self.route
            .active
            .borrow()
            .as_ref()
            .map_or(0, |queue| queue.capacity)
    }

    pub(crate) fn activate(&self, generation: &GenerationTelemetry) {
        self.route.activate(generation.queue.clone());
    }

    pub(crate) fn deactivate(&self, generation: &GenerationTelemetry) {
        self.route.deactivate(&generation.queue);
    }
}

#[derive(Debug, Default)]
struct TelemetryRoute {
    active: RefCell<Option<Rc<TelemetryQueue>>>,
}

impl TelemetryRoute {
    fn enqueue(&self, signal: OtelSignal) -> TelemetryAdmission {
        self.active
            .borrow()
            .as_ref()
            .map_or(TelemetryAdmission::Closed, |queue| queue.enqueue(signal))
    }

    fn activate(&self, queue: Rc<TelemetryQueue>) {
        if let Some(previous) = self.active.replace(Some(queue)) {
            previous.close();
        }
    }

    fn deactivate(&self, queue: &Rc<TelemetryQueue>) {
        let mut active = self.active.borrow_mut();
        if active
            .as_ref()
            .is_some_and(|current| Rc::ptr_eq(current, queue))
        {
            active.take();
        }
        queue.close();
    }
}

#[derive(Clone, Debug)]
pub(crate) struct GenerationTelemetry {
    queue: Rc<TelemetryQueue>,
}

impl GenerationTelemetry {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            queue: Rc::new(TelemetryQueue::new(capacity)),
        }
    }

    pub(crate) fn try_emit(
        &self,
        signal: OtelSignal,
    ) -> Result<TelemetryAdmission, TelemetryError> {
        validate_signal(&signal)?;
        Ok(self.queue.enqueue(signal))
    }

    fn receive(&self) -> LocalBoxFuture<'static, Option<OtelSignal>> {
        TelemetryQueue::receive(self.queue.clone())
    }
}

#[derive(Debug)]
pub(crate) struct TelemetryQueue {
    capacity: usize,
    state: RefCell<TelemetryQueueState>,
    dropped: Cell<u64>,
    closed: Cell<bool>,
    receiver_waker: RefCell<Option<Waker>>,
}

#[derive(Debug, Default)]
struct TelemetryQueueState {
    pending: VecDeque<OtelSignal>,
}

impl TelemetryQueue {
    fn new(capacity: usize) -> Self {
        let capacity = normalize_capacity(capacity);
        Self {
            capacity,
            state: RefCell::new(TelemetryQueueState {
                pending: VecDeque::with_capacity(capacity),
            }),
            dropped: Cell::new(0),
            closed: Cell::new(false),
            receiver_waker: RefCell::new(None),
        }
    }

    fn enqueue(&self, signal: OtelSignal) -> TelemetryAdmission {
        if self.closed.get() {
            return TelemetryAdmission::Closed;
        }
        let mut state = self.state.borrow_mut();
        if state.pending.len() >= self.capacity {
            self.dropped.set(self.dropped.get().saturating_add(1));
            return TelemetryAdmission::Dropped;
        }
        state.pending.push_back(signal);
        drop(state);
        if let Some(waker) = self.receiver_waker.borrow_mut().take() {
            waker.wake();
        }
        TelemetryAdmission::Accepted
    }

    fn receive(queue: Rc<Self>) -> LocalBoxFuture<'static, Option<OtelSignal>> {
        Box::pin(poll_fn(move |context| {
            if let Some(signal) = queue.state.borrow_mut().pending.pop_front() {
                return Poll::Ready(Some(signal));
            }
            if queue.closed.get() {
                return Poll::Ready(None);
            }
            queue.receiver_waker.replace(Some(context.waker().clone()));
            if let Some(signal) = queue.state.borrow_mut().pending.pop_front() {
                queue.receiver_waker.borrow_mut().take();
                return Poll::Ready(Some(signal));
            }
            Poll::Pending
        }))
    }

    fn close(&self) {
        if self.closed.replace(true) {
            return;
        }
        if let Some(waker) = self.receiver_waker.borrow_mut().take() {
            waker.wake();
        }
    }
}

const fn normalize_capacity(capacity: usize) -> usize {
    if capacity == 0 { 1 } else { capacity }
}

/// Counts exporter outcomes without entering the Kernel diagnostic feed.
#[derive(Clone, Debug)]
pub struct OtelExportStats {
    state: Rc<OtelExportStatsState>,
}

#[derive(Debug, Default)]
struct OtelExportStatsState {
    exported: Cell<u64>,
    failed: Cell<u64>,
}

impl OtelExportStats {
    /// Creates empty exporter statistics.
    pub fn new() -> Self {
        Self {
            state: Rc::new(OtelExportStatsState::default()),
        }
    }

    /// Returns the number of signals accepted by the exporter.
    pub fn exported_count(&self) -> u64 {
        self.state.exported.get()
    }

    /// Returns the number of exporter failures or panics.
    pub fn failed_count(&self) -> u64 {
        self.state.failed.get()
    }

    /// Records one successful export.
    pub fn record_exported(&self) {
        self.state
            .exported
            .set(self.state.exported.get().saturating_add(1));
    }

    /// Records one failed or panicking export.
    pub fn record_failed(&self) {
        self.state
            .failed
            .set(self.state.failed.get().saturating_add(1));
    }
}

impl Default for OtelExportStats {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) async fn export_diagnostics(
    mut observer: DiagnosticObserver,
    exporter: Rc<dyn OtelExporter>,
    stats: OtelExportStats,
    cancellation: CancellationToken,
) {
    loop {
        let receive = observer.recv().fuse();
        let cancelled = cancellation.cancelled().fuse();
        pin_mut!(receive, cancelled);
        let record = match select(receive, cancelled).await {
            Either::Left((record, _)) => record,
            Either::Right(((), _)) => return,
        };
        let Some(record) = record else {
            return;
        };
        let signal = diagnostic_to_signal(&record);
        if validate_signal(&signal).is_err() {
            stats.record_failed();
            continue;
        }
        if !export_one(
            exporter.clone(),
            signal,
            stats.clone(),
            cancellation.clone(),
        )
        .await
        {
            return;
        }
    }
}

pub(crate) async fn export_application_signals(
    telemetry: GenerationTelemetry,
    exporter: Rc<dyn OtelExporter>,
    stats: OtelExportStats,
    cancellation: CancellationToken,
) {
    loop {
        let receive = telemetry.receive().fuse();
        let cancelled = cancellation.cancelled().fuse();
        pin_mut!(receive, cancelled);
        let signal = match select(receive, cancelled).await {
            Either::Left((signal, _)) => signal,
            Either::Right(((), _)) => return,
        };
        let Some(signal) = signal else {
            return;
        };
        if !export_one(
            exporter.clone(),
            signal,
            stats.clone(),
            cancellation.clone(),
        )
        .await
        {
            return;
        }
    }
}

async fn export_one(
    exporter: Rc<dyn OtelExporter>,
    signal: OtelSignal,
    stats: OtelExportStats,
    cancellation: CancellationToken,
) -> bool {
    let Ok(future) =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| exporter.export(signal)))
    else {
        stats.record_failed();
        return true;
    };
    let export = std::panic::AssertUnwindSafe(future).catch_unwind().fuse();
    let cancelled = cancellation.cancelled().fuse();
    pin_mut!(export, cancelled);
    match select(export, cancelled).await {
        Either::Left((result, _)) => match result {
            Ok(Ok(())) => stats.record_exported(),
            Ok(Err(_)) | Err(_) => stats.record_failed(),
        },
        Either::Right(((), _)) => return false,
    }
    true
}

pub(crate) fn validate_signal(signal: &OtelSignal) -> Result<(), TelemetryError> {
    validated_signal_encoded_size(signal).map(drop)
}

fn validated_signal_encoded_size(signal: &OtelSignal) -> Result<usize, TelemetryError> {
    let mut encoded_bytes = ENCODED_SIGNAL_FIXED_BYTES;
    let attributes = match signal {
        OtelSignal::Span(span) => {
            if span.trace_context.span_id().iter().all(|byte| *byte == 0)
                || span
                    .parent_span_id
                    .is_some_and(|parent| parent.iter().all(|byte| *byte == 0))
                || span.ended_at.is_some_and(|end| end < span.started_at)
            {
                return Err(TelemetryError::InvalidSignal);
            }
            add_text(
                &mut encoded_bytes,
                &span.name,
                MAX_OTEL_SIGNAL_NAME_BYTES,
                true,
            )?;
            if let Some(tracestate) = span.trace_context.tracestate() {
                add_text(&mut encoded_bytes, tracestate, MAX_TRACE_STATE_BYTES, true)?;
            }
            &span.attributes
        }
        OtelSignal::Metric(metric) => {
            if !metric.value.is_finite() {
                return Err(TelemetryError::InvalidSignal);
            }
            add_text(
                &mut encoded_bytes,
                &metric.name,
                MAX_OTEL_SIGNAL_NAME_BYTES,
                true,
            )?;
            if let Some(unit) = &metric.unit {
                add_text(&mut encoded_bytes, unit, MAX_OTEL_METRIC_UNIT_BYTES, true)?;
            }
            &metric.attributes
        }
        OtelSignal::Log(log) => {
            add_text(&mut encoded_bytes, &log.body, MAX_OTEL_LOG_BODY_BYTES, true)?;
            &log.attributes
        }
    };
    validate_attributes(&mut encoded_bytes, attributes)?;
    Ok(encoded_bytes)
}

fn validate_attributes(
    encoded_bytes: &mut usize,
    attributes: &std::collections::BTreeMap<String, String>,
) -> Result<(), TelemetryError> {
    if attributes.len() > MAX_OTEL_ATTRIBUTES {
        return Err(TelemetryError::InvalidSignal);
    }
    for (key, value) in attributes {
        add_text(encoded_bytes, key, MAX_OTEL_ATTRIBUTE_KEY_BYTES, true)?;
        add_text(encoded_bytes, value, MAX_OTEL_ATTRIBUTE_VALUE_BYTES, false)?;
    }
    Ok(())
}

fn add_text(
    encoded_bytes: &mut usize,
    value: &str,
    maximum_bytes: usize,
    required: bool,
) -> Result<(), TelemetryError> {
    if (required && value.is_empty()) || value.len() > maximum_bytes {
        return Err(TelemetryError::InvalidSignal);
    }
    *encoded_bytes = encoded_bytes
        .checked_add(ENCODED_STRING_OVERHEAD_BYTES)
        .and_then(|size| size.checked_add(value.len()))
        .filter(|size| *size <= MAX_OTEL_SIGNAL_ENCODED_BYTES)
        .ok_or(TelemetryError::InvalidSignal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ENCODED_STRING_OVERHEAD_BYTES, GenerationTelemetry, MAX_OTEL_ATTRIBUTE_KEY_BYTES,
        MAX_OTEL_ATTRIBUTE_VALUE_BYTES, MAX_OTEL_ATTRIBUTES, MAX_OTEL_LOG_BODY_BYTES,
        MAX_OTEL_METRIC_UNIT_BYTES, MAX_OTEL_SIGNAL_ENCODED_BYTES, MAX_OTEL_SIGNAL_NAME_BYTES,
        TelemetryHandle, TelemetryQueue, validated_signal_encoded_size,
    };
    use crate::{
        OtelLog, OtelMetric, OtelSeverity, OtelSignal, OtelSpan, TelemetryError, TraceContext,
    };
    use std::{collections::BTreeMap, time::Duration};

    #[test]
    fn queue_is_bounded_and_non_blocking() {
        let handle = TelemetryHandle::new();
        let generation = GenerationTelemetry::new(1);
        handle.activate(&generation);
        let signal = OtelSignal::Log(OtelLog {
            timestamp: Duration::ZERO,
            severity: OtelSeverity::Info,
            body: "test".to_owned(),
            attributes: BTreeMap::new(),
        });
        assert_eq!(
            handle.try_emit(signal.clone()),
            Ok(super::TelemetryAdmission::Accepted)
        );
        assert_eq!(
            handle.try_emit(signal),
            Ok(super::TelemetryAdmission::Dropped)
        );
        assert_eq!(handle.dropped_count(), 1);
        handle.deactivate(&generation);
        assert_eq!(
            handle.try_emit(OtelSignal::Log(OtelLog {
                timestamp: Duration::ZERO,
                severity: OtelSeverity::Info,
                body: "closed".to_owned(),
                attributes: BTreeMap::new(),
            })),
            Ok(super::TelemetryAdmission::Closed)
        );
        drop(TelemetryQueue::receive(generation.queue));
    }

    #[test]
    fn stable_route_replaces_and_closes_generations_safely() {
        let handle = TelemetryHandle::new();
        let first = GenerationTelemetry::new(2);
        let second = GenerationTelemetry::new(2);
        let signal = OtelSignal::Log(OtelLog {
            timestamp: Duration::ZERO,
            severity: OtelSeverity::Info,
            body: "generation".to_owned(),
            attributes: BTreeMap::new(),
        });

        assert_eq!(
            handle.try_emit(signal.clone()),
            Ok(super::TelemetryAdmission::Closed)
        );
        handle.activate(&first);
        assert_eq!(
            handle.try_emit(signal.clone()),
            Ok(super::TelemetryAdmission::Accepted)
        );
        handle.activate(&second);
        assert_eq!(
            first.try_emit(signal.clone()),
            Ok(super::TelemetryAdmission::Closed)
        );
        handle.deactivate(&first);
        assert_eq!(
            handle.try_emit(signal.clone()),
            Ok(super::TelemetryAdmission::Accepted)
        );
        handle.deactivate(&second);
        assert_eq!(
            handle.try_emit(signal),
            Ok(super::TelemetryAdmission::Closed)
        );
    }

    #[test]
    fn individual_signal_fields_and_attribute_cardinality_have_exact_bounds() {
        let span = |name: String| {
            OtelSignal::Span(OtelSpan {
                name,
                trace_context: trace_context(),
                parent_span_id: None,
                started_at: Duration::ZERO,
                ended_at: Some(Duration::ZERO),
                attributes: BTreeMap::new(),
            })
        };
        assert!(super::validate_signal(&span("n".repeat(MAX_OTEL_SIGNAL_NAME_BYTES))).is_ok());
        assert_eq!(
            super::validate_signal(&span("n".repeat(MAX_OTEL_SIGNAL_NAME_BYTES + 1))),
            Err(TelemetryError::InvalidSignal)
        );

        let mut metric = OtelMetric {
            name: "m".repeat(MAX_OTEL_SIGNAL_NAME_BYTES),
            value: 1.0,
            unit: Some("u".repeat(MAX_OTEL_METRIC_UNIT_BYTES)),
            timestamp: Duration::ZERO,
            attributes: BTreeMap::new(),
        };
        assert!(super::validate_signal(&OtelSignal::Metric(metric.clone())).is_ok());
        metric.unit = Some("u".repeat(MAX_OTEL_METRIC_UNIT_BYTES + 1));
        assert_eq!(
            super::validate_signal(&OtelSignal::Metric(metric)),
            Err(TelemetryError::InvalidSignal)
        );

        let mut attributes = (0..MAX_OTEL_ATTRIBUTES)
            .map(|index| (format!("key-{index}"), String::new()))
            .collect::<BTreeMap<_, _>>();
        assert!(super::validate_signal(&log("body", attributes.clone())).is_ok());
        attributes.insert("one-too-many".to_owned(), String::new());
        assert_eq!(
            super::validate_signal(&log("body", attributes)),
            Err(TelemetryError::InvalidSignal)
        );
    }

    #[test]
    fn body_attribute_and_aggregate_encoded_sizes_have_exact_bounds() {
        assert!(
            super::validate_signal(&log(&"b".repeat(MAX_OTEL_LOG_BODY_BYTES), BTreeMap::new()))
                .is_ok()
        );
        assert_eq!(
            super::validate_signal(&log(
                &"b".repeat(MAX_OTEL_LOG_BODY_BYTES + 1),
                BTreeMap::new(),
            )),
            Err(TelemetryError::InvalidSignal)
        );

        let attributes = BTreeMap::from([(
            "k".repeat(MAX_OTEL_ATTRIBUTE_KEY_BYTES),
            "v".repeat(MAX_OTEL_ATTRIBUTE_VALUE_BYTES),
        )]);
        assert!(super::validate_signal(&log("body", attributes.clone())).is_ok());
        let oversized_key =
            BTreeMap::from([("k".repeat(MAX_OTEL_ATTRIBUTE_KEY_BYTES + 1), String::new())]);
        assert_eq!(
            super::validate_signal(&log("body", oversized_key)),
            Err(TelemetryError::InvalidSignal)
        );
        let oversized_value = BTreeMap::from([(
            "key".to_owned(),
            "v".repeat(MAX_OTEL_ATTRIBUTE_VALUE_BYTES + 1),
        )]);
        assert_eq!(
            super::validate_signal(&log("body", oversized_value)),
            Err(TelemetryError::InvalidSignal)
        );

        let mut aggregate = log(&"b".repeat(MAX_OTEL_LOG_BODY_BYTES), BTreeMap::new());
        {
            let OtelSignal::Log(aggregate_log) = &mut aggregate else {
                unreachable!();
            };
            for index in 0..11 {
                aggregate_log.attributes.insert(
                    format!("k{index:02}"),
                    "v".repeat(MAX_OTEL_ATTRIBUTE_VALUE_BYTES),
                );
            }
        }
        let last_key = "k11";
        let current = validated_signal_encoded_size(&aggregate).unwrap();
        let last_value_bytes = MAX_OTEL_SIGNAL_ENCODED_BYTES
            - current
            - (ENCODED_STRING_OVERHEAD_BYTES * 2)
            - last_key.len();
        assert!(last_value_bytes <= MAX_OTEL_ATTRIBUTE_VALUE_BYTES);
        {
            let OtelSignal::Log(aggregate_log) = &mut aggregate else {
                unreachable!();
            };
            aggregate_log
                .attributes
                .insert(last_key.to_owned(), "v".repeat(last_value_bytes));
        }
        assert_eq!(
            validated_signal_encoded_size(&aggregate),
            Ok(MAX_OTEL_SIGNAL_ENCODED_BYTES)
        );
        {
            let OtelSignal::Log(aggregate_log) = &mut aggregate else {
                unreachable!();
            };
            aggregate_log
                .attributes
                .get_mut(last_key)
                .unwrap()
                .push('v');
        }
        assert_eq!(
            super::validate_signal(&aggregate),
            Err(TelemetryError::InvalidSignal)
        );
    }

    #[test]
    fn invalid_signal_is_rejected_before_it_enters_the_queue() {
        let handle = TelemetryHandle::new();
        let generation = GenerationTelemetry::new(1);
        handle.activate(&generation);
        assert_eq!(
            handle.try_emit(log(
                &"b".repeat(MAX_OTEL_LOG_BODY_BYTES + 1),
                BTreeMap::new(),
            )),
            Err(TelemetryError::InvalidSignal)
        );
        assert_eq!(handle.pending_count(), 0);
    }

    fn log(body: &str, attributes: BTreeMap<String, String>) -> OtelSignal {
        OtelSignal::Log(OtelLog {
            timestamp: Duration::ZERO,
            severity: OtelSeverity::Info,
            body: body.to_owned(),
            attributes,
        })
    }

    fn trace_context() -> TraceContext {
        TraceContext::from_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            None,
        )
        .unwrap()
    }
}
