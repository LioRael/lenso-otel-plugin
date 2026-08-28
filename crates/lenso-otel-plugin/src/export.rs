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
    /// A required name, span identity, or attribute key was empty or invalid.
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
        if !export_one(
            exporter.clone(),
            diagnostic_to_signal(&record),
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
    let valid_attributes = |attributes: &std::collections::BTreeMap<String, String>| {
        attributes.keys().all(|key| !key.is_empty())
    };
    let valid = match signal {
        OtelSignal::Span(span) => {
            !span.name.is_empty()
                && span.trace_context.span_id().iter().any(|byte| *byte != 0)
                && span.ended_at.is_none_or(|end| end >= span.started_at)
                && valid_attributes(&span.attributes)
        }
        OtelSignal::Metric(metric) => {
            !metric.name.is_empty()
                && metric.value.is_finite()
                && valid_attributes(&metric.attributes)
        }
        OtelSignal::Log(log) => !log.body.is_empty() && valid_attributes(&log.attributes),
    };
    valid.then_some(()).ok_or(TelemetryError::InvalidSignal)
}

#[cfg(test)]
mod tests {
    use super::{GenerationTelemetry, TelemetryHandle, TelemetryQueue};
    use crate::{OtelLog, OtelSeverity, OtelSignal};
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
}
