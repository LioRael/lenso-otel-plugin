use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use futures::future::LocalBoxFuture;
use lenso_kernel::{
    ActivateContext, DeactivateContext, DiagnosticFilter, DiagnosticObserver, InvocationContext,
    ModuleDependencies, ModuleFuture, ModuleLifecycle, NativeRequestEndpoint, NativeRequestHandle,
    RequestCapability, RuntimeDiagnostics, RuntimeFailure,
};
use lenso_native_adapter::{NativeModuleFactory, NativeModuleFactoryContext, NativeModuleInstance};

use crate::{
    OtelSignal,
    export::{
        GenerationTelemetry, OtelExportStats, OtelExporter, TelemetryAdmission, TelemetryError,
        TelemetryHandle, export_application_signals, export_diagnostics, validate_signal,
    },
};

/// Package identity for the optional OpenTelemetry Module.
pub const OTEL_MODULE_PACKAGE_ID: &str = "lenso.opentelemetry.module";

/// Capability identity for explicit application telemetry input.
pub const OTEL_TELEMETRY_CAPABILITY_ID: &str = "lenso.otel.telemetry@1";

/// Descriptor version for [`OtelTelemetry`].
pub const OTEL_TELEMETRY_DESCRIPTOR_VERSION: &str = "1.0.0";

/// Operation that accepts one explicit application signal.
pub const OTEL_TELEMETRY_OPERATION: &str = "emit";

/// Default Runtime Diagnostics queue capacity owned by one `OTel` Module generation.
pub const DEFAULT_DIAGNOSTIC_QUEUE_CAPACITY: usize = 256;

/// Default explicit application telemetry queue capacity.
pub const DEFAULT_TELEMETRY_QUEUE_CAPACITY: usize = 256;

/// `OTel` Runtime Diagnostics and application-signal selection.
#[derive(Clone, Debug)]
pub struct OtelModuleConfig {
    diagnostic_filter: DiagnosticFilter,
    diagnostic_queue_capacity: usize,
    telemetry_queue_capacity: usize,
}

impl OtelModuleConfig {
    /// Creates the default all-source, bounded `OTel` configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Selects which Kernel Diagnostic sources become `OTel` Logs.
    #[must_use]
    pub const fn with_diagnostic_filter(mut self, filter: DiagnosticFilter) -> Self {
        self.diagnostic_filter = filter;
        self
    }

    /// Sets the independently bounded Runtime Diagnostics queue.
    #[must_use]
    pub const fn with_diagnostic_queue_capacity(mut self, capacity: usize) -> Self {
        self.diagnostic_queue_capacity = normalize_capacity(capacity);
        self
    }

    /// Sets the independently bounded explicit application telemetry queue.
    #[must_use]
    pub const fn with_telemetry_queue_capacity(mut self, capacity: usize) -> Self {
        self.telemetry_queue_capacity = normalize_capacity(capacity);
        self
    }

    const fn diagnostic_filter(&self) -> DiagnosticFilter {
        self.diagnostic_filter
    }

    const fn diagnostic_queue_capacity(&self) -> usize {
        self.diagnostic_queue_capacity
    }

    const fn telemetry_queue_capacity(&self) -> usize {
        self.telemetry_queue_capacity
    }
}

impl Default for OtelModuleConfig {
    fn default() -> Self {
        Self {
            diagnostic_filter: DiagnosticFilter::all(),
            diagnostic_queue_capacity: DEFAULT_DIAGNOSTIC_QUEUE_CAPACITY,
            telemetry_queue_capacity: DEFAULT_TELEMETRY_QUEUE_CAPACITY,
        }
    }
}

const fn normalize_capacity(capacity: usize) -> usize {
    if capacity == 0 { 1 } else { capacity }
}

/// One response from the explicit application telemetry Capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetryResponse {
    /// Whether the signal entered the `OTel` Module queue.
    pub admission: TelemetryAdmission,
}

/// Error channel for the explicit application telemetry Capability client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TelemetryInvocationError {
    /// The signal was malformed according to the Module-owned input contract.
    Domain(TelemetryError),
    /// The Kernel or Adapter could not execute the Capability.
    Runtime(RuntimeFailure),
}

/// Marker for the local explicit application telemetry Capability.
#[derive(Debug)]
pub struct OtelTelemetry;

impl RequestCapability for OtelTelemetry {
    type Request = OtelSignal;
    type Response = TelemetryResponse;
    type DomainError = TelemetryError;
    const ID: &'static str = OTEL_TELEMETRY_CAPABILITY_ID;
    const DESCRIPTOR_VERSION: &'static str = OTEL_TELEMETRY_DESCRIPTOR_VERSION;
}

/// Typed client for explicit application telemetry.
#[derive(Debug)]
pub struct OtelTelemetryClient {
    handle: NativeRequestHandle<OtelTelemetry>,
}

impl OtelTelemetryClient {
    /// Creates a client from one explicitly bound Module dependency.
    pub fn new(handle: NativeRequestHandle<OtelTelemetry>) -> Self {
        Self { handle }
    }

    /// Resolves the one `OTel` telemetry dependency from Module lifecycle bindings.
    pub fn from_dependencies(dependencies: &ModuleDependencies) -> Result<Self, RuntimeFailure> {
        Ok(Self::new(dependencies.one::<OtelTelemetry>()?))
    }

    /// Enqueues one signal without waiting for exporter progress.
    pub async fn emit(
        &self,
        signal: OtelSignal,
    ) -> Result<TelemetryResponse, TelemetryInvocationError> {
        self.handle
            .invoke(OTEL_TELEMETRY_OPERATION, signal)
            .await
            .map_err(TelemetryInvocationError::Runtime)?
            .map_err(TelemetryInvocationError::Domain)
    }
}

/// Native Rust factory for the removable `OTel` Module.
#[derive(Debug)]
pub struct OtelModuleFactory {
    diagnostics: RuntimeDiagnostics,
    exporter: Rc<dyn OtelExporter>,
    config: OtelModuleConfig,
    telemetry_routes: RefCell<BTreeMap<String, TelemetryHandle>>,
    stats: OtelExportStats,
    expose_telemetry_capability: bool,
}

impl OtelModuleFactory {
    /// Creates a diagnostics/export Module with no required exporter behavior.
    pub fn new<E: OtelExporter>(diagnostics: RuntimeDiagnostics, exporter: E) -> Self {
        let config = OtelModuleConfig::default();
        Self {
            diagnostics,
            exporter: Rc::new(exporter),
            telemetry_routes: RefCell::new(BTreeMap::new()),
            stats: OtelExportStats::new(),
            config,
            expose_telemetry_capability: false,
        }
    }

    /// Applies Module-owned queue and source policy before the factory is linked.
    #[must_use]
    pub fn with_config(mut self, config: OtelModuleConfig) -> Self {
        self.config = config;
        self
    }

    /// Exposes the explicit application telemetry Capability in this Module plan.
    #[must_use]
    pub const fn with_telemetry_capability(mut self) -> Self {
        self.expose_telemetry_capability = true;
        self
    }

    /// Returns the stable host telemetry route for one App-local Module Instance.
    pub fn telemetry_for(&self, instance_key: impl Into<String>) -> TelemetryHandle {
        let instance_key = instance_key.into();
        self.telemetry_routes
            .borrow_mut()
            .entry(instance_key)
            .or_insert_with(TelemetryHandle::new)
            .clone()
    }

    /// Returns host-observed exporter outcomes aggregated across this factory's generations.
    pub fn stats(&self) -> OtelExportStats {
        self.stats.clone()
    }
}

impl NativeModuleFactory for OtelModuleFactory {
    fn package_id(&self) -> &'static str {
        OTEL_MODULE_PACKAGE_ID
    }

    fn instantiate(
        &self,
        context: NativeModuleFactoryContext<'_>,
    ) -> Result<NativeModuleInstance, RuntimeFailure> {
        let observer = self
            .diagnostics
            .subscribe(
                self.config.diagnostic_filter(),
                self.config.diagnostic_queue_capacity(),
            )
            .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
                detail: format!("OTel diagnostics observer could not be created: {error:?}"),
            })?;
        let telemetry = GenerationTelemetry::new(self.config.telemetry_queue_capacity());
        let host_telemetry = self.telemetry_for(context.instance_key());
        let lifecycle = OtelModuleLifecycle {
            observer: RefCell::new(Some(observer)),
            telemetry: telemetry.clone(),
            host_telemetry,
            exporter: self.exporter.clone(),
            stats: self.stats.clone(),
        };
        let endpoints = if self.expose_telemetry_capability {
            vec![Rc::new(OtelTelemetryEndpoint { telemetry }) as Rc<dyn NativeRequestEndpoint>]
        } else {
            Vec::new()
        };
        Ok(NativeModuleInstance::with_lifecycle(endpoints, lifecycle))
    }
}

#[derive(Debug)]
struct OtelModuleLifecycle {
    observer: RefCell<Option<DiagnosticObserver>>,
    telemetry: GenerationTelemetry,
    host_telemetry: TelemetryHandle,
    exporter: Rc<dyn OtelExporter>,
    stats: OtelExportStats,
}

impl ModuleLifecycle for OtelModuleLifecycle {
    fn activate(&self, context: ActivateContext) -> ModuleFuture {
        let observer = self.observer.borrow_mut().take();
        let telemetry = self.telemetry.clone();
        let host_telemetry = self.host_telemetry.clone();
        let exporter = self.exporter.clone();
        let stats = self.stats.clone();
        Box::pin(async move {
            let observer = observer.ok_or_else(|| RuntimeFailure::Internal {
                detail: "OTel diagnostics observer was activated twice".to_owned(),
            })?;
            let diagnostics_exporter = exporter.clone();
            let diagnostics_stats = stats.clone();
            let diagnostics_cancellation = context.cancellation();
            context
                .tasks()
                .spawn_local(Box::pin(async move {
                    export_diagnostics(
                        observer,
                        diagnostics_exporter,
                        diagnostics_stats,
                        diagnostics_cancellation,
                    )
                    .await;
                }))
                .map_err(|error| RuntimeFailure::Internal {
                    detail: format!("failed to schedule OTel diagnostics export: {error:?}"),
                })?;

            let telemetry_exporter = exporter;
            let telemetry_stats = stats;
            let telemetry_cancellation = context.cancellation();
            let telemetry_worker = telemetry.clone();
            context
                .tasks()
                .spawn_local(Box::pin(async move {
                    export_application_signals(
                        telemetry_worker,
                        telemetry_exporter,
                        telemetry_stats,
                        telemetry_cancellation,
                    )
                    .await;
                }))
                .map_err(|error| RuntimeFailure::Internal {
                    detail: format!("failed to schedule OTel application export: {error:?}"),
                })?;
            host_telemetry.activate(&telemetry);
            Ok(())
        })
    }

    fn deactivate(&self, _context: DeactivateContext) -> ModuleFuture {
        self.host_telemetry.deactivate(&self.telemetry);
        Box::pin(futures::future::ready(Ok(())))
    }
}

#[derive(Debug)]
struct OtelTelemetryEndpoint {
    telemetry: GenerationTelemetry,
}

impl NativeRequestEndpoint for OtelTelemetryEndpoint {
    fn capability_id(&self) -> &'static str {
        OTEL_TELEMETRY_CAPABILITY_ID
    }

    fn descriptor_version(&self) -> &'static str {
        OTEL_TELEMETRY_DESCRIPTOR_VERSION
    }

    fn operations(&self) -> &'static [&'static str] {
        &[OTEL_TELEMETRY_OPERATION]
    }

    fn invoke(
        &self,
        operation: &str,
        request: Box<dyn std::any::Any>,
        _context: InvocationContext,
    ) -> LocalBoxFuture<
        'static,
        Result<Result<Box<dyn std::any::Any>, Box<dyn std::any::Any>>, RuntimeFailure>,
    > {
        if operation != OTEL_TELEMETRY_OPERATION {
            return Box::pin(futures::future::ready(Err(
                RuntimeFailure::UnknownOperation {
                    capability: OTEL_TELEMETRY_CAPABILITY_ID,
                    operation: operation.to_owned(),
                },
            )));
        }
        let Ok(signal) = request.downcast::<OtelSignal>() else {
            return Box::pin(futures::future::ready(Err(
                RuntimeFailure::ProtocolViolation {
                    capability: OTEL_TELEMETRY_CAPABILITY_ID,
                },
            )));
        };
        let telemetry = self.telemetry.clone();
        Box::pin(async move {
            match validate_signal(&signal) {
                Ok(()) => Ok(Ok(Box::new(TelemetryResponse {
                    admission: telemetry.try_emit(*signal).expect("validated signal"),
                }) as Box<dyn std::any::Any>)),
                Err(error) => Ok(Err(Box::new(error) as Box<dyn std::any::Any>)),
            }
        })
    }
}
