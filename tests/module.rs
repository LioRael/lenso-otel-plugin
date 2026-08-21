use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
    time::Duration,
};

use futures::future::LocalBoxFuture;
use lenso_app_plan::{AppComposition, ModuleInstancePlan, ResolvedAppPlan};
use lenso_app_plan::{CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan};
use lenso_kernel::{
    DeterministicDriver, Kernel, RuntimeDiagnostics, RuntimeDriver, ShutdownOutcome,
};
use lenso_native_adapter::{
    NativeModuleFactory, NativeModuleFactoryContext, NativeModuleInstance, NativeModuleRegistry,
};
use lenso_otel_module::{
    OTEL_MODULE_PACKAGE_ID, OTEL_TELEMETRY_CAPABILITY_ID, OTEL_TELEMETRY_DESCRIPTOR_VERSION,
    OTEL_TELEMETRY_OPERATION, OtelExportStats, OtelExporter, OtelLog, OtelModuleConfig,
    OtelModuleFactory, OtelSeverity, OtelSignal, OtelTelemetry, TelemetryAdmission,
};

const CALLER_PACKAGE_ID: &str = "test.otel-caller";

#[derive(Debug)]
struct NoopFactory;

impl NativeModuleFactory for NoopFactory {
    fn package_id(&self) -> &'static str {
        CALLER_PACKAGE_ID
    }

    fn instantiate(
        &self,
        _context: NativeModuleFactoryContext<'_>,
    ) -> Result<NativeModuleInstance, lenso_kernel::RuntimeFailure> {
        Ok(NativeModuleInstance::default())
    }
}

#[derive(Clone, Debug)]
struct RecordingExporter {
    signals: Rc<RefCell<Vec<OtelSignal>>>,
    fail: Rc<Cell<bool>>,
}

impl RecordingExporter {
    fn new() -> Self {
        Self {
            signals: Rc::new(RefCell::new(Vec::new())),
            fail: Rc::new(Cell::new(false)),
        }
    }

    fn signals(&self) -> Vec<OtelSignal> {
        self.signals.borrow().clone()
    }
}

impl OtelExporter for RecordingExporter {
    fn export(
        &self,
        signal: OtelSignal,
    ) -> LocalBoxFuture<'static, Result<(), lenso_otel_module::ExportError>> {
        let signals = self.signals.clone();
        let fail = self.fail.clone();
        Box::pin(async move {
            if fail.get() {
                return Err(lenso_otel_module::ExportError::Rejected);
            }
            signals.borrow_mut().push(signal);
            Ok(())
        })
    }
}

#[derive(Clone, Debug)]
struct PendingExporter;

impl OtelExporter for PendingExporter {
    fn export(
        &self,
        _signal: OtelSignal,
    ) -> LocalBoxFuture<'static, Result<(), lenso_otel_module::ExportError>> {
        Box::pin(futures::future::pending())
    }
}

fn plan() -> ResolvedAppPlan {
    AppComposition::new(
        vec![ModuleInstancePlan::new("otel", OTEL_MODULE_PACKAGE_ID)],
        Vec::new(),
    )
    .resolve()
    .expect("the diagnostics-only OTel Module plan should resolve")
}

fn telemetry_plan() -> ResolvedAppPlan {
    let caller = ModuleInstancePlan::new("caller", CALLER_PACKAGE_ID).with_requirement(
        CapabilityRequirementPlan::one(
            OTEL_TELEMETRY_CAPABILITY_ID,
            OTEL_TELEMETRY_DESCRIPTOR_VERSION,
        ),
    );
    let otel = ModuleInstancePlan::new("otel", OTEL_MODULE_PACKAGE_ID).with_capability(
        CapabilityEndpointPlan::new(
            OTEL_TELEMETRY_CAPABILITY_ID,
            OTEL_TELEMETRY_DESCRIPTOR_VERSION,
            [OTEL_TELEMETRY_OPERATION],
        ),
    );
    AppComposition::new(
        vec![caller, otel],
        vec![CapabilityBinding::new(
            "caller",
            OTEL_TELEMETRY_CAPABILITY_ID,
            OTEL_TELEMETRY_DESCRIPTOR_VERSION,
            "otel",
        )],
    )
    .resolve()
    .expect("the explicit telemetry Capability plan should resolve")
}

fn log_signal(body: &str) -> OtelSignal {
    OtelSignal::Log(OtelLog {
        timestamp: Duration::ZERO,
        severity: OtelSeverity::Info,
        body: body.to_owned(),
        attributes: BTreeMap::new(),
    })
}

fn start(
    driver: &DeterministicDriver,
    diagnostics: RuntimeDiagnostics,
    factory: OtelModuleFactory,
) -> lenso_kernel::NativeApp {
    driver
        .run(Kernel::start_native_with_diagnostics(
            plan(),
            driver.clone(),
            NativeModuleRegistry::new().with_factory(factory),
            diagnostics,
        ))
        .expect("the OTel Module must not gate App readiness")
}

fn start_with_telemetry_capability(
    driver: &DeterministicDriver,
    diagnostics: RuntimeDiagnostics,
    factory: OtelModuleFactory,
) -> lenso_kernel::NativeApp {
    driver
        .run(Kernel::start_native_with_diagnostics(
            telemetry_plan(),
            driver.clone(),
            NativeModuleRegistry::new()
                .with_factory(factory)
                .with_factory(NoopFactory),
            diagnostics,
        ))
        .expect("the explicit telemetry Capability must not gate App readiness")
}

#[test]
fn exporter_is_async_and_explicit_telemetry_does_not_gate_readiness() {
    let driver = DeterministicDriver::new();
    let diagnostics = RuntimeDiagnostics::new();
    let exporter = RecordingExporter::new();
    let factory = OtelModuleFactory::new(diagnostics.clone(), exporter.clone());
    let telemetry = factory.telemetry();
    let app = start(&driver, diagnostics, factory);

    assert!(app.is_ready());
    assert_eq!(
        telemetry.try_emit(log_signal("application.signal")),
        Ok(TelemetryAdmission::Accepted)
    );
    driver.run(driver.yield_now());

    let signals = exporter.signals();
    assert!(signals.iter().any(|signal| {
        matches!(signal, OtelSignal::Log(log) if log.body == "application.signal")
    }));
    assert!(signals.iter().any(|signal| {
        matches!(signal, OtelSignal::Log(log) if log.body == "lenso.runtime.diagnostic")
    }));
    assert_eq!(
        driver.run(app.shutdown(Duration::from_secs(1))),
        ShutdownOutcome::Clean
    );
}

#[test]
fn explicit_telemetry_capability_enqueues_through_a_declared_binding() {
    let driver = DeterministicDriver::new();
    let diagnostics = RuntimeDiagnostics::new();
    let exporter = RecordingExporter::new();
    let factory =
        OtelModuleFactory::new(diagnostics.clone(), exporter.clone()).with_telemetry_capability();
    let app = start_with_telemetry_capability(&driver, diagnostics, factory);

    let response = driver.run(app.invoke::<OtelTelemetry>(
        "caller",
        OTEL_TELEMETRY_OPERATION,
        log_signal("declared.capability"),
    ));
    assert!(matches!(
        response,
        Ok(Ok(response)) if response.admission == TelemetryAdmission::Accepted
    ));
    driver.run(driver.yield_now());
    assert!(exporter.signals().iter().any(|signal| {
        matches!(signal, OtelSignal::Log(log) if log.body == "declared.capability")
    }));
    assert_eq!(
        driver.run(app.shutdown(Duration::from_secs(1))),
        ShutdownOutcome::Clean
    );
}

#[test]
fn exporter_failures_are_isolated_from_app_terminal_outcomes() {
    let driver = DeterministicDriver::new();
    let diagnostics = RuntimeDiagnostics::new();
    let exporter = RecordingExporter::new();
    exporter.fail.set(true);
    let factory = OtelModuleFactory::new(diagnostics.clone(), exporter)
        .with_config(OtelModuleConfig::default().with_diagnostic_queue_capacity(2));
    let stats = factory.stats();
    let telemetry = factory.telemetry();
    let app = start(&driver, diagnostics, factory);
    assert!(app.is_ready());
    assert_eq!(
        telemetry.try_emit(log_signal("will.fail")),
        Ok(TelemetryAdmission::Accepted)
    );
    driver.run(driver.yield_now());
    assert!(stats.failed_count() > 0);
    assert!(!app.is_failed());
    assert_eq!(
        driver.run(app.shutdown(Duration::from_secs(1))),
        ShutdownOutcome::Clean
    );
}

#[test]
fn slow_exporter_drops_bounded_telemetry_and_shutdown_remains_bounded() {
    let driver = DeterministicDriver::new();
    let diagnostics = RuntimeDiagnostics::new();
    let factory = OtelModuleFactory::new(diagnostics.clone(), PendingExporter).with_config(
        OtelModuleConfig::default()
            .with_diagnostic_queue_capacity(1)
            .with_telemetry_queue_capacity(1),
    );
    let telemetry = factory.telemetry();
    let app = start(&driver, diagnostics, factory);

    assert!(app.is_ready());
    assert_eq!(
        telemetry.try_emit(log_signal("first")),
        Ok(TelemetryAdmission::Accepted)
    );
    assert_eq!(
        telemetry.try_emit(log_signal("second")),
        Ok(TelemetryAdmission::Dropped)
    );
    assert_eq!(telemetry.dropped_count(), 1);
    assert_eq!(
        driver.run(app.shutdown(Duration::from_secs(1))),
        ShutdownOutcome::Clean
    );
}

#[test]
fn exporter_stats_are_observable_without_becoming_runtime_diagnostics() {
    let stats = OtelExportStats::new();
    stats.record_exported();
    stats.record_failed();
    assert_eq!(stats.exported_count(), 1);
    assert_eq!(stats.failed_count(), 1);
}
