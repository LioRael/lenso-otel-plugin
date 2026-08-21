use std::{any::Any, rc::Rc, time::Duration};

use futures::future::LocalBoxFuture;
use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    ModuleInstancePlan,
};
use lenso_kernel::{
    CancellationToken, DeterministicDriver, InvocationContext, InvocationContextError, Kernel,
    NativeRequestEndpoint, RequestCapability, RuntimeFailure, ShutdownOutcome,
};
use lenso_native_adapter::{
    NativeModuleFactory, NativeModuleFactoryContext, NativeModuleInstance, NativeModuleRegistry,
};
use lenso_otel_module::{
    TRACE_CONTEXT_EXTENSION_KEY, TraceContext, TraceContextError, TraceContextPropagator,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ConformanceFixture {
    issuer: String,
    signing_key_utf8: String,
    audiences: Vec<String>,
    capability_id: String,
    operation: String,
    traceparent: String,
    tracestate: String,
    proof: String,
    invalid_traceparents: Vec<String>,
}

fn conformance_fixture() -> ConformanceFixture {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/otel/trace-context-conformance.json");
    serde_json::from_slice(&std::fs::read(path).expect("trace fixture should be readable"))
        .expect("trace fixture should be valid JSON")
}

fn propagator() -> TraceContextPropagator {
    TraceContextPropagator::new("otel.fixture", b"trace-signing-key")
        .expect("fixture propagator should have a registered issuer")
}

fn trace_context() -> TraceContext {
    TraceContext::from_traceparent(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        Some("rojo=00f067aa0ba902b7"),
    )
    .expect("the W3C fixture should be valid")
}

#[test]
fn parses_and_round_trips_w3c_trace_context() {
    let trace = trace_context();

    assert_eq!(
        trace.traceparent(),
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    );
    assert_eq!(trace.tracestate(), Some("rojo=00f067aa0ba902b7"));
    assert_eq!(
        TraceContext::from_bytes(&trace.to_bytes()).expect("wire value should parse"),
        trace
    );
}

#[test]
fn injects_a_registered_sealed_extension_without_overwrite() {
    let propagator = propagator();
    let context = InvocationContext::new(7, None, CancellationToken::new());
    let context = propagator
        .inject(context, &trace_context(), ["example.greeting@1:greet"])
        .expect("trace context should attach");

    let extension = context
        .sealed_extension(TRACE_CONTEXT_EXTENSION_KEY)
        .expect("trace context should be sealed");
    assert_eq!(extension.issuer(), "otel.fixture");
    assert_eq!(
        extension.audience(),
        &["example.greeting@1:greet".to_owned()]
    );
    assert_eq!(
        propagator.extract_for_target(&context, "example.greeting@1", "greet"),
        Ok(Some(trace_context()))
    );
    assert!(matches!(
        propagator.inject(context, &trace_context(), ["example.greeting@1:greet"]),
        Err(TraceContextError::Context(
            InvocationContextError::SealedExtensionAlreadySet { .. }
        ))
    ));
}

#[test]
fn rejects_forged_issuer_or_proof_and_hides_uncovered_targets() {
    let propagator = propagator();
    let context = propagator
        .inject(
            InvocationContext::new(8, None, CancellationToken::new()),
            &trace_context(),
            ["example.greeting@1:greet"],
        )
        .expect("trace context should attach");

    assert_eq!(
        propagator.extract_for_target(&context, "example.other@1", "read"),
        Ok(None)
    );

    let forged = InvocationContext::new(9, None, CancellationToken::new())
        .with_sealed_extension(lenso_kernel::SealedInvocationExtension::signed(
            TRACE_CONTEXT_EXTENSION_KEY,
            "attacker",
            ["example.greeting@1:greet"],
            trace_context().to_bytes(),
            "forged-proof",
        ))
        .expect("the Kernel preserves a structurally valid sealed extension");
    assert!(matches!(
        propagator.extract_for_target(&forged, "example.greeting@1", "greet"),
        Err(TraceContextError::IssuerMismatch { .. })
    ));
}

#[test]
fn matches_the_shared_rust_typescript_trace_contract() {
    let fixture = conformance_fixture();
    let propagator =
        TraceContextPropagator::new(&fixture.issuer, fixture.signing_key_utf8.as_bytes())
            .expect("fixture propagator should be configured");
    let trace = TraceContext::from_traceparent(&fixture.traceparent, Some(&fixture.tracestate))
        .expect("fixture trace should parse");
    let context = propagator
        .inject(
            InvocationContext::new(10, None, CancellationToken::new()),
            &trace,
            fixture.audiences,
        )
        .expect("fixture trace should be sealed");
    let extension = context
        .sealed_extension(TRACE_CONTEXT_EXTENSION_KEY)
        .expect("fixture trace extension should exist");
    assert_eq!(extension.proof(), fixture.proof);
    assert_eq!(
        propagator.extract_for_target(&context, &fixture.capability_id, &fixture.operation),
        Ok(Some(trace))
    );
    for invalid in fixture.invalid_traceparents {
        assert!(TraceContext::from_traceparent(&invalid, None).is_err());
    }
}

const NATIVE_TRACE_CAPABILITY_ID: &str = "test.native-trace@1";
const NATIVE_TRACE_OPERATION: &str = "read";

#[derive(Debug)]
struct NativeTrace;

impl RequestCapability for NativeTrace {
    type Request = ();
    type Response = TraceContext;
    type DomainError = ();

    const ID: &'static str = NATIVE_TRACE_CAPABILITY_ID;
    const DESCRIPTOR_VERSION: &'static str = "1.0.0";
}

#[derive(Debug)]
struct NativeTraceEndpoint {
    propagator: TraceContextPropagator,
}

impl NativeRequestEndpoint for NativeTraceEndpoint {
    fn capability_id(&self) -> &'static str {
        NATIVE_TRACE_CAPABILITY_ID
    }

    fn descriptor_version(&self) -> &'static str {
        NativeTrace::DESCRIPTOR_VERSION
    }

    fn operations(&self) -> &'static [&'static str] {
        &[NATIVE_TRACE_OPERATION]
    }

    fn invoke(
        &self,
        operation: &str,
        request: Box<dyn Any>,
        context: InvocationContext,
    ) -> LocalBoxFuture<'static, Result<Result<Box<dyn Any>, Box<dyn Any>>, RuntimeFailure>> {
        if operation != NATIVE_TRACE_OPERATION {
            return Box::pin(futures::future::ready(Err(
                RuntimeFailure::UnknownOperation {
                    capability: NATIVE_TRACE_CAPABILITY_ID,
                    operation: operation.to_owned(),
                },
            )));
        }
        if request.downcast::<()>().is_err() {
            return Box::pin(futures::future::ready(Err(
                RuntimeFailure::ProtocolViolation {
                    capability: NATIVE_TRACE_CAPABILITY_ID,
                },
            )));
        }
        let result = self.propagator.extract_for_target(
            &context,
            NATIVE_TRACE_CAPABILITY_ID,
            NATIVE_TRACE_OPERATION,
        );
        Box::pin(futures::future::ready(match result {
            Ok(Some(trace)) => Ok(Ok(Box::new(trace) as Box<dyn Any>)),
            Ok(None) | Err(_) => Err(RuntimeFailure::ProtocolViolation {
                capability: NATIVE_TRACE_CAPABILITY_ID,
            }),
        }))
    }
}

#[derive(Debug)]
struct NativeTraceFactory {
    package_id: &'static str,
    propagator: Option<TraceContextPropagator>,
}

impl NativeModuleFactory for NativeTraceFactory {
    fn package_id(&self) -> &'static str {
        self.package_id
    }

    fn instantiate(
        &self,
        _context: NativeModuleFactoryContext<'_>,
    ) -> Result<NativeModuleInstance, RuntimeFailure> {
        let endpoints = self
            .propagator
            .as_ref()
            .map_or_else(Vec::new, |propagator| {
                vec![Rc::new(NativeTraceEndpoint {
                    propagator: propagator.clone(),
                }) as Rc<dyn NativeRequestEndpoint>]
            });
        Ok(NativeModuleInstance::new(endpoints))
    }
}

#[test]
fn native_adapter_preserves_and_filters_sealed_trace_context() {
    let driver = DeterministicDriver::new();
    let propagator = propagator();
    let caller = ModuleInstancePlan::new("caller", "test.native-trace-caller").with_requirement(
        CapabilityRequirementPlan::one(NATIVE_TRACE_CAPABILITY_ID, NativeTrace::DESCRIPTOR_VERSION),
    );
    let provider = ModuleInstancePlan::new("provider", "test.native-trace-provider")
        .with_capability(CapabilityEndpointPlan::new(
            NATIVE_TRACE_CAPABILITY_ID,
            NativeTrace::DESCRIPTOR_VERSION,
            [NATIVE_TRACE_OPERATION],
        ));
    let plan = AppComposition::new(
        vec![caller, provider],
        vec![CapabilityBinding::new(
            "caller",
            NATIVE_TRACE_CAPABILITY_ID,
            NativeTrace::DESCRIPTOR_VERSION,
            "provider",
        )],
    )
    .resolve()
    .expect("native trace plan should resolve");
    let app = driver
        .run(Kernel::start_native(
            plan,
            driver.clone(),
            NativeModuleRegistry::new()
                .with_factory(NativeTraceFactory {
                    package_id: "test.native-trace-caller",
                    propagator: None,
                })
                .with_factory(NativeTraceFactory {
                    package_id: "test.native-trace-provider",
                    propagator: Some(propagator.clone()),
                }),
        ))
        .expect("native trace App should start");
    let trace = trace_context();
    let context = propagator
        .inject(
            InvocationContext::new(20, None, CancellationToken::new()),
            &trace,
            [format!(
                "{NATIVE_TRACE_CAPABILITY_ID}:{NATIVE_TRACE_OPERATION}"
            )],
        )
        .expect("native target trace should seal");
    assert_eq!(
        driver.run(app.invoke_with_context::<NativeTrace>(
            "caller",
            NATIVE_TRACE_OPERATION,
            context,
            (),
        )),
        Ok(Ok(trace))
    );

    let uncovered = propagator
        .inject(
            InvocationContext::new(21, None, CancellationToken::new()),
            &trace_context(),
            ["test.other@1:read"],
        )
        .expect("uncovered trace should still be structurally valid");
    assert!(matches!(
        driver.run(app.invoke_with_context::<NativeTrace>(
            "caller",
            NATIVE_TRACE_OPERATION,
            uncovered,
            (),
        )),
        Err(RuntimeFailure::ProtocolViolation { .. })
    ));
    assert_eq!(
        driver.run(app.shutdown(Duration::from_secs(1))),
        ShutdownOutcome::Clean
    );
}
