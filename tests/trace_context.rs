use lenso_kernel::{CancellationToken, InvocationContext, InvocationContextError};
use lenso_otel_module::{
    TRACE_CONTEXT_EXTENSION_KEY, TraceContext, TraceContextError, TraceContextPropagator,
};

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
    assert_eq!(propagator.extract(&context), Ok(Some(trace_context())));
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
        propagator.extract(&forged),
        Err(TraceContextError::IssuerMismatch { .. })
    ));
}
