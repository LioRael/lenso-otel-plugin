import { expect, test } from "bun:test";

import {
  extractTraceContext,
  injectTraceContext,
  TraceContextError,
} from "../../crates/lenso-otel-module/typescript/trace-context.ts";
import fixture from "./trace-context-conformance.json";

test("Rust and TypeScript share the sealed trace-context contract", async () => {
  const [extension] = await injectTraceContext(
    [],
    {
      traceparent: fixture.traceparent,
      tracestate: fixture.tracestate,
    },
    fixture.issuer,
    fixture.signing_key_utf8,
    fixture.audiences,
  );

  expect(extension.proof).toBe(fixture.proof);
  expect(
    await extractTraceContext(
      [extension],
      fixture.capability_id,
      fixture.operation,
      fixture.issuer,
      fixture.signing_key_utf8,
    ),
  ).toEqual({
    traceparent: fixture.traceparent,
    tracestate: fixture.tracestate,
  });
});

test("Rust and TypeScript reject the same invalid traceparents", async () => {
  for (const traceparent of fixture.invalid_traceparents) {
    await expect(
      injectTraceContext(
        [],
        { traceparent },
        fixture.issuer,
        fixture.signing_key_utf8,
        fixture.audiences,
      ),
    ).rejects.toBeInstanceOf(TraceContextError);
  }
});
