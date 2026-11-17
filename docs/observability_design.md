# Optional retrieval-check observability: accepted v1 contract

Status: **Design accepted by the maintainer on 2026-11-16; not implemented.**
[#48](https://github.com/sahilmathur254/guardtrellis/issues/48) is the completed design
decision. Acceptance follows revision 2's re-review of the complete metadata allowlist,
the recipe-owned export boundary and interruption before scanning. Acceptance tests
inspect exported metric envelopes; trace spans are deferred. SDK behavior, dependencies
and the original examples remain unchanged. The current authorization covers acceptance,
issue/board updates and a separate implementation issue only; implementation, commit,
push, merge and publication are not authorized by this step.

Implementation: [#101](https://github.com/sahilmathur254/guardtrellis/issues/101),
Next / P2 / Ready; not started. `0.2.1` is a candidate, not a release commitment.

## Outcome and boundary

Observe the count, outcome and elapsed scan time of the existing checked tool-result handoff.
The named boundary is the synchronous `Stage.RETRIEVAL` scan after a tool returns and before
`require_text()` and consumption. Preserve `scan -> require_text -> consume`; never use raw
input as a fallback. Tool execution, authorization, consumption, telemetry export and callback
side effects remain outside the measured scan.

Use a sibling, application-owned example and guide. Leave the original handoff policy and
logging example unchanged. A separately packaged adapter adds a public compatibility surface
without a demonstrated caller gap; defer it. No new installed GuardTrellis API, core import,
scanner, default, exporter or network call is proposed.

Source placement: the [retrieval scan and checked consumption](../examples/tool_result_handoff.py)
at lines 117-123. Do not copy its request-ID/diagnostics logger into this recipe.
[`Result.diagnostics()`](../src/guardtrellis/models.py) includes offsets and scanner
metadata; it is not the telemetry attribute schema.

## Compatibility references and deliberate scope choice

Pin the reviewed design references to OpenTelemetry specification **v1.62.0**:

- [Specification release v1.62.0](https://github.com/open-telemetry/opentelemetry-specification/releases/tag/v1.62.0).
- [Metrics API](https://github.com/open-telemetry/opentelemetry-specification/blob/v1.62.0/specification/metrics/api.md).
- [Error handling](https://github.com/open-telemetry/opentelemetry-specification/blob/v1.62.0/specification/error-handling.md).

Record the reviewed GenAI snapshot at `0c87594975195608dc91b3f702e250a7b240c151`:
https://github.com/open-telemetry/semantic-conventions-genai/blob/0c87594975195608dc91b3f702e250a7b240c151/docs/README.md

Adopt **no `gen_ai.*` convention**. This scan is neither model inference nor tool execution.
These pins identify design references, not a claim of implementing the entire specification or
selecting Python package versions. Python dependency ranges must be chosen and tested separately
during implementation.

The accepted v1 is metrics-only. Trace spans introduce trace/span identifiers and more
ambient context. The accepted #48 design criterion is: **Define opt-in/disabled behavior, exporter
ownership/network destinations, failure/interruption behavior, and offline
exported-metric-envelope privacy tests covering Resource and instrumentation-scope metadata,
metric definitions, data-point attributes and empty exemplars.** This replaces
exported-span privacy tests for this scope. Completing this design criterion does not
mean the implementation tests have run. Spans and a reusable adapter remain later work.

Python behavior relevant to this revision was checked against released SDK `v1.45.2`:

- [Resource
  construction](https://github.com/open-telemetry/opentelemetry-python/blob/v1.45.2/opentelemetry-sdk/src/opentelemetry/sdk/resources/__init__.py#L199)
  runs default/environment detectors when using `Resource.create()`.
- [Provider
  defaults](https://github.com/open-telemetry/opentelemetry-python/blob/v1.45.2/opentelemetry-sdk/src/opentelemetry/sdk/metrics/_internal/__init__.py#L446)
  use that construction path when no Resource is supplied.
- [Meter scope
  construction](https://github.com/open-telemetry/opentelemetry-python/blob/v1.45.2/opentelemetry-sdk/src/opentelemetry/sdk/metrics/_internal/__init__.py#L622)
  includes name, version, schema URL and attributes in exported scope metadata.

This source pin is evidence for the design, not a chosen Python dependency minimum.

## Signals and cardinality

| Proposed custom instrument | Type | Unit | Exact description |
| --- | --- | --- | --- |
| `guardtrellis.checks` | Monotonic counter | `{check}` | `Number of retrieval scan attempts that completed or raised.` |
| `guardtrellis.check.duration` | Histogram | `s` | `Elapsed time of a retrieval scan attempt in seconds.` |

Only two fixed attribute keys:

- `stage`: the literal `retrieval`.
- `outcome`: exactly one of `allow`, `warn`, `redact`, `block`, `error`, `raised`, `interrupted`.

Each instrument has at most seven attribute combinations. This does not mean seven exported
histogram time series. Validate/map the SDK action to the finite enum; never stringify arbitrary
objects. Returned SDK ERROR is distinct from an exception raised by the operation. Aggregate
check counts are allowed; finding counts are not exported.

Exclude raw/checked text, replacements, arguments, tool names, field/document names, scanner
names, finding codes, exception text/types/stacks, offsets, lengths, finding counts, request
IDs, baggage, user attributes and content-capture fields. Do not flatten a result or diagnostics
dictionary.

## Disabled, enabled and failure behavior

Disabled is the default: perform the original scan exactly once, with no OpenTelemetry import,
instrument/provider construction, telemetry configuration read or timing call in that path.

Enabled: the application explicitly supplies preconfigured instruments/provider. Measure
scan time using a monotonic clock. Stop timing before recording metrics. The recipe
never explicitly calls collection, flush, shutdown or export on the handoff path, and
creates no automatic/background exporter. Arbitrary host-supplied instruments/providers
can perform synchronous work or export according to their configuration; the recipe
cannot make that configuration network-free. The controlled demonstration below has no
network exporter. There is no retry, alternate scan, deadline, async instrumentation or
new cancellation mechanism.

An ordinary `Exception` from timing or recording is an observability failure: suppress its
content, preserve the original scan result/exception and checked-delivery decision, and do not
fabricate timing values. On successful timing, record one counter increment and one duration
observation. On a clock/instrument fault, missing or partially recorded telemetry is allowed and
must be tested; metric writes are not transactional. Do not emit raw error logs or retry
recording.

A `KeyboardInterrupt`/`SystemExit` before the scan starts, including from the first timing
call, propagates unchanged: **zero scan calls, zero consumer calls and no scan metrics**.
Never run a scan to satisfy a call-count assertion after such an interruption. An
ordinary `Exception` from that initial timing call is different: still run the scan
exactly once, preserve its delivery decision and omit duration when timing is unavailable.

Once scanning starts, it is attempted exactly once. A `KeyboardInterrupt`/`SystemExit`
raised by the scan propagates after best-effort recording of the static `interrupted`
outcome. An already-pending scan exception must not be replaced by a timing/recording
failure, including a secondary interruption. If interruption occurs after the scan,
during timing or recording with no scan exception pending, propagate it and do not call
the consumer. Metric writes may already be partial; do not retry them.

| Event | Scan calls | Consumer calls | Required outcome |
| --- | ---: | ---: | --- |
| Initial clock raises ordinary `Exception` | 1 | Normal checked-delivery rule | Preserve scan result/exception; no duration sample without valid timing. |
| Initial clock raises `KeyboardInterrupt`/`SystemExit` | 0 | 0 | Propagate that same interruption; no scan metrics. |
| Scan returns ALLOW/WARN/REDACT | 1 | 1 | Pass exactly `require_text()` to the consumer. |
| Scan returns BLOCK/ERROR | 1 | 0 | Preserve rejection; no raw fallback. |
| Exception escapes the scan | 1 | 0 | Preserve exception identity; `raised`, or `interrupted` for `KeyboardInterrupt`/`SystemExit`, if recording succeeds. |
| Later clock/instrument raises ordinary `Exception` | 1 | Normal checked-delivery rule | Preserve the scan result/exception; partial or missing metrics are allowed. |
| Later clock/instrument interrupts without a pending scan exception | 1 | 0 | Propagate that interruption; do not consume. |
| Later clock/instrument fails with a pending scan exception | 1 | 0 | Re-raise the original scan exception, not the telemetry failure. |

Normal checked-delivery rules above assume no subsequent interruption and a successful
consumer callback. An ordinary scanner failure normally becomes a returned SDK ERROR;
exercise an exception escaping the scan separately when testing `raised`.

Instrumentation cannot guarantee zero latency impact or protect against a hanging host
implementation. Instruments, callbacks and provider/exporter configuration are trusted
application code; retain host timeouts and resource controls. No production performance claim
follows from this example.

## Ownership and complete exported-envelope privacy

The host owns provider, exporter, destinations, credentials, lifecycle, timeouts and shutdown.
The recipe must not set a global provider, discover a network exporter or enable automatic
instrumentation. Core GuardTrellis remains network-free.

The runnable demonstration uses only a real in-memory metrics reader/export path and
explicitly disabled exemplars. Its complete metadata allowlist is:

| Envelope field | Exact permitted value |
| --- | --- |
| Resource attributes | `{"service.name": "guardtrellis-observability-demo"}` only. |
| Resource schema URL | Empty; no schema URL is adopted. |
| Instrumentation-scope name | `guardtrellis.examples.tool_result_metrics` |
| Instrumentation-scope version | The string `"1"` (recipe schema revision, not SDK version). |
| Instrumentation-scope schema URL | Empty; no schema URL is adopted. |
| Instrumentation-scope attributes | Empty. |
| Metric definitions | Only the two exact names, types, units and descriptions in the instrument table above. |
| Data-point attribute keys | Exactly `stage` and `outcome`, with only the values defined above. |
| Exemplars | Empty on every data point; no exemplar attributes or trace/span IDs. |

Construct the demonstration's Resource directly from the one static attribute and pass
it explicitly to the provider. Do not use `Resource.create()`, omit the provider Resource,
run detectors, or merge a default/ambient Resource: those paths can read configuration,
create identifiers or log environment values before export. Do not temporarily edit the
process environment to suppress detection. Supply the fixed meter metadata explicitly
and disable exemplars through the SDK configuration rather than relying on environment
defaults.

An absent/`None`/empty representation is permitted only for fields defined as empty
(scope attributes and the two schema URLs); tests normalize those empty forms before
comparing the logical envelope. No nonempty value may be normalized away. SDK-generated
collection timestamps, aggregation temporality and numerical counter/histogram fields
are permitted structural data, not extra metadata attributes. Validate their types and
invariants; do not compare wall-clock values to fixed constants. A fault can leave either
instrument absent or partly recorded, but cannot introduce another instrument or attribute.

Assert exact metadata equality across the complete Resource/scope/metric/data-point/
exemplar envelope, in addition to searching for synthetic canaries. Unexpected keys,
scope metadata, metric definitions or nonempty exemplars fail acceptance even when they
contain no known canary. Check SDK behavior under each selected dependency profile.

The demonstration guarantees the tested exported envelope follows this allowlist.
With a host-supplied provider, the recipe guarantees only the fields it supplies; ambient
host Resource/scope data, auto-instrumentation and destinations are host-controlled.
Do not claim arbitrary application telemetry is payload-free.

## Implementation scope after contract acceptance

1. One source example/helper and one guide demonstrating the existing retrieval scan and checked
  handoff, with telemetry disabled by default.
2. An optional source-checkout dependency profile for the real Python metrics SDK and its tests,
  following existing repository dependency patterns. No mandatory/core dependency and no new
  installed package API. Record tested lower/current constrained profiles and the distinction
  between specification and Python distribution versions.
3. Focused offline regressions plus native CI integration on Windows, macOS and Linux; CodeQL
  and required package checks before any later merge decision.

## Acceptance checks

- With telemetry disabled/enabled and no interruption, ALLOW/WARN/REDACT preserve exact
  checked consumption and BLOCK/ERROR deliver nothing. The scan executes once. Test
  the original policy, not an unrequested policy change.
- Cover every row of the fault/interruption matrix. In particular, an interruption in
  the first timing call produces zero scans, zero consumption and no scan metrics;
  an ordinary timing exception still permits exactly one scan. Preserve pending scan
  exception identity and verify scan/consumer call history, not only exception type.
- A controlled monotonic clock proves scan-only duration boundaries and correct finite
  attribution; timing failure never creates a negative/non-finite or fabricated sample.
- Use a real in-memory MetricReader/exporter, not only mocked `record()` calls. Assert
  the complete metadata allowlist across Resource, instrumentation scope, metric
  definitions, data-point attributes and exemplars; validate numerical/time fields
  separately. Inspect the actual exported metric envelope, not just instrument inputs.
- Synthetic canaries in raw input, checked text, replacements, custom scanner metadata,
  exception text, environment Resource settings and active trace context never appear
  in the demonstration's exported metrics or captured logs. Exercise well-formed and
  malformed environment Resource settings in isolated test processes; construct no
  detector and mutate no shared process environment in the recipe. Empty exemplars,
  absent spans and no network calls are required for the controlled demonstration.
- Verify the recipe makes no explicit collection, flush, shutdown or export call in
  the handoff path. Do not generalize this to arbitrary host instrument/provider code.
- With optional packages absent, the disabled example still imports and runs; importing it
  creates no instruments or exporter and changes no global provider. Enabled setup failures are
  static and do not expose payloads.
- Run the relevant existing handoff regressions plus new recipe checks locally and in native
  Windows CI. Local macOS checks cannot substitute for native Windows evidence.

## Accepted decision and remaining gates

The maintainer accepted the metrics-only application recipe, complete exported-metric-envelope
allowlist, explicit fault/interruption policy and host-owned exporter boundary on
2026-11-16. #48 is complete as a design decision; the implementation is separately scoped
in [#101](https://github.com/sahilmathur254/guardtrellis/issues/101).
The acceptance and tracking request does not start implementation. Python dependency
constraints, runtime/privacy tests, native Windows and CodeQL evidence remain future
implementation gates. Any commit, push, merge or publication requires separate authorization.
Broader #45 independent review and unsupported detector coverage remain separate work.

## Revision 2 re-review

Codex-assisted source and design re-review found no remaining contract blockers after
all three corrections. The scope version is explicitly a string. This is a static
contract review: dependency-profile compatibility, the exported-envelope/privacy tests,
failure/interruption tests and native Windows execution still require implementation
evidence. Maintainer acceptance is recorded above; no SDK behavior or dependency changes
are made by this design closeout.
