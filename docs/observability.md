# Optional metrics for a checked tool-result handoff

The [source recipe](../examples/tool_result_metrics.py) observes the count, outcome and
elapsed scan time of the synchronous `Stage.RETRIEVAL` check after a tool returns. It
preserves `scan -> require_text -> consume`: only the checked text reaches the next
consumer. Tool execution, authorization, `require_text()`, consumption and telemetry
recording are outside the measured scan.

This is an application-owned sibling of the [tool-result handoff](tool_result_handoff.md),
using the existing public GuardTrellis APIs. It adds no installed SDK API, scanner,
default, automatic interception or provider integration. The accepted
[#48 contract](observability_design.md) records the design;
[#101](https://github.com/sahilmathur254/guardtrellis/issues/101) completed through
[PR #103](https://github.com/sahilmathur254/guardtrellis/pull/103) on 2026-11-17.
The recipe is merged source work after the `0.2.0` release. It can contribute to a possible
`0.2.1` batch, with no version-bump or publication commitment. See
[verification status](#verification-status).

## Start with telemetry disabled

Run from a source checkout with core dependencies:

```sh
uv sync --frozen --group dev
uv run --frozen python examples/tool_result_metrics.py
```

`scan_and_consume(raw_return, consume, *, result_guard=RETURN_POLICY, instruments=None,
clock=perf_counter)` returns the checked string after calling `consume` with that same
string. With `instruments=None`, it performs no OpenTelemetry imports, instrument/provider
construction, telemetry-configuration reads or clock calls. No optional telemetry package
is required on that path.

The original policy is retained: a 2,000-character bound, selected secret signatures,
the fixed application marker `internal-only`, then the built-in PII policy. Blockers
precede redaction so a redactor cannot erase the marker before it is checked. This
does not change detector coverage or interpret instruction meaning. Configure a trusted
`result_guard` explicitly when a different retrieval policy is needed.

`ALLOW`, `WARN` and `REDACT` deliver exactly `require_text()` to the consumer. `BLOCK`
and returned SDK `ERROR` raise `Rejected` and do not call the consumer. No branch retries
the scan or falls back to the raw return. The helper covers only this returned-text
boundary; keep host authorization and tool validation before execution, and route every
downstream raw-return path through the check.

## Enable the controlled in-memory demonstration

The `observability` dependency group is a source-checkout option, separate from published
package extras and mandatory dependencies:

```sh
uv sync --frozen --group dev --group observability
uv run --frozen --group observability python examples/tool_result_metrics.py --metrics
```

This opts into the Python OpenTelemetry metrics API and SDK. It does not provide a
`guardtrellis[observability]` extra or install the recipe as a new SDK module. The
demonstration uses a real in-memory metrics reader, prints its exported metric envelope,
and creates no network exporter or trace span. It does not need credentials.

Applications explicitly supply their instruments through `Metrics(checks=counter,
duration=histogram)`. The recipe does not discover or set a global provider. For example,
from the repository root:

```python
from examples.tool_result_metrics import create_demo_metrics, scan_and_consume

telemetry = create_demo_metrics()
state = []
try:
    checked = scan_and_consume(
        "Contact demo@example.org",
        state.append,
        instruments=telemetry.instruments,
    )
    assert state == [checked] == ["Contact [PII]"]
    # Collection is the caller's step, after the checked handoff has returned.
    exported = telemetry.reader.get_metrics_data()
    assert exported is not None
    print(exported.to_json())
finally:
    # Lifecycle also belongs to the caller, outside the handoff path.
    telemetry.provider.shutdown()
```

Ordinary `create_demo_metrics()` setup failures raise the fixed-message
`RuntimeError("Metrics demonstration setup failed")`; exception contents are not displayed
as the setup error. Initial setup and its cleanup happen outside the checked handoff.

Dependency installation can download packages. The recipe and controlled runtime probes
make no provider, database or network-exporter calls; the profile probes forbid sockets.
An arbitrary application-supplied instrument/provider can do synchronous work or send
data according to its configuration. This example cannot make host configuration
network-free or protect against a hanging instrument implementation.

## The complete exported schema

The two custom instruments describe a retrieval check, not model inference or tool
execution. No `gen_ai.*` semantic convention is adopted.

| Instrument | Type | Unit | Exact description |
| --- | --- | --- | --- |
| `guardtrellis.checks` | Monotonic counter | `{check}` | `Number of retrieval scan attempts that completed or raised.` |
| `guardtrellis.check.duration` | Histogram | `s` | `Elapsed time of a retrieval scan attempt in seconds.` |

Each data point has exactly these two attributes:

- `stage`: the literal `retrieval`.
- `outcome`: one of `allow`, `warn`, `redact`, `block`, `error`, `raised`, `interrupted`.

The helper maps SDK actions to these fixed values. A returned SDK `ERROR` is `error`;
an exception escaping the scan is `raised`, or `interrupted` for `KeyboardInterrupt` or
`SystemExit`. An ordinary scanner exception normally becomes a returned SDK `ERROR`.
There are at most seven attribute combinations per instrument, not seven histogram
time series. The counter measures scan attempts, not findings.

The controlled demonstration's complete metadata allowlist is:

| Envelope field | Permitted value |
| --- | --- |
| Resource attributes | Only `{"service.name": "guardtrellis-observability-demo"}`. |
| Resource schema URL | Empty. |
| Instrumentation-scope name | `guardtrellis.examples.tool_result_metrics`. |
| Instrumentation-scope version | The string `"1"`, identifying the recipe schema revision. |
| Instrumentation-scope schema URL and attributes | Empty. |
| Metric definitions | Only the two exact names, types, units and descriptions above. |
| Data-point attributes | Exactly the fixed `stage` and finite `outcome` values above. |
| Exemplars | Empty for every data point; no trace/span IDs or exemplar attributes. |

The demonstration directly constructs the fixed Resource and passes it explicitly to
the provider. It uses neither `Resource.create()` nor ambient/default Resource merging
or detectors. Meter metadata is explicit, and exemplars are disabled through SDK
configuration. The recipe does not rewrite the process environment to hide resource
configuration.

Absent, `None` and empty representations may be normalized only for fields defined as
empty. Nonempty values cannot be discarded by normalization. Collection timestamps,
aggregation temporality and numerical counter/histogram fields are permitted structural
data; their types and invariants are checked separately from the metadata allowlist.
Healthy exports must contain both expected instruments and the expected counts/duration;
an empty reader cannot establish privacy correctness.

No raw or checked text, replacements, tool arguments/names, document/field names, scanner
names, finding codes/counts, exception details, offsets, lengths, request IDs, baggage or
user attributes are supplied to metrics. Do not copy the original handoff example's
request-ID/diagnostics logger or flatten `Result.diagnostics()` into attributes.

The complete exported-envelope guarantee applies to the controlled demonstration and
tested profiles. With arbitrary host instruments, the recipe controls only the fields
it supplies. Host Resource/scope metadata, automatic instrumentation, credentials,
destinations and retention remain host-owned; arbitrary application telemetry is not
guaranteed payload-free.

## Timing, failures and interruptions

Enabled timing uses a monotonic clock around only the scan. Timing stops before metric
recording, checked consumption or consumer execution. Invalid, negative or non-finite
elapsed samples are omitted instead of fabricated. A healthy scan attempt produces one
counter increment and one duration observation.

| Event | Scan calls | Consumer calls | Behavior |
| --- | ---: | ---: | --- |
| Initial clock raises an ordinary `Exception` | 1 | Normal checked-delivery rule | Preserve the scan result/exception; omit duration without valid timing. |
| Initial clock raises `KeyboardInterrupt`/`SystemExit` | 0 | 0 | Propagate that same interruption; record no scan metrics. |
| Scan returns ALLOW/WARN/REDACT | 1 | 1 | Pass exactly `require_text()` to the consumer. |
| Scan returns BLOCK/ERROR | 1 | 0 | Preserve rejection; never use raw text as a fallback. |
| An exception escapes the scan | 1 | 0 | Preserve its identity; best-effort `raised`/`interrupted` metrics. |
| Later clock/instrument raises an ordinary `Exception` | 1 | Normal checked-delivery rule | Preserve the scan result/exception; missing or partial telemetry is allowed. |
| Later clock/instrument interrupts without a pending scan exception | 1 | 0 | Propagate the interruption; do not consume. |
| Later clock/instrument fails with a pending scan exception | 1 | 0 | Re-raise the original scan exception, including when the secondary failure interrupts. |

The recipe suppresses ordinary timing/recording failures without logging their contents
or retrying recording.
Counter and histogram writes are not transactional: either can be absent or partially
recorded after a fault. The helper does not call collection, flush, shutdown or export
on the handoff path and creates no automatic/background exporter.

The delivery rules assume no subsequent interruption and a successful consumer callback.
A consumer can have side effects before raising; metrics do not undo those effects.
Consumer exceptions remain caller-owned and propagate from this helper. Host instruments
and callbacks remain trusted application code. Keep host deadlines,
timeouts and resource controls; no zero-overhead or production performance claim follows
from this recipe.

## Verification status

The source group declares OpenTelemetry API/SDK bounds `>=1.45.2,<2`.
The SDK's API constraint must be resolved as a compatible pair. This Python-package
floor is separate from the accepted design's pinned specification `v1.62.0` and GenAI
reference snapshot. The minimum profile pins the declared pair; the locked profile
constrains the selected closure from `uv.lock`. The initial minimum and locked profiles
both select API `1.45.2`, SDK `1.45.2` and semantic conventions `0.66b2`. They run in
separate fresh environments and report their actual versions; these initial profiles
do not establish compatibility across the entire declared range.

```sh
uv run --frozen python scripts/check_observability_profile.py --profile disabled
uv run --frozen python scripts/check_observability_profile.py --profile minimum --regressions
uv run --frozen python scripts/check_observability_profile.py --profile locked --regressions
uv run --frozen --group observability pytest tests/test_tool_result_metrics.py
uv run --frozen --group observability mypy examples/tool_result_metrics.py
```

The enabled profile commands run the focused regressions inside each fresh environment
after its consumer-isolation checks. The disabled profile deliberately installs no test
tooling.

The disabled profile proves import and checked delivery with OpenTelemetry absent.
The enabled profiles inspect real SDK exports, not only mocked `add()`/`record()` calls.
Envelope privacy checks cover every Resource/scope/metric/data-point/exemplar field,
synthetic canaries, captured logs, active trace context and well-formed/malformed Resource
environment settings in isolated processes. They forbid network access in the runtime
probe. Existing handoff regressions keep the original policy and checked-delivery path
in scope. See [focused regressions](../tests/test_tool_result_metrics.py) and the
[profile checker](../scripts/check_observability_profile.py).

#101 is complete through merged PR #103. The local validation record and the later
exact-merge native evidence below retain their separate source/platform scopes. An
all-extras run or a skipped optional test does not establish the disabled profile, and
local macOS cannot establish Windows success. Future changes need their own native CI,
Python/Actions CodeQL and required package checks. Package publication has a separate
approval gate; this source contribution preserves SDK behavior and version.

### Local validation — 2026-11-17

These local results were recorded for the #101 working tree based on
`0e1a162225c7aacaca0bbf96a1f868e3777fa7a3`, on macOS with Python `3.12.0`.

| Check | Observed result |
| --- | --- |
| Full repository tests with warnings treated as errors | 2,128 passed; no skips. |
| Focused recipe and profile regressions | 141 passed; no skips: 119 recipe cases and 22 profile cases. |
| Fresh disabled profile | Passed with the OpenTelemetry namespace absent; import, checked delivery and no telemetry-config/clock access were verified. |
| Fresh minimum and locked profiles | Each passed all 119 recipe regressions without skips, plus real exported-envelope probes in isolated empty, well-formed and malformed Resource environments. |
| Actual enabled profile versions | Both selected API `1.45.2`, SDK `1.45.2` and semantic conventions `0.66b2`; actual versions were asserted before and after regression tooling. |
| Existing evaluations | All 14 existing CI evaluation commands completed successfully; historical detector limitations remain recorded rather than converted into accuracy claims. |
| Lint, formatting, types and workflow syntax | Ruff lint and formatting of all 151 files, all four CI mypy scopes and actionlint passed. |
| Lock and version agreement | `uv lock --check --offline` and release-version agreement for unchanged `0.2.0` passed. |
| Packaging | Wheel and source archive passed strict metadata checks and fresh core-only, OpenAI-only, all-extras and Gemini-only locked installation smokes. Provider requests were mocked. |

These local results are separate from the subsequent native evidence below. Fresh
profiles with the same initial package versions do not establish compatibility across
the entire declared version range.

### Merge and native CI evidence — 2026-11-17

[PR #103](https://github.com/sahilmathur254/guardtrellis/pull/103) merged as
`c6e9b84cf377ac3f2c9596c2770909964f5ea680`; #101 is completed. The
[post-merge native matrix](https://github.com/sahilmathur254/guardtrellis/actions/runs/44089985507)
passed all six jobs on that exact main revision: Linux Python 3.11–3.14 and macOS/Windows
Python 3.12. Windows passed 2,048 tests with 80 expected platform skips; its fresh minimum
and locked observability profiles each passed all 119 focused regressions without skips.
The 14 existing evaluation commands and wheel/source-archive installation checks also passed.

[Python and Actions CodeQL](https://github.com/sahilmathur254/guardtrellis/actions/runs/44089985635)
completed with actual processed analyses on `refs/heads/main`, using the advanced workflow's
analysis key and both language categories. Python record `2186205386` and Actions record
`2186203981` reported zero findings and empty errors/warnings. This verifies the merged
source and selected mocked/in-memory paths, not a new package publication, live-provider
run or general guarantee for arbitrary host telemetry. Later changes require their own
exact-commit validation and any package release requires separate approval.

Trace spans, async instrumentation, a reusable adapter package, network exporters,
payload capture, dashboards, GenAI inference labeling and accuracy/performance guarantees
remain outside this recipe.
