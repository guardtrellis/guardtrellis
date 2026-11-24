# OpenAI callback example

This source example connects `Guard.run` to the OpenAI Responses API using the optional
OpenAI Python SDK. It uses the same callback for a credential-free HTTP mock and an
explicitly opted-in live smoke. The GuardTrellis core has no provider dependency.

The example and `openai` extra were introduced in `0.1.0a2`.
Clone the repository as described in the
[README](../README.md#examples-and-development), then run:

```sh
uv sync --frozen --extra openai --group dev
uv run --frozen --extra openai python examples/openai_app.py
uv run --frozen --extra openai pytest tests/test_openai_example.py
```

Alternatively, install `'.[openai]'` from the checkout into an activated virtual environment.
Examples are source scripts, not installed console commands.

## SDK 3 compatibility

This source checkout requires `openai>=3,<4` and `httpx2>=2.12,<3` for the `openai`
extra; the current lockfile selects OpenAI `3.50.0` and HTTPX2 `2.16.0`. This also
applies to the [Azure example](azure_openai.md). Re-sync the extra before running either
source script. These locked versions do not establish compatibility across every allowed
version. Older published GuardTrellis releases retain their own dependency requirements.

The [bounded OpenAI/Azure profile work](https://github.com/sahilmathur254/guardtrellis/issues/104)
is a child of [#49](https://github.com/sahilmathur254/guardtrellis/issues/49), tracked Now / P2 /
In review. Its accepted scope checks the minimum pair OpenAI `3.0.0` / HTTPX2 `2.12.0`
and the reviewed lock pair `3.50.0` / `2.16.0` for the two existing examples. The local
candidate preserves SDK behavior and dependency requirements; native CI remains pending.
The broader #49 work remains Backlog because no resolver conflict has been demonstrated.

When updating an application copied from the SDK 2 examples, replace its `httpx` imports,
clients, timeouts, transports, request/response types, and mocked exceptions with `httpx2`.
The examples' metadata reports now name `httpx2` as the HTTP package. Applications that
still need `httpx` for another integration should keep that separate dependency.

HTTPX2 uses the operating-system certificate trust store by default. Install the required
system CA certificates, or supply a verified CA bundle with `SSL_CERT_FILE`; do not disable
TLS verification. Mocked tests do not verify a deployment's certificate configuration.
See the pinned [SDK 3.19.2 HTTPX2 migration reference](https://github.com/openai/openai-python/blob/v3.19.2/httpx2.md)
for custom client, instrumentation, and trust-store migration details.

## Isolated compatibility profiles

The profile checker uses fresh environments containing only GuardTrellis and its OpenAI
extra. Both the Responses example and the Azure Chat Completions example use the same
dependency profile; their distinct HTTP mock suites must both pass.

| Profile | OpenAI | HTTPX2 | Other runtime dependencies |
| --- | --- | --- | --- |
| `minimum` | `3.0.0` | `2.12.0` | Resolved for the selected Python/platform; record actual versions. |
| `locked` | `3.50.0` | `2.16.0` | Constrained by the selected OpenAI closure exported from `uv.lock`. |

From a checkout with the locked build/development tooling installed:

```sh
uv run --frozen python scripts/check_openai_profile.py --profile minimum --regressions
uv run --frozen python scripts/check_openai_profile.py --profile locked --regressions
uv build --offline --no-build-isolation
uv run --frozen python scripts/smoke_dist.py --openai-only --openai-profile minimum
uv run --frozen python scripts/smoke_dist.py --openai-only --openai-profile locked
```

Consumer-isolation checks precede the addition of locked pytest tooling, excluding unrelated
lint/type tools that could constrain provider or core dependencies. Every initial
runtime package/version must remain unchanged after tooling installation and regressions;
tests use the isolated interpreter directly so project synchronization cannot replace the
minimum pins. Empty, skipped or failing regression runs are not compatibility evidence.
Copied source examples execute outside the checkout against the installed SDK. Runtime
probes use synthetic configuration and prohibit socket/DNS access; package-index downloads
during environment setup are separate from provider calls.

The native CI matrix is configured to check both profiles and both distributions on
Linux, macOS and Windows. Local validation remains distinct from a submitted revision's
native CI and Python/Actions CodeQL evidence. These two selected profiles do not establish
compatibility across every allowed dependency combination, live provider availability or
a deployment's certificate configuration. An unavailable or failing minimum is retained
for triage; it does not authorize changing dependency requirements or expected outcomes.

### Local profile evidence — 2026-11-17

The local, uncommitted candidate based on `454d93aa6c2f6af060ca8e739eeba411a3d030a0`
passed both source profiles on macOS ARM64, CPython `3.12.0`, with uv `0.8.17`:

| Check | Minimum | Locked |
| --- | --- | --- |
| Both HTTPX2 clients construct without network access and close synchronously | Passed | Passed |
| Both copied source mock commands deliver only `Contact [PII]` | Passed | Passed |
| Existing adapter regressions | 73 passed, zero skips | 73 passed, zero skips |
| Initial installed packages unchanged after pytest tooling and after tests | 28 preserved | 26 preserved |
| Dependency consistency checks before and after regressions | Passed | Passed |

Each run prints the exact initial and post-tooling/test versions, source/lock/example/SDK
hashes, base revision, dirty-worktree status and runtime identity. These hashes distinguish
the working candidate from its base commit. The local result does not establish native
Windows/Linux checks, other Python versions or processed Python/Actions CodeQL. Current
review and distribution-check status are recorded in [#104](https://github.com/sahilmathur254/guardtrellis/issues/104).

## Default: no provider calls

The default command uses the real SDK with `httpx2.MockTransport`. It does not open a
network connection or require credentials. It stays mocked even if `OPENAI_API_KEY` and
the live opt-in environment variable are present, unless `--live` is also passed.

The fabricated input is `Reply with exactly: Contact demo@example.org`. Only
`Reply with exactly: Contact [PII]` crosses the callback boundary. The HTTP mock returns
another fabricated email so the example also demonstrates output redaction, printing
`Contact [PII]` only after checking. The JSON report says `"mode": "mock"`; its token
counts are fabricated fixture values, not usage evidence.

The reusable boundary is:

```python
from examples.openai_app import OpenAIModel, make_guard

# Own a configured OpenAI client in your application; see make_client in the example.
model = OpenAIModel(client)
result = make_guard().run(user_text, model)
if result.accepted:
    deliver(result.require_text())  # Use the checked text, not a raw SDK response.
else:
    record_metadata(result.diagnostics())
```

`client`, `user_text`, `deliver`, and `record_metadata` above are application-owned.
The runnable script provides a complete demonstration. In an application, choose policies
appropriate for each stage and configure logging before invoking the callback.

## Explicit live smoke

A maintainer must approve the account, destination, and spending before the live smoke.
Set `OPENAI_API_KEY` privately in the runner's environment using your usual secret manager
or private shell setup; never paste it into an issue, chat, command argument, or report.
The script does not load `.env` files or reuse Codex/ChatGPT credentials.

After approval, run **once** from the checked source commit:

```sh
GUARDTRELLIS_OPENAI_LIVE=1 uv run --frozen --extra openai python examples/openai_app.py --live
```

The live path first confirms a fabricated GitHub-token signature is blocked without a
callback request. It then sends the fixed prompt above, with its email already redacted,
to `https://api.openai.com/v1/responses`. It makes at most **one generation request**:

- Model: `gpt-5.6-luna`, reasoning effort `none`, default service tier.
- Maximum output: 128 tokens; fixed short text input, no files or additional context.
- No tools, streaming, background work, response storage, automatic retries, or redirects.
- No CLI model/prompt override or automatic fallback to another model.

The model's published standard rates on 2026-09-25 are $0.20 per million input tokens and
$1.20 per million output tokens; cache writes have a 1.25x input rate. Even conservatively
allowing 1,000 input tokens plus 128 output tokens gives less than $0.001 in token charges.
This is an estimate at the cited rates, not an enforced dollar budget or a promise about
account-specific charges. The command bounds requests and generated tokens. Confirm
[current model pricing and access](https://developers.openai.com/api/docs/models/gpt-5.6-luna)
before approving; a failed/uncertain request must not be automatically repeated.

Exit status 0 means the input-block assertion and one accepted, checked complete response
passed. Status 1 means the smoke failed; status 2 means an opt-in/key prerequisite is
missing. Model access, billing, networking, and provider behavior can prevent live success.

The live command prints only JSON metadata: UTC date, Python/package versions, configured
model, request attempts, output-token cap, token usage if available, and Guard diagnostics.
It prints no prompts, response contents, credentials, raw errors, or request IDs. Record the
exact source commit separately; a package version alone does not identify an unreleased checkout.

## Failure, logging, and side-effect boundaries

The callback requires a `completed` response with complete text messages. Refusals (including
mixed text/refusal content), empty text, incomplete responses, and unsupported output items
produce an output `ERROR`; they cannot accidentally become an accepted empty string through
the SDK's `output_text` convenience property. The SDK joins all text blocks before Guard
scans the complete output. There is no partial response delivery or tool execution.

Provider connection, authentication, rate-limit, and timeout failures propagate to
`Guard.run`, which produces a generic `callback_error` without exception contents.
`max_retries=0` prevents the SDK from retrying failed requests. The client is closed by
a context manager, including on failure.

The SDK/HTTP timeout uses 5-second connect, write, and connection-pool timeouts and a
20-second read timeout. These bound network phases/inactivity, not total wall-clock
execution. `Guard.run` has no execution deadline. Using this synchronous callback with
`Guard.arun` moves it into a thread; Guard's async wait/cancellation does not terminate that
thread or cancel already accepted remote work. Configure provider timeouts and application
admission limits for your workload; see the [async contract](api.md#limits-and-asynchronous-work).

The standalone command suppresses Python standard logging for its process, including SDK
and HTTP debug logging. It installs no tracing integration. Importing the example leaves
application logging untouched: review `OPENAI_LOG`, HTTP event hooks, tracing/APM exporters,
debugger capture, and any existing wrappers before integrating. They may record data before
Guard checks it. Do not print SDK exceptions or raw responses. Suppressing standard logging
does not disable arbitrary instrumentation or erase data from memory.

Accepted input is still sent to OpenAI, and rejected output was already generated remotely.
Blocking, redaction, timeouts, and cancellation cannot undo provider processing, billing,
retention, or callback side effects. `store=False` opts out of stored response state; it
does not establish Zero Data Retention. Review OpenAI's
[data controls](https://developers.openai.com/api/docs/guides/your-data) for the account in use.
This example uses a fixed official API endpoint; `OPENAI_BASE_URL` does not override it.
The separate [Azure OpenAI example](azure_openai.md) uses Chat Completions; running one
example does not validate the other or arbitrary compatible endpoints.

## Verification and live evidence

Normal CI always uses mocks, including the test of the live command's reporting path.
Tests verify the actual serialized request, blocked input, complete-output redaction/blocking,
failure privacy, no retry/redirect, explicit opt-in, and metadata-only live reporting.
Wheel and source-distribution smokes verify that provider SDKs and HTTP clients are absent
from core installs, then run both OpenAI examples with only the `openai` extra installed.
They run all examples again with every integration extra installed.

**Live verification is pending.** No mocked result is evidence of a successful provider call.
After an approved live run, record the maintainer approval, UTC date, exact commit, package
versions, model, request count, outcome, and token usage from the metadata report in
[#8](https://github.com/sahilmathur254/guardtrellis/issues/8). The only payloads are the
fabricated prompt and synthetic blocked signature documented above. The separate
[Gemini live smoke](gemini.md#recorded-live-smoke-2026-09-26) supplies evidence for #8's
one-provider criterion; it does not verify this OpenAI path. One live smoke establishes
that specific integration path, not general detection quality, production readiness,
or model-output reliability.

Official references: [OpenAI Python SDK setup](https://developers.openai.com/api/docs/libraries),
[Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create).
