# Stripe account-key evaluation, v1

Maintainer-approved design and local evaluation scope, 2026-11-24, for
[#109](https://github.com/guardtrellis/guardtrellis/issues/109) under the
[accepted contract](../../docs/stripe_keys_design.md). Runtime implementation #110
remains gated on reviewed baseline acceptance. No SDK behavior, defaults, examples,
dependency versions, package version or historical evaluation evidence changes here.
Commit, push, merge and publication are not authorized by this local evaluation.

## Authorship and expectations

Forty-eight original, Codex-assisted English-context synthetic development scenarios
are public Apache-2.0 material. Values are fabricated independently of vendor/scanner
example credentials. Author self-review and separate assistant review are disclosed;
there is no external independent, blinded, held-out or representative case review.
Six earlier exploratory prefix probes are not part of this frozen batch. No live
Stripe key, account, provider, database, DNS or other network request is used.

The accepted disclosure-shape policy selects four exact sensitive prefixes and a
10–247 ASCII-alphanumeric suffix. It is not a Stripe issuance or validity grammar.
Publishable prefixes are benign controls, never exemptions for other findings.
The exact delimiter, candidate/attempt/input/shared-finding budgets, atomic errors,
URI precedence and current-scanner-revision span semantics are in the accepted design.

Before the first formal SDK scan, freeze this protocol, corpus, every representation's
default and future-enabled expectations, pure projector, resource recipes, harness
controls and source ledger. The manifest records their byte hashes, accepted-design
hash, pre-observation SDK/source/lock hashes and every historical evaluation hash.
Post its SHA-256 to #109 before observation. Validate the receipt and asset bytes at
runtime. `contract.py` imports no SDK and contains no Stripe search/matching oracle:
it encodes fixed values, maps authored intervals and applies declared profile outcomes.
Never infer expected behavior from an SDK observation. Any later correction needs an
explicit new version or post-observation erratum; keep original frozen bytes/results.

## Fixed main matrix

| Group | Scenarios | Meaning |
| --- | ---: | --- |
| Sensitive prefix/length | 24 | Four prefixes times suffix lengths 9, 10, 24, 99, 247, 248; 16 in-range shapes and eight short/overlong controls. |
| Publishable and benign context | 12 | Six publishable controls and six prose/syntax/case/embedding/documentation controls, including intentionally shape-matching benign intent. |
| Malformed/mixed/span/delivery | 12 | Unicode and malformed continuations, delimiter-split forms, nested/multiple/overlapping signatures, mixed PII/public/legacy secrets, wrappers, quoted and leading-newline controls. |

Four representations are plain, literal JSON, fully Unicode-escaped JSON and a fixed
`value` explicitly decoded once. Strictly decode both wire encodings to the same value;
scan that decoded value only once. No recursive or SDK decoding. Original values are
at most 1,024 Python characters; all represented inputs at most 8,192. Desired full
protection intervals and scenario labels are separate from contract expectations.
Freeze contract eligibility/action/codes/spans/complete checked output/delivery for
each representation. JSON escaping can invalidate a candidate, change its preceding
boundary or take a 255-character candidate over budget. Never copy plain-text
eligibility to JSON. Raw Unicode-escaped JSON is a no-decoding control, not detection
of encoded Stripe secrets. Short controls add no Stripe findings; an eligible overlong
candidate produces a future enabled ERROR, not a true-positive detection.

Each profile performs one RETRIEVAL scan with `Guard.max_chars=8_192`:

| Profile | Ordered scanners |
| --- | --- |
| `secret_block` | Default `SecretScanner()` |
| `secret_redact` | `SecretScanner(action=Action.REDACT)` |
| `handoff` | Default `SecretScanner()`, then default `PIIScanner()` |

These are dedicated policies, not a claim to reproduce a shipped policy constant.
Pass only accepted `require_text()` to a local recording consumer. BLOCK/ERROR must
make no consumer call, without raw fallback. This tests downstream checked handoff;
it cannot undo earlier callbacks, tool calls, captures, state changes or side effects.

Phase A uses only the current SDK API. No `stripe_keys` argument, shadow detector or
substitute future implementation executes. The matrix is **48 × 4 × 3 = 576 correlated
observations**, not independent examples. Twelve children each handle a fixed 12-case
chunk/profile and emit 48 ordered rows. Freeze both default and future-enabled data,
but execute only defaults. After separate #110 acceptance and real implementation,
reuse the same cases in both modes: 1,152 fresh main observations, retaining this
original baseline separately. Never relabel cases to fit implementation outcomes.

## Separate resources and harness controls

Eight compact resource recipes exercise 100,000/100,001 input characters, 255/256
candidate characters, 256/257 eligible malformed attempts and 255/256 existing GitHub
findings plus one Stripe candidate. Each has direct BLOCK and Guard BLOCK observations
with `max_chars=200_000`: **16 baseline resource observations in eight children**.
Current defaults do not have private Stripe budgets; freeze phase-specific expectations.
The mixed-finding recipes reach combined 256/257 only in future enabled mode. The
future comparison reruns both modes: 32 fresh resource observations in 16 children.

Four separately frozen harness controls cover legacy Unicode offsets, a preceding
PII redactor followed by legacy-secret redaction with scanner-revision coordinates,
Guard ingress rejection, and supervised cleanup. The cleanup control is infrastructure
evidence and not an SDK/detection observation. None inflates primary accuracy counts.
WARN/all-stage/invalid-option/late-error/URI-precedence regressions belong to #110.
H04 uses a worker that announces verified identity and readiness before a scripted
60-second sleep, without scanning. The parent arms a 100-millisecond timeout after
readiness, inside the ordinary ten-second outer observation budget, then kills/reaps.
Only actual expected timeout plus successful reap produces the parent-derived passing
infrastructure-control row. Startup failure or an unverified ready record cannot pass.

## Containment, output and provenance

Reuse existing platform-specific sanitized environments, supported resource limits,
Windows base-interpreter/venv launcher, and kill/reap helpers. Main and resource passes
each have a 180-second parent observation budget; each child gets at most ten seconds,
clipped by remaining observation time, and 64 KiB stdout and stderr caps per stream.
Cleanup is separately bounded by the existing five-second reap wait before temporary
directory removal. Harness controls use the same per-child bounds in their own pass.
OS launch/filesystem delays are not hard SDK execution deadlines or process isolation.
Available CPU/RSS cover the whole worker, including startup, not per-scan performance.

Freeze every expected row, ordered worker inventory and bounded metadata schema.
Only validated rows from a completed prefix may survive a later failure. Preserve
timeouts, interrupts, capture/identity/protocol failures, cleanup state and not-started
denominators; no missing child silently removes expected observations. Unknown metrics
stay null. Actual installed SDK/dependency versions, platform/interpreter, SDK/helper/
runner/project/lock digests and freeze identity are recorded independently of the
manifest's original base commit. Pin one runtime identity for the entire batch.

The worker protocol uses a verified `identity` record before rows and a `complete`
record after the exact ordered inventory. Both carry SDK version, SDK digest and whole
runtime/source digest. Completion also carries count, the four optional resource limits
(`cpu_seconds`, `address_space_bytes`, `core_bytes`, `output_file_bytes`), and CPU/RSS
measurements. Identity mismatch cannot contribute attributed outcome rows. H04 emits
only identity/readiness, with its outcome derived by the supervisor as described above.

Main row keys are `id`, `representation`, `action`, `accepted`, `primary`, `incidental`,
`findings`, `consumer_calls`, `comparisons`, `contract_comparisons`, `delivery_integrity`,
`contract_match`, `privacy_ok`. Findings contain only static `code`, character `start`/
`end` (both null for spanless errors), `scanner`, `scanner_index` and `revision`.
Primary/incidental records are code/start/end triples; at most eight findings per main
row. Desired comparisons are action/spans/text/delivery booleans; contract comparisons
are action/findings/text/delivery booleans. Action uses the existing five enum spellings;
acceptance/integrity/privacy/contract flags are actual booleans, and consumer calls are
bounded nonnegative integers. No text value is emitted with a comparison.

Resource row keys are `id`, `mode` (direct/guard interface), `input_chars`, `action`,
`accepted`, `finding_count` (0–256), sorted static `finding_codes`, `error_spanless`,
`has_deliverable_text`, `consumer_calls`, `delivery_integrity`, `contract_match`,
`contract_comparisons`, `privacy_ok`, `operation_ms`. Direct Check text/call fields are
null because Check exposes no checked-text delivery API. Exact dense findings are
compared in worker memory, not emitted. Counts, codes and comparisons remain separate.

SDK-control row keys are `id`, `action`, `accepted`, `findings`, `consumer_calls`,
`contract_comparisons`, `contract_match`, `privacy_ok`, `delivery_integrity`. H04 instead
has `id`, static `status`, `child_reaped`, `contract_match`, `privacy_ok`,
`delivery_integrity`. Row IDs, representation/interface values, codes and scanner names
must belong to the fixed inventory/allowlists; unknown fields or contradictory derived
counts/actions/flags invalidate the protocol. Optional unavailable resource metrics
are null; present durations/counts must be finite and nonnegative. The parent enriches
validated rows only with fixed corpus family/group/label/profile/scope metadata.

Reports contain only bounded static IDs/codes, offsets, counts, booleans, descriptive
measurements and source/runtime identity. Exclude raw/checked text, replacements,
credential fragments, canaries, arbitrary host paths/environment and exception messages.
Do not forward arbitrary malformed worker data. Bound combined JSON/Markdown reports
to 2 MiB; interrupted/incomplete reporting is best effort if storage is unavailable.
Never overwrite an existing report directory or prior baseline.

## Scoring and gates

Separate primary Stripe signals from incidental GitHub/AWS/PEM/PII findings and overall
actions. A legacy block or PII redaction is not Stripe detection. Report exact spans,
full checked text/delivery comparisons, contract conformance and authored desired
protection separately. Keep contextual false positives, unsupported misses and partial
redactions visible. Overlaps remain separate findings; only overlapping edits merge.

Report primary TP/FP/TN/FN and expected/completed/error/incomplete counts per prefix,
profile and representation; undefined precision/recall are null. ERROR never counts as
detection. Expected future limit ERROR can meet the processing contract while missing
desired protection. Repeated representations, profiles and executions are correlated.
No population accuracy, vendor comparison, latency/throughput or safety guarantee.

Success requires complete/reaped observations, exact eligible current-default contracts,
checked-handoff integrity, no unexpected SDK/protocol/privacy errors and unmodified frozen
assets. Desired-outcome misses stay visible without converting known exclusions into
SDK defects. Baseline acceptance is a separate maintainer review. Native Windows/macOS/
Linux and processed Python/Actions CodeQL for this contribution require a later authorized
submitted revision; local launch regressions do not establish native Windows execution.
