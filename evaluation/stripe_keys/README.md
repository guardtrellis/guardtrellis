# Stripe account-key disclosure evaluation, v1

Evaluation-only contribution to [#109](https://github.com/guardtrellis/guardtrellis/issues/109)
and the wider [#45](https://github.com/guardtrellis/guardtrellis/issues/45) program under
the [accepted Stripe contract](../../docs/stripe_keys_design.md). SDK 0.2.0 remains
unchanged. The future opt-in implementation belongs to #110 and requires baseline review.

Forty-eight original Codex-assisted synthetic development scenarios cover four sensitive
test/live prefixes, publishable controls, benign lookalikes, malformed/overlong forms,
mixed legacy secrets/PII, overlaps and character-span/delivery boundaries. These public
Apache-2.0 cases received author self-review and separate internal assistant review;
they are not externally independent, blinded, held-out or representative evidence.
All values are fabricated. No Stripe SDK/API, live credential or network request is used.

## Reproduce after the freeze

```sh
uv run --frozen python evaluation/stripe_keys/run.py \
  --report-dir /tmp/guardtrellis-stripe-keys-new
```

Choose a directory that does not exist. Existing reports and historical evidence are
never replaced. The native CI matrix includes this full command; only an actual later
authorized submission can establish Windows/macOS/Linux and processed CodeQL results.

## Freeze and matrix

The [protocol](PROTOCOL_v1.md), [corpus](corpus_v1.jsonl),
[default and future expectations](expectations_v1.json), [pure projector](contract.py),
[resource recipes](resource_cases_v1.json), [harness controls](harness_controls_v1.jsonl)
and [source ledger](sources_v1.json) are prepared before any new-scenario SDK scan.
The [manifest](freeze_v1.json) binds their bytes and source/lock/historical provenance;
the loader requires its external #109 digest receipt before executing the batch.
Authored expectations are not tuned from observed results. Corrections require an
explicit new version or erratum retaining the original frozen assets and evidence.

| Category | Count | Interpretation |
| --- | ---: | --- |
| Authored scenarios | 48 | 24 prefix/length, 12 benign-context and 12 mixed/malformed/span scenarios; development cases, not independent external authorship. |
| Current-default main observations | 576 | 48 scenarios × four representations × three profiles; correlated observations. |
| Current-default resource observations | 16 | Eight recipes × direct/Guard calls; separate from detection accuracy. |
| Harness controls | 4 | Legacy Unicode spans, preceding-redactor revision, Guard ingress and supervised cleanup; separate from detection accuracy. |
| Future main comparison | 1,152 | Fresh default/enabled comparison only after the real SDK option exists; not executed by this baseline. |
| Future resource comparison | 32 | Both modes × eight recipes × direct/Guard; not executed by this baseline. |

The profiles are default secret BLOCK, secret REDACT, and secret BLOCK followed by
default PII REDACT, each at RETRIEVAL with an 8,192-character Guard cap. They are dedicated
policies. Representations are plain, literal JSON, fully Unicode-escaped JSON and one
explicitly decoded fixed value. No implicit/recursive SDK decoding is introduced.

Each representation has independently authored contract eligibility, actions and spans.
JSON escaping can invalidate a candidate, change its boundary or exceed its budget;
desired span projection alone does not establish support. Fully escaped raw JSON is a
no-decoding control. Short/overlong controls are not counted as supported positives.

## Interpret the evidence

Primary Stripe signals, incidental legacy/PII findings, current-contract conformance and
desired complete protection are distinct. An incidental GitHub/PEM BLOCK does not prove
Stripe detection. ERROR is never a true positive. Unsupported misses, shape-matching
benign false positives and incomplete/partial protection must remain visible.

Only accepted `require_text()` reaches the local consumer. BLOCK/ERROR means no downstream
consumption; this does not undo earlier callbacks or side effects. Findings use half-open
Python-character offsets in the scanner's current revision. The preceding-redactor
control separately verifies why those coordinates may differ from original ingress.

Main, resource and harness passes use bounded children, ten-second child wall budgets,
64 KiB stdout/stderr caps, 180-second observation budgets per pass and separately bounded
cleanup. Unknown metrics and missing observations remain explicit. These are external
containment checks, not hard SDK deadlines, production performance or capacity evidence.
Reports omit raw/checked text, credential fragments, replacements, exception messages,
environment values and arbitrary host paths. Actual runtime/source identity is recorded
separately from the original frozen base commit.

Design acceptance does not accept the baseline or authorize #110, commit, push, merge
or publication. Local verification and actual submitted-revision CI remain separate.

## Retained local baseline

The manifest SHA-256 is
`260c7743a6a45545266989087f0faad26d5cc3d3fd555516aa61ebd262728441`.
Its [external receipt](https://github.com/guardtrellis/guardtrellis/issues/109#issuecomment-7130408959)
was recorded at `2026-11-24T11:40:52Z`, before the first formal observation batch began at
`2026-11-24T11:41:05.787160+00:00`. That first pass remains outside the checkout. Subsequent
runner review added static argument-parser interruption handling and explicit null metrics;
the frozen protocol, labels, cases, expectations and manifest were not rewritten.

The [retained final-runner report](baseline_sdk_0.2.0/REPORT.md) and
[metadata results](baseline_sdk_0.2.0/results.json) identify the actual runner/source/runtime.
All **576 main current-default contracts**, **16 resource contracts** and **four harness
controls** matched. All 24 supervised children were reaped, including the intentional
H04 timeout. No unexpected SDK errors, incomplete observations, privacy failures or
checked-delivery integrity failures occurred. H03's Guard ingress ERROR is an expected
separate control, not a main-matrix error or detection.

The unchanged SDK has no Stripe-specific detector: **0 TP, 0 FP, 156 TN and 420 FN**
across the correlated main observations. Those 420 sensitive observations include
supported-shape candidates, unsupported disclosures and raw no-decoding controls; this
is not a representative accuracy estimate. Thirty observations had incidental legacy
secret or PII findings, which were not credited as Stripe detections. Exact desired
complete protection/delivery matched 153/576 observations. Current-contract conformance
does not mean the desired Stripe protection is already implemented.

Local macOS/Python 3.12 verification passed 121 focused Stripe evaluation regressions
plus 226 existing resource/detector-delivery/retrieval-tool evaluation regressions with
warnings treated as errors. Repository Ruff lint/format checks and existing SDK mypy
checks passed. Native Windows launching is covered by a local simulation and existing
launcher reuse; native Windows/macOS/Linux CI and Python/Actions CodeQL for this patch
remain pending an authorized commit/push. No full-suite, native Windows or release pass
is inferred from these local checks. Baseline acceptance remains with the maintainer.
