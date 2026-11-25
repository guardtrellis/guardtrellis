# Stripe account-key disclosure evaluation, v1

Evaluation-only contribution to [#109](https://github.com/guardtrellis/guardtrellis/issues/109)
and the wider [#45](https://github.com/guardtrellis/guardtrellis/issues/45) program under
the [accepted Stripe contract](../../docs/stripe_keys_design.md). The original SDK 0.2.0
baseline remains unchanged. The local, unreleased #110 implementation adds an explicit
opt-in and a separate default/enabled comparison after acceptance of that baseline.
Published 0.2.0 does not accept the new argument.

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
That sentence records the original evaluation gate: #109 was subsequently accepted/merged
through #111; the maintainer separately accepted #110's implementation plan on 2026-11-25
and authorized local implementation/comparison. Commit/push, merge and publication of #110
remain on hold.

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

## Unreleased #110 implementation comparison

The maintainer accepted #109 through #111 and authorized the local implementation on
2026-11-25. Published 0.2.0 still has no `stripe_keys` option. The source implementation
and this separately retained comparison are not package-publication evidence.

```sh
uv run --frozen python evaluation/stripe_keys/run.py --compare \
  --report-dir /tmp/guardtrellis-stripe-comparison-new
```

The [comparison protocol](COMPARISON_v1.md),
[inventory/schema](comparison_inventory_v1.json) and [record](comparison_v1.json) supplement
the original freeze without changing any original labels, projections or expectations.
Manifest SHA-256 `3820efce4fd7d8705b5b18609686a01e9488383fb654aadedffb15c5c5069d61` was
[recorded on #110](https://github.com/guardtrellis/guardtrellis/issues/110#issuecomment-7159776116)
at `2026-11-25T10:29:54Z`, before the first formal comparison batch timestamp
`2026-11-25T10:30:09.674686+00:00`. That first pass stays outside the checkout. The retained
replay follows formatting of the runner's receipt constant; frozen bytes and outcomes
were not changed. Each report identifies the actual source/runtime that ran.

The [retained comparison](comparison_source_v1/REPORT.md) and
[metadata](comparison_source_v1/results.json) record all **1,152 main**, **32 resource**
and **four control** contracts matched; all 44 supervised children were reaped. No
unexpected errors, incomplete observations, privacy failures or checked-delivery
integrity failures occurred. Thirty-nine main limit ERROR outcomes match the frozen
processing expectations; they never count as detections or desired-protection successes.

| Detector mode | TP | FP | TN | FN | Expected main ERROR | Exact desired outcomes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Default | 0 | 0 | 156 | 420 | 0 | 153/576 |
| Enabled | 213 | 18 | 138 | 168 | 39 | 328/576 |

These are correlated selected development observations, not independent/general accuracy
estimates. Enabled false positives include well-shaped benign documentation/placeholders;
retained misses include raw escaped JSON, excluded lengths/boundaries and unsupported
formats. Signal matches can still fail complete desired spans/protection. Incidental
legacy/PII findings remain separate. Resource limit outcomes and infrastructure controls
are outside this main accuracy table.

The unchanged default-only command also matched all 576 main / 16 resource / four control
contracts under the new source. All fourteen earlier evaluation commands passed. Local
strict regressions passed 2,563 checks, including 201 new SDK and 41 new comparison checks.
The original 0.2.0 baseline, accepted design, seven frozen input assets and manifest remain
byte-identical. Source version still reads 0.2.0; actual implementation head/base, dirty
state and SDK/source hashes distinguish these unreleased bytes from published 0.2.0.
Parent-only VCS provenance and child-verified source identity avoid nested Git processes
inside timed workers.

Native Windows launching has local protocol/cleanup regressions, including the comparison
selector. Actual submitted-revision Windows/macOS/Linux and processed Python/Actions
CodeQL remain pending commit/push authorization. Version/changelog synchronization and
publication remain separate release-preparation gates.
