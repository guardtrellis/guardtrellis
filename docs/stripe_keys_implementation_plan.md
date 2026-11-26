# Stripe account-key detection: #110 implementation plan

Status: **Plan accepted by the maintainer, 2026-11-25; implementation merged through
[PR #113](https://github.com/guardtrellis/guardtrellis/pull/113), 2026-11-26.**

The implementation steps below retain the accepted plan's behavior and original release
sequencing. Dated validation and merge records distinguish that snapshot from the `0.2.1`
release closeout. Check [PyPI](https://pypi.org/project/guardtrellis/) for package availability.

Acceptance covers the reviewed plan snapshot SHA-256
`fec9574a358c11332136d045e55acac6575dd402726f065801176df709c2eb43`.

The maintainer asked to start the next release work after merging #111. This first step
aligns [#110](https://github.com/guardtrellis/guardtrellis/issues/110) with the
[accepted design](stripe_keys_design.md) and accepted
[#109 baseline](https://github.com/guardtrellis/guardtrellis/issues/109).
The baseline merged through [#111](https://github.com/guardtrellis/guardtrellis/pull/111)
at `1a2f11ab580e17b2e68b67c1e21ce3d3935d50c3`; native matrix and processed Python/Actions
CodeQL passed on that exact main commit. The accepted baseline and implementation work
used SDK/package version 0.2.0.

At plan acceptance, the maintainer authorized local implementation, regressions, comparisons,
documentation and issue/organization-board tracking while preserving frozen evidence,
dependency bounds, versions and existing CLI policies. Commit/push, merge and publication
were separate later gates; the closeout below records the implementation's subsequent merge.

## Fixed behavior and exclusions

The accepted contract remains authoritative; this plan does not reopen its grammar.

- Add keyword-only `SecretScanner(stripe_keys=False)`, accepting an actual `bool` only.
- Recognize only `sk_test_`, `sk_live_`, `rk_test_`, `rk_live_`, with their accepted static
  per-family codes and 10–247 ASCII alphanumeric suffix policy. This is selected shape
  detection, not a complete Stripe issuance or validity specification.
- Use the exact 25-character ASCII delimiter set and maximal-candidate rules in the design.
  Malformed/short candidates produce no Stripe finding; never shorten them into a match.
  Retain their sensitive misses.
  Delimiter-split forms may leave fragments untouched, and well-shaped benign placeholders
  may match. Document those outcomes rather than adding exemptions.
- Preserve default BLOCK and explicit WARN/REDACT for token-only use. URI mode still requires
  BLOCK at construction and use. Configure once; no concurrent mutation guarantee.
- Use half-open Python-character spans in the scanner's current input revision. The Guard
  supplies scanner/index/revision metadata; do not map findings back to original ingress.
- Keep publishable `pk_test_`/`pk_live_` values free of Stripe findings/attempts while retaining
  independent legacy/URI findings. Defer webhook/organization/prod/other-vendor formats,
  decoding, normalization, network validation and CLI adoption.

## 1. Add one private bounded helper

Add `src/guardtrellis/_stripe_keys.py`, following the private URI-helper pattern:

- Static exact-prefix search, explicit delimiter membership and one forward cursor.
  Fixed regex or equivalent fixed-prefix search must not use Unicode word boundaries,
  case folding, normalization, entropy or configurable regular expressions.
- `find_stripe_keys(text)` yields `Finding` objects; no public export or new dependency.
  An internal `StripeKeyLimitError` carries no input or exception-message payload.
- Input cap 100,000 Python characters, candidate cap 255 including prefix, eligible-attempt
  cap 256. Count empty/short/malformed eligible attempts before reading candidates.
- Walk each eligible candidate to its delimiter/end while tracking complete ASCII validity.
  The 256th nondelimiter character raises even if an earlier character already invalidated
  the candidate. Skip nested prefixes inside that candidate and never emit a shorter match.
- Do not slice or accumulate unbounded candidates. Bound pending findings by the attempt cap.
  This bounds the Stripe pass; it introduces no hard synchronous SDK execution deadline.

## 2. Integrate without changing the disabled path

In `src/guardtrellis/scanners.py`, validate/store the flag alongside the existing URI flag.
Retain the current legacy-only fast path when both flags are false; it must not call the
Stripe helper or add Stripe input/attempt limits. Keep existing `_find` signatures intact.

For enabled options, preserve this order:

1. Reject an enabled URI policy with a non-BLOCK action before reading content.
2. Materialize the complete bounded URI preflight when enabled. URI limit/unexpected-error
   outcomes retain precedence over Stripe and old-token outcomes.
3. Materialize the complete bounded Stripe preflight when enabled, before aggregation can
   return because of an old match or the shared finding ceiling.
4. Feed URI, existing token/PEM and Stripe findings into the existing `_decision`, preserving
   the shared 256-individual-finding cap, sort order and overlapping-edit merging. Use constant
   BLOCK when URI mode is selected; otherwise retain the selected token action.

Map a Stripe budget exception to one spanless `stripe_key_limit_exceeded` ERROR. Retain
`finding_limit_exceeded`, URI codes and `scanner_error` for ordinary unexpected helper
failures. Do not catch `BaseException`. Do not move the scanner cap into a Guard-wide cap.

Atomicity applies to the SecretScanner Check: an error returns no partial successful
SecretScanner findings or edits. The existing Guard may retain findings/traces from an
earlier PII redactor; preserve that history while withholding the final checked text.
No Guard/model/tool wrapper changes or history reset are needed.

## 3. Add behavior and failure-boundary regressions

Use fabricated, locally constructed values; no live keys or provider requests.

| Area | Required evidence |
| --- | --- |
| Compatibility/configuration | Implicit/explicit disabled checks match existing actions/findings/edits; disabled helper is never called; only actual bool flags accepted; all four flag combinations; URI non-BLOCK construction/runtime rejection. |
| Grammar | Four prefixes, suffix lengths 9/10/247/248, every delimiter, case/embedding/nested prefixes, malformed ASCII/Unicode/mark/control/backslash continuations, quotes/newlines and literal JSON boundary effects. |
| Action/stage | All three token actions and all existing Stages; WARN delivers original text; complete REDACT preserves surrounding text; BLOCK/ERROR withhold checked text; relevant input callbacks and downstream checked consumers obey their actual stage boundaries. |
| Findings/edits | Unicode character offsets; multiple keys; PEM overlaps and merged edits; independent publishable-plus-legacy findings; earlier PII REDACT followed by Stripe REDACT/BLOCK/ERROR with correct revisions. |
| Work/error precedence | Input 100,000/100,001; candidate 255/256; attempts 256/257 including malformed values; shared findings 256/257 across old/new/URI findings; late overflow after earlier matches under every action; URI error before Stripe error; unexpected helper exception versus interrupt propagation. |
| Privacy | Static codes/offsets only in diagnostics, repr and rejection surfaces; fabricated fragments absent from logs/errors; no partial success or raw fallback on ERROR. |

Keep OUTPUT/RETRIEVAL/tool-result tests honest: an earlier callback/tool call already ran.
Assertions must cover downstream consumption, not claim rejection undoes earlier side effects.
Retain every existing scanner, URI, checked-delivery and historical evaluation regression.

## 4. Extend evaluation with an explicit comparison mode

Preserve all frozen assets and their original manifest/receipt, accepted design and retained
`baseline_sdk_0.2.0` files byte for byte. In particular, do not change frozen `contract.py`,
case labels, projections or future-enabled expectations after observing the implementation.

Extend the nonfrozen runner with an explicit `--compare` mode and a separate
`COMPARISON_v1.md` protocol. Keep the existing default command and 12 baseline cells at
576 default-only observations. Its default policy factory must keep working through the
old argument set; the Stripe argument is supplied only by the enabled comparison factory.
Update the static no-shadow/default-API regression to test that actual baseline boundary,
rather than prohibit a separately selected comparison factory from using the real API.

The comparison must:

- Execute default and enabled modes against the same 48 cases, three profiles and four
  representations: **1,152 fresh main observations in 24 children**, with 48 rows per child.
- Run all eight frozen resource recipes in both detector modes and both direct/Guard
  interfaces: **32 resource observations in 16 children**, two rows per recipe/mode child.
- Run the four existing harness controls once as a separately counted control pass. They
  continue testing legacy/revision/ingress/cleanup behavior, not Stripe detection accuracy.
- Name the new policy dimension `detector_mode` and keep it distinct from the historical
  resource row `mode`, whose values mean direct/Guard interface. Include detector mode in
  worker selection, expected inventory, row validation and attribution; a correct result
  from the wrong policy must not pass.
- Retain ten-second child / 64 KiB per-stream bounds and separately bounded cleanup.
  Clip each child's ten seconds to the remaining parent observation budget. Main, resource
  and control passes each retain a 180-second observation budget. Record
  expected and missing rows explicitly; preserve validated prefixes and source identity.
- Distinguish exact expected contract ERROR from unexpected ERROR. A frozen limit ERROR
  can pass processing conformance only when its code, spanlessness, absence of partial
  findings/edits, rejected delivery and all other comparisons match. It still fails the
  authored desired protection and is never TP/FP/TN/FN. Any unexpected ERROR fails the run.
- Keep positive/negative/error/incomplete denominators, per-prefix/profile/representation/
  detector-mode results, incidental findings, desired full protection and checked-delivery
  integrity separate. Retain benign-context false positives and unsupported/partial misses.
- Record exact actual SDK/source/runtime/lock/runner/comparison-protocol identities and pin
  one identity across children. Reports remain bounded, payload-free and non-overwriting.
  Keep combined JSON/Markdown output at 2 MiB, with bounded metadata-only stdout/stderr.
  Name the original freeze base separately from the actual implementation base/head and
  dirty-worktree/source hashes; do not present the old `d4c385...` freeze commit as the
  implementation revision. Include the selected detector mode in each worker handshake.

Before the first comparison scan, review and fix the new protocol, worker inventory, output
schema and harness-control count. Record their hashes alongside the original freeze identity.
This is a new harness/protocol record, not a replacement expectation freeze. If a frozen
expectation conflicts with the accepted contract, stop and record an attributable erratum
or new version; never tune the original to the observed SDK.

Retain the comparison as a separate explicitly unreleased source snapshot, including the
actual version field and source hashes. A version field still reading 0.2.0 does not establish
that published 0.2.0 contains this implementation. Later version-preparation validation must
identify its own runtime/source rather than overwrite either baseline or comparison.

## 5. Documentation and verification

Update `docs/api.md`, a focused `docs/stripe_keys.md` guide, `docs/limitations.md`,
`docs/coverage.md`, `docs/compatibility.md`, `ROADMAP.md` and the evaluation README to explain
opt-in behavior, exact selected grammar, limits/errors, stage/revision semantics, unsupported
forms, contextual false positives, raw JSON exclusions and complete checked delivery.
Link actual comparison/native CI evidence separately from the preserved historical snapshots.
Label new option usage as unreleased source-checkout behavior until the implementation
ships; published 0.2.0 does not accept `stripe_keys`.

Keep examples and CLI profiles unchanged. A future documented explicit configuration example
may use the new option; it must not silently enable Stripe in an existing shipped policy.
Do not change mandatory/optional dependency bounds or the source version in this feature batch.

Verification before submission:

1. Focused new regressions, existing scanner/URI/delivery tests, then the full strict suite.
2. All existing evaluation commands plus unchanged default Stripe baseline and new comparison.
3. Repository lint/format/types, source/version checks, offline wheel/sdist build, strict Twine
   and fresh core/provider/all-extras installation smokes outside the checkout.
4. After separately authorized submission: actual Windows/macOS/Linux matrix, exact-revision
   comparison output, cleanup and processed Python/Actions CodeQL. Local Windows simulations
   do not substitute for native execution.

Current 0.2.0 is already published. Do not edit its released changelog entry, add an unsupported
`Unreleased` heading, or create a mismatched 0.2.1 heading while the source still says 0.2.0.
Carry this proposed release-note text into the separately scoped 0.2.1 preparation PR:

> Add opt-in local detection for selected Stripe secret/restricted test/live account-key
> shapes, with complete supported spans, checked redaction/withholding and bounded processing.
> Defaults and publishable-key handling remain unchanged. No credential validation or
> webhook, organization-key, generic-secret or implicit encoded-JSON coverage is claimed.

That release PR owns canonical changelog/version/generated pins/lock synchronization and
final roadmap/coverage closeout. After its reviewed merge and final-main CI, publication
still needs protected-environment/organization-publisher verification, a fresh TestPyPI
rehearsal and same-artifact PyPI promotion under separate authorization.

## Acceptance and next action

The #109 design/baseline gate was satisfied before implementation. The maintainer accepted
this plan on 2026-11-25 and authorized local SDK implementation. At local validation,
#110 was **In review**, Now/P2; submitted-revision native CI, commit/push, merge and
publication remained separate gates.

The local evidence includes 2,563 strict tests, the fourteen prior evaluation commands,
unchanged default Stripe replay and the retained 1,152-main/32-resource/four-control
comparison. Its [pre-observation receipt](https://github.com/guardtrellis/guardtrellis/issues/110#issuecomment-7159776116)
precedes all formal enabled observations; original frozen bytes and baseline were preserved.
See the [comparison record](../evaluation/stripe_keys/README.md#110-implementation-comparison)
for retained limitations, expected errors and source/runtime provenance. That dated local
source evidence is separate from native CI and publication acceptance.

## Merge and 0.2.1 release closeout (2026-11-26)

Implementation merged through PR #113 at `9087fdb97dce3ae60b527e5dbbca11848cecb622`.
All 17 active checks passed on reviewed head `a4a9e77d9745ddefd2594390aca733e87d12c6ea`,
including the [native PR matrix](https://github.com/guardtrellis/guardtrellis/actions/runs/45613735598),
[processed Python/Actions CodeQL](https://github.com/guardtrellis/guardtrellis/actions/runs/45613735643)
and [candidate installation checks](https://github.com/guardtrellis/guardtrellis/actions/runs/45613735533).
Windows passed 2,474 tests with 89 expected platform-specific skips; all 201 new SDK and
41 new comparison regressions ran. These results identify the reviewed PR revision,
not a later release-preparation commit.

The `0.2.1` closeout owns version/changelog/generated-pin/lock synchronization and current
availability wording. It does not change the accepted contract, scanner behavior, dependency
bounds or retained baseline/comparison bytes. Historical snapshots keep the 0.2.0 version
fields and source hashes they actually observed. Final candidate/main validation, TestPyPI
rehearsal and same-artifact PyPI verification retain their own commit/run evidence;
this plan and its merge do not establish an index upload.
