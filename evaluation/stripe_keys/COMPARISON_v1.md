# Stripe opt-in comparison protocol, v1

Prepared 2026-11-25 for the accepted #110 implementation plan. Review and record this
protocol/inventory manifest on #110 before the first formal enabled comparison. This
record supplements the original #109 freeze; it does not replace expectations, labels,
case/projector bytes or the accepted baseline. SDK implementation and comparisons are
local/unreleased work; no commit, push, merge or publication follows from this record.

## Fixed inputs and observations

Use the exact 48 scenarios, four representations, three profiles, resource recipes,
controls and default/enabled predictions in the original `freeze_v1.json` with digest
`260c7743a6a45545266989087f0faad26d5cc3d3fd555516aa61ebd262728441`.
Validate their byte hashes and pure authored projections before observations. Any
conflicting expectation requires an attributable erratum/new version, never tuning to
implementation output. The current default-only command remains 576 observations.

Explicit `--compare` schedules these separately counted passes:

| Pass | Children | Rows | Selection |
| --- | ---: | ---: | --- |
| Main | 24 | 1,152 | default/enabled × three profiles × four 12-scenario chunks; each child scans four representations per scenario and emits 48 rows. |
| Resource | 16 | 32 | default/enabled × eight recipes; each child observes direct and Guard interfaces. |
| Controls | 4 | 4 | Four existing controls run once using their unchanged legacy policies; H04 is infrastructure, not SDK accuracy evidence. |

All main policies scan RETRIEVAL with Guard max_chars 8,192. Default uses the original
factory and old argument set. Enabled alone supplies the real `stripe_keys=True` flag;
there is no shadow detector or normalization/decoding. The local consumer receives only
accepted `require_text()`, with no consumer invocation or raw fallback for BLOCK/ERROR.
An earlier callback/tool invocation cannot be undone by rejecting returned text.

The word `mode` on historical resource rows still means direct/Guard interface. The
new `detector_mode` dimension means default/enabled and is separately validated. Do not
attribute a row to a detector policy based solely on a result that both policies share.

## Ordered worker protocol

`comparison_inventory_v1.json` fixes every worker selector and row ID/order, count,
representation/interface, field allowlist and bound. `comparison_v1.json` binds its
hash, this protocol and the original freeze. Runtime requires the reviewed manifest
digest plus the external #110 receipt URL; missing/tampered records fail before SDK scans.

Each worker emits a verified identity before rows and a complete record after its
exact inventory. Comparison identity and completion add `detector_mode`, `worker_kind`
and integer `worker_cell` to the baseline SDK/source/runtime identity fields. Every
selector must match the parent's scheduled worker. Identity mismatch cannot contribute
attributed rows; a completion identity mismatch discards that worker's rows. Unknown,
duplicate, truncated, out-of-order or payload-bearing events invalidate the protocol.

Raw main/resource/SDK-control row schemas retain the baseline static allowlists. The
parent enriches validated main rows with fixed case/profile metadata, detector_mode and
the frozen expected_error boolean. Resource rows gain detector_mode separately from
their interface-valued mode field. Parent-generated H04 cleanup rows retain the original
schema. No input/checked text, replacements, credential fragments, exception messages,
environment values or arbitrary host paths appear in rows or reports.

H04 emits identity/readiness then sleeps, without scanning. Readiness arms its original
100-millisecond timeout inside the normal outer child budget. Only verified readiness,
actual expected timeout, empty stderr and successful reap produce its passing control
row. A startup failure or unknown identity does not pass as cleanup success.

## Bounds, cleanup and source identity

Every main/resource/control pass has a separate 180-second observation budget. Each
child receives at most ten seconds, clipped to parent time remaining, and 64 KiB stdout
and stderr per stream. Existing platform resource controls, sanitized environments,
native Windows base-interpreter/venv launcher and five-second reap allowance are reused.
Reap before removing temporary work; preserve an unreaped worker's directory. Unknown
CPU/RSS/limit values stay null. These limits are external containment, not an SDK deadline
or process sandbox. CPU/RSS include worker setup, not isolated scanner capacity evidence.

Workers verify actual SDK, runner, helper, lock, project, frozen-asset and comparison-record
bytes plus Python/platform/dependency identity. They do not launch nested git commands.
The parent separately captures actual implementation head/base and dirty-worktree status;
that VCS snapshot is not an independently verified child revision. The base is merge-base
with the available origin/main reference, or null when unavailable (for example a shallow
checkout without that ref); it is not an immutable pre-feature base. It remains distinct
from the original frozen baseline base commit. Actual source hashes identify dirty local
code; a still-0.2.0 version field does not mean published 0.2.0 includes the implementation.

Preserve validated prefixes and explicit expected/missing denominators after failure,
timeout or interruption. Complete success needs the exact ordered 44-worker schedule,
all expected rows and every child reaped. JSON plus Markdown output is capped at 2 MiB;
reports never overwrite existing directories or the retained historical baseline.

## Scoring, errors and acceptance

Primary Stripe signals alone determine TP/FP/TN/FN; incidental legacy/PII findings do
not become Stripe detections. Report counts by prefix family/profile/representation/
detector_mode, desired complete spans/text/delivery and contract conformance separately.
Keep contextual false positives, unsupported misses and partial redactions visible.
These public AI-assisted development cases are correlated, implementation-aware and not
externally independent, hidden, blinded or representative efficacy evidence.

ERROR never enters TP/FP/TN/FN. A frozen expected limit ERROR passes processing conformance
only if the exact action/code/spanless findings, rejected checked output and delivery all
match. It remains a desired-protection miss, never a detection success. Any unexpected
ERROR, wrong error reason, partial findings/edits, accepted payload or incorrect handoff
fails acceptance. Positive/negative/error/incomplete denominators stay explicit; undefined
precision/recall are null. Expected SDK errors are separate from infrastructure failures.

Exit zero requires complete/reaped work, matching eligible contracts and no unexpected
SDK/error/protocol/privacy/handoff failures. Local success does not establish native CI,
general detection accuracy, latency/throughput, credential validity or release approval.
