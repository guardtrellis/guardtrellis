# Stripe account-key detection: proposed contract

Status: **Design accepted by the maintainer, 2026-11-24; not implemented.**
[#109](https://github.com/guardtrellis/guardtrellis/issues/109) owns the contract and
pre-implementation evaluation. [#110](https://github.com/guardtrellis/guardtrellis/issues/110)
owns any later SDK implementation and enabled comparison. Track future work on the
[organization roadmap](https://github.com/orgs/guardtrellis/projects/1).

This document resolves the grammar, processing-error and coordinate questions. The
maintainer subsequently authorized local preparation and evaluation of the 48-scenario
batch, with expectations frozen before scanning, and issue/organization-board updates.
SDK changes, commit, push, merge and publication remain outside that authorization.
Six earlier exploratory prefix probes are disclosed in #109; they are not this formal
batch or an accuracy estimate.

## Outcome and evidence boundary

Recognize selected Stripe account-level credential shapes in explicitly supplied text.
Keep the core local and provider-independent. No Stripe dependency, API request,
credential-validity check, normalization, automatic decoding or authorization mechanism.

[Stripe's key guide](https://docs.stripe.com/keys), reviewed on 2026-11-24, distinguishes
secret/restricted keys from publishable keys and documents test/live prefixes. It does
not establish the complete suffix grammar or lifetime length bounds proposed here.

Two pinned detector implementations illustrate differing heuristics:

- [Gitleaks at `c11adc91`](https://github.com/gitleaks/gitleaks/blob/c11adc91ad701db3e2c8df030f747086ebca8847/cmd/generate/config/rules/stripe.go)
  uses a 10-99-character ASCII alphanumeric body in its Stripe rule.
- [TruffleHog at `0fa069c1`](https://github.com/trufflesecurity/trufflehog/blob/0fa069c12f0c7baf431041cd1e564a9c5058846c/pkg/detectors/stripe/stripe.go)
  uses 20-247 for live-key candidates and excludes test keys in that detector.

The **10-247** range below is our selected disclosure-shape policy, not a Stripe-issued-key
specification or coverage guarantee. No source code, fixture keys, entropy exemption,
live verification behavior or additional prefix from those implementations is adopted.

## Proposed API and compatibility

Proposed keyword-only addition: `SecretScanner(stripe_keys=False)`. This argument does
not exist in the current SDK. Require an actual `bool`; reject integers, strings and
other nonboolean values with a static `ValueError` message.

- Disabled mode preserves existing GitHub/AWS/PEM rules, findings, edits, actions and
  limits. It performs no Stripe candidate walk and adds no private Stripe budget.
- Enabled token-only mode retains `Action.BLOCK` by default and supports explicit
  `Action.WARN` and `Action.REDACT`. The selected action applies to old and new token
  findings together; per-family action selection is outside scope.
- `connection_strings=True` continues requiring BLOCK at construction and during use.
  Its existing configuration/error behavior is preserved. Configure scanners once;
  no new concurrent configuration-mutation guarantee is proposed.
- Existing CLI profiles, examples, dependency bounds and historical evidence are unchanged.
  Adoption in a CLI profile or integration requires a separate scope decision.
- No package version changes here. A possible `0.2.1` batch is not a release commitment.

## Exact candidate grammar

All four sensitive prefixes are **case-sensitive**, exact eight-character spellings:

| Prefix | Static finding code |
| --- | --- |
| `sk_test_` | `secret_stripe_secret_test` |
| `sk_live_` | `secret_stripe_secret_live` |
| `rk_test_` | `secret_stripe_restricted_test` |
| `rk_live_` | `secret_stripe_restricted_live` |

The suffix must contain **10-247 ASCII letters/digits**, drawn only from `A-Z`, `a-z`
and `0-9`. Do not use Unicode word classes, case folding, entropy thresholds or special
exemptions for low-entropy synthetic keys or well-shaped placeholder words.

Define delimiter set **D** as exactly these 25 ASCII characters:

| Class | Delimiters |
| --- | --- |
| ASCII whitespace | U+0009 through U+000D, and U+0020 |
| Quotes | U+0022 (double quote), U+0027 (apostrophe), U+0060 (grave accent) |
| Wrappers | `(`, `)`, `[`, `]`, `{`, `}`, `<`, `>` |
| Other punctuation | `,`, `;`, `:`, `=`, `.`, `!`, `?`, `&` |

1. A prefix starts a candidate only at offset zero or immediately after D.
2. Read the maximal candidate through the character before the next D, or end of input.
   The prefix and suffix together are the candidate; surrounding delimiters are excluded.
3. At at most **255 total candidate characters**, accept only the exact prefix and complete
   ASCII suffix above. An empty/short/invalid suffix adds no Stripe finding.
4. The **256th nondelimiter candidate character** exceeds the work budget and returns ERROR;
   it must not produce a shorter match. This also applies to an already-malformed candidate.
5. Advance beyond the candidate. Never reconsider a nested Stripe prefix inside it.
   Existing GitHub/AWS/PEM and enabled URI searches remain independent over their full input.

Every character outside D remains inside the candidate. In particular, underscore,
hyphen, slash, backslash, Unicode letters/digits, combining marks, format controls and
non-ASCII whitespace invalidate an otherwise ASCII candidate. They do not terminate it
and allow a shorter prefix redaction. An embedded prefix preceded by such a character
does not start a candidate. Prefix matching is not a generic `sk_*` or identifier search.

### Unsupported and benign cases

`pk_test_` and `pk_live_` add no Stripe finding and consume no sensitive-prefix attempt.
They are not global exemptions: other secrets or enabled URI findings still apply.

Malformed/short candidates within the work budget add no Stripe finding. A no-finding
result is not credential validation or a benignness decision: sensitive unsupported
scenarios remain misses. Well-shaped fabricated/documentation values still match; their
scenario false positives are retained separately from format-contract conformance.

D itself is a deliberate coverage boundary. A delimiter-split or masked disclosure can
contain an independently matching left segment and leave other fragments untouched.
For example, periods or spaces can split a string that an author intended as one masked
key. Do not claim complete protection of that unsupported disclosure, even if REDACT
removed a supported segment. Freeze and report such partial outcomes explicitly.

Defer `sk_org_`, `whsec_`, `*_prod_`, other vendors, verbal/encoded/obfuscated forms,
Unicode normalization and broader delimiters. Expanding D or the suffix range changes
coverage and requires separately reviewed cases and documentation.

## Spans, actions and checked delivery

Finding/edit coordinates are half-open Python-character intervals `[start, end)` in the
**current SecretScanner input revision**, including the complete prefix and suffix.
They are not byte offsets or necessarily offsets in the original Guard ingress string.
[Guard's pipeline](../src/guardtrellis/guard.py) stamps the revision that existed before
applying that scanner's edits; an earlier redactor can change both text length and revision.
Do not invent a reverse map to the original input or serialized JSON.

Retain [existing aggregation](../src/guardtrellis/scanners.py): individual overlapping
findings count separately; findings are sorted by start/end/code; only overlapping REDACT
edits are merged. Replacement remains `[SECRET]`, with surrounding text preserved.

| Result | Checked delivery |
| --- | --- |
| No old/new findings | ALLOW, unchanged text. |
| WARN with findings | Original text remains deliverable; a warning is not withholding. |
| REDACT with findings | Only the complete checked text from `require_text()` is consumed. |
| BLOCK or ERROR | No checked text or downstream consumption of this result; no raw fallback. |

This gate applies to downstream use of the checked result. OUTPUT checks occur after
the model/application callback; RETRIEVAL or tool-result checks occur after a tool returns.
Rejection cannot undo an earlier invocation, state change, capture or other side effect.

Use only static finding/error codes and offsets in supported diagnostics. No token fragments,
raw/checked strings, parser errors, environment values or exception messages in reports/logs.
This is not secure memory erasure, prevention of earlier capture or control of host logging.

## Limits, atomicity and precedence

These private limits apply only when Stripe detection is enabled, including direct
`SecretScanner.scan` calls. Raising `Guard.max_chars` does not relax them.

| Budget | Maximum | Exceeded outcome |
| --- | ---: | --- |
| Scanner input | 100,000 Python characters | `stripe_key_limit_exceeded` |
| One candidate, including its eight-character prefix | 255 characters | `stripe_key_limit_exceeded` |
| Boundary-eligible sensitive-prefix attempts | 256 | `stripe_key_limit_exceeded` |
| Combined individual findings from existing tokens/PEM, Stripe and enabled URIs | Existing 256 | Existing `finding_limit_exceeded` |

Count every eligible sensitive prefix, including empty, short and malformed candidates.
Left-boundary-ineligible prefixes and publishable prefixes do not consume an attempt.
Do not count only successful findings. Check the input cap before walking; for each eligible
prefix, count/check the attempt before reading its candidate.

For a direct scanner call, preserve this precedence:

1. Existing enabled-URI runtime configuration rejection returns
   `connection_string_configuration_error` before any content walk.
2. Consume the complete bounded URI preflight when enabled. Its limit/error outcomes retain
   precedence: `connection_string_limit_exceeded`, or `scanner_error` for an unexpected
   ordinary failure. Do not return early because a Stripe or existing token would match.
3. Consume the complete bounded Stripe preflight. Its budget overflow returns
   `stripe_key_limit_exceeded`; an unexpected ordinary helper failure returns `scanner_error`.
4. Collect old/new findings under the shared 256-finding ceiling, then form the final Check.

Every error above is a spanless ERROR with one static reason, no partial success findings
or edits, and no checked delivery. A late overflow overrides earlier matches under WARN,
REDACT and BLOCK. Do not suppress `KeyboardInterrupt` or `SystemExit` as ordinary failures.
Guard ingress can reject with `text_limit_exceeded` before invoking the scanner; that is a
separate existing boundary. Constructor validation remains separate from scan-time results.

Increasing per-call budgets, streaming, cancellation changes or hard SDK deadlines are
outside scope. Resource measurements use external containment; they do not establish
latency, throughput or production-capacity guarantees.

## Evaluation sequence and proposed batch

### Phase A: #109, current SDK only

With this contract accepted, author and review the formal corpus/projections/protocol. Freeze
their bytes and provenance before the first formal SDK observation. No fixture is frozen
or scanned by this draft. Historical corpora, reports, SDK source/defaults and dependencies
remain unchanged. No shadow detector, copied regex implementation or new SDK argument in
the baseline harness; future enabled expectations are authored data only.

Propose **48 public, Codex-assisted synthetic development scenarios**:

| Group | Count | Meaning |
| --- | ---: | --- |
| Sensitive-prefix/length scenarios | 24 | Four prefixes times suffix lengths 9, 10, 24, 99, 247, 248: 16 in-range shapes and eight excluded-length controls, not 24 supported positives. |
| Publishable/benign-context controls | 12 | Six publishable-prefix/length controls plus six prose, syntax-reference, case/prefix/embedding and well-shaped-documentation lookalikes. Shape-matching benign intent may intentionally produce an enabled-mode false positive. |
| Malformed, mixed-content and span/delivery scenarios | 12 | Unicode-prefix offsets; invalid underscore/Unicode/mark/control/slash continuations; delimiter-split masks; multiple/nested candidates; PEM overlap; publishable-plus-legacy-secret; secret-plus-PII; punctuation wrappers. Each case gets an explicit primary family, label and rationale. |

Fixtures use independently generated fabricated values, never keys copied from vendor or
scanner examples. Record authorship, self-review and any actual independent review. These
are not held-out, blinded, representative or independently authored efficacy evidence.

The four suffix-length-9 controls expect no Stripe finding when otherwise eligible and
within budget. The four suffix-length-248 controls exceed the candidate budget when
boundary-eligible in enabled mode; they are processing-error controls, not supported
positives. Freeze their exact outcomes per representation rather than assuming a fixed
number of ERROR cells from the plain-text lengths alone.

Use four representations: plain text, literal JSON, fully Unicode-escaped JSON and one
explicitly decoded fixed `value` field. Both wire encodings must strictly decode to the same
value; count one decoded observation. No recursive decoding. Cap authored values at 1,024
Python characters and every represented input at 8,192; validate these bounds before freeze.

Freeze format-contract eligibility, action, findings and spans independently for every
scanned representation. Projecting desired protection intervals does not establish that
a representation meets the candidate grammar. JSON escaping can add a nondelimiter
backslash after a candidate, invalidating it or taking a 255-character candidate over its
budget; an escaped leading newline can make a prefix boundary-ineligible. Include quoted
and leading-newline controls within the 12 mixed/span scenarios, with differing plain,
literal-JSON, raw-escaped and decoded expectations where required. Do not add decoding or
change D to make the representations agree. Fully Unicode-escaped JSON has no literal
sensitive prefix and is a no-decoding control, not supported encoded-key detection.

Run three fixed current-API profiles at RETRIEVAL, all with `Guard.max_chars=8_192`:

| Profile | Ordered scanners |
| --- | --- |
| `secret_block` | Default `SecretScanner()` |
| `secret_redact` | `SecretScanner(action=Action.REDACT)` |
| `handoff` | Default `SecretScanner()`, then default `PIIScanner()` |

Each profile performs one scan, then passes only `require_text()` to a local recording
consumer when permitted. BLOCK/ERROR must produce no consumer call. This checks a text
handoff; it does not imply host interception, tool authorization or safe prior tool execution.

This is **48 x 4 x 3 = 576 correlated baseline observations**, not 576 independent cases.
Split into four fixed 12-case chunks per profile: 12 bounded children, 48 observations each.
Propose a 10-second wall budget per child, 64 KiB stdout/stderr capture, a 180-second parent
observation budget and separately bounded cleanup. Use the existing native Windows launch
and kill/reap pattern. Preserve incomplete work and unknown resource metrics honestly.

### Separate resource and harness controls

Freeze eight compact resource recipes separately from the 48-case accuracy/delivery corpus:
100,000/100,001 input characters; 255/256 candidate characters; 256/257 malformed sensitive
prefix attempts; and 255/256 existing GitHub findings plus one Stripe-shaped candidate.
The latter pair yields 256/257 combined findings only in the later enabled implementation.

For each recipe, observe direct BLOCK scanning and Guard BLOCK scanning with
`max_chars=200_000`: 16 resource observations in eight contained children. Freeze distinct
current-default and future-enabled outcomes; the old SDK has no Stripe private budgets.
Keep these counts/errors/timings outside primary accuracy denominators. Child containment
is external, not an SDK execution deadline. Available CPU/RSS describe the whole child.
Use the same proposed 10-second child wall budget, 64 KiB stdout/stderr capture and
180-second parent observation budget per resource pass, with separately bounded cleanup.
Freeze the complete expected row inventory and bounded, payload-free output schema before
scanning; a partial child must not silently remove its missing observation.

Add separately counted harness controls for legacy Unicode offsets, an earlier PII redactor
followed by a supported legacy-secret redactor, Guard ingress limits and supervised cleanup.
Freeze their exact inventory before scanning. Do not change a main profile by case to make
such a control pass. WARN, every Stage, invalid options, late limits and URI/Stripe error
precedence also need targeted #110 regressions; they are not extra main-matrix accuracy rows.

### Phase B: #110, separately accepted implementation

After maintainer acceptance of the contract and reviewed #109 baseline, implement only the
selected opt-in. Reuse the exact frozen cases/projections with the same three profiles in
default and explicitly enabled modes: **1,152 fresh comparison observations**. Retain the
original 576-observation baseline separately. Execute enabled resource expectations only
when the real SDK option exists; do not fake them in the baseline harness.
Rerun all eight resource recipes in both default and enabled modes: **32 fresh resource
observations** in 16 contained children, one per recipe/mode, under the frozen resource
bounds and schema. Keep these separate from the 1,152 comparison observations.

Default mode must match retained contract expectations. Any supported-contract or default
compatibility failure pauses acceptance for triage. Do not relabel failures or change corpus
bytes to fit the implementation. Later revisions require explicit, attributable versions.

## Freeze, scoring and delivery gates

- Freeze protocol, case recipes/labels, desired full intervals/output/delivery, current
  contract expectations, future enabled expectations, deterministic representation projector
  and author-review record before the first formal scan. Record contract eligibility,
  action and spans for each representation separately from desired protection. The projector
  must import no SDK, search for no secret patterns and derive no expectations from observed
  output or by copying plain-text eligibility into another representation.
- Record a pre-observation digest receipt in #109/#45 after separately authorized publication.
  Record SDK/source/example/lock hashes, interpreter/platform and actual installed versions
  for every run. Historical manifests remain immutable; new runtime identity is not hidden.
- Separate primary-family findings from incidental legacy/PII findings and overall action.
  A legacy block or PII redaction is not a Stripe detection. Attribute multiple keys explicitly;
  additional entities do not silently inflate independent-scenario counts.
- Report per-prefix/policy/representation counts, TP/FP/TN/FN and undefined rates as null,
  plus exact spans, complete desired protection, actual checked delivery and contract matches.
  Retain benign-context false positives, unsupported misses and partial redactions. No
  arbitrary accuracy target, superiority claim or population/general-language claim.
- ERROR and incomplete work are separate from detection and never credited as TP. Keep
  expected/missing denominators visible. Expected limit ERROR may conform to a processing
  contract while failing the authored desired outcome; do not collapse those judgments.
- Reports allow only validated static IDs/codes, offsets, counts, comparisons and source/runtime
  identity. Exclude raw/checked text, replacements, credential fragments, arbitrary paths,
  environment values and exception messages. Reap children before deleting temporary work.
- #109 acceptance needs frozen/reviewed baseline, relevant harness/privacy/cleanup regressions
  and submitted-revision native Windows/macOS/Linux plus processed Python/Actions CodeQL.
  #110 additionally needs action/stage/configuration/span/error/delivery regressions,
  default/enabled comparisons, externally bounded probes, documentation/changelog and fresh
  wheel/sdist verification. Local evidence does not establish native CI or publication.

## Acceptance gate

The maintainer accepted this design on 2026-11-24 and authorized the local evaluation
batch. Acceptance of the reviewed baseline is still required before starting #110.
No runtime implementation is accepted by design approval alone. Commit/push, merge and
release remain separate authorization gates; native CI remains unverified until an
authorized submitted revision runs.
