# Stripe account-key shapes (0.2.1)

The opt-in `stripe_keys` option is a `0.2.1` addition, merged through
[PR #113](https://github.com/guardtrellis/guardtrellis/pull/113). SDK `0.2.0` does not accept
the argument. Check [PyPI](https://pypi.org/project/guardtrellis/) for published availability;
a source merge or passing candidate checks does not establish package publication.

Select `SecretScanner(stripe_keys=True)` where your application explicitly checks text.
It adds local detection for selected Stripe secret/restricted test/live account-key shapes.
The option is disabled by default, requires an actual boolean, and makes no Stripe API or
credential-validity request. No new dependency or automatic CLI-policy change is involved.

```python
from guardtrellis import Action, Guard, SecretScanner, Stage

guard = Guard(retrieval_scanners=[SecretScanner(stripe_keys=True, action=Action.REDACT)])
synthetic = "Credential: " + "sk_test_" + "A" * 24
result = guard.scan(synthetic, stage=Stage.RETRIEVAL)
print(result.require_text())  # Credential: [SECRET]
```

Consume only checked `require_text()` values when accepted. BLOCK/ERROR exposes no checked
text and must have no raw fallback. WARN deliberately permits the original text. RETRIEVAL
and tool-result checks occur after a tool returns; OUTPUT checks follow the callback.
Rejection cannot undo earlier invocation, capture, logging or other side effects.

## Selected grammar

| Case-sensitive prefix | Finding code |
| --- | --- |
| `sk_test_` | `secret_stripe_secret_test` |
| `sk_live_` | `secret_stripe_secret_live` |
| `rk_test_` | `secret_stripe_restricted_test` |
| `rk_live_` | `secret_stripe_restricted_live` |

A complete suffix has 10–247 ASCII letters/digits, without an entropy or placeholder
exemption. This range is the accepted GuardTrellis disclosure-shape policy, not a universal
Stripe issuance grammar. [Stripe's key guide](https://docs.stripe.com/keys) distinguishes
secret/restricted keys from publishable keys; a signature match does not establish validity.

A candidate starts at offset zero or immediately after one of exactly 25 ASCII delimiters:

- U+0009 through U+000D and U+0020: tab, line feed, vertical tab, form feed, carriage return,
  and space.
- Double quote, apostrophe, grave accent.
- `(`, `)`, `[`, `]`, `{`, `}`, `<`, `>`.
- `,`, `;`, `:`, `=`, `.`, `!`, `?`, `&`.

Read the entire candidate to the next delimiter/end. Every other character remains inside
it. Underscores, hyphens, slash/backslash, Unicode letters/digits/marks/format controls and
non-ASCII whitespace invalidate a candidate rather than permit a shorter ASCII match.
Nested prefixes inside it are not retried. Short/malformed candidates within the budget
produce no Stripe finding; they can still contain sensitive information.

`pk_test_` and `pk_live_` add no Stripe finding or sensitive-prefix attempt. They never
exempt independent GitHub/AWS/PEM or selected connection-URI findings. Well-shaped fabricated
or documentation values can match regardless of benign intent. A delimiter-split/masked
disclosure may have a matching left segment and unprotected remaining fragments; REDACT
does not establish complete protection of that unsupported form.

Webhook `whsec_`, organization `sk_org_`, prod variants, other vendors, verbal/obfuscated
forms, normalization and encoded values remain outside scope. No implicit JSON decoding
occurs. In particular, literal JSON escaping can append a nondelimiter backslash, change
the left boundary or exceed the candidate budget; a plain-text match need not match its
serialized spelling. Explicitly decode a selected value in the host before checking it
when that is the intended application boundary. This option adds no recursive JSON scanner.

## Actions, spans and overlap

Default action remains BLOCK; explicit WARN/REDACT applies to old and new token findings
together. Combining `stripe_keys=True` with `connection_strings=True` requires BLOCK at
construction and use. Configure scanners once and do not mutate them during use.

Findings and edits cover the complete supported prefix/suffix with half-open Python-character
offsets in the **current SecretScanner input revision**. Guard stamps scanner/index/revision.
Earlier redaction can change offsets; there is no reverse map to original ingress, UTF-8
bytes or wire JSON. Individual overlapping findings remain separate; only overlapping
REDACT edits merge. Replacement stays `[SECRET]`, preserving surrounding text.

## Work limits and explicit failure

These private budgets apply only when Stripe mode is enabled, including direct scanner
calls. Increasing `Guard.max_chars` does not relax them.

| Budget | Maximum |
| --- | ---: |
| Input | 100,000 Python characters |
| Candidate including its eight-character prefix | 255 characters |
| Eligible sensitive-prefix attempts, including empty/short/malformed candidates | 256 |
| Shared individual findings across old tokens/PEM, Stripe and enabled URIs | Existing 256 |

The 256th nondelimiter character overflows even an already-invalid candidate. A Stripe
budget overflow returns spanless `stripe_key_limit_exceeded`; shared finding overflow
retains `finding_limit_exceeded`. An ordinary unexpected helper failure yields static
`scanner_error`. These are ERROR outcomes, not true-positive detections.

URI runtime configuration is checked first, then complete URI preflight, complete Stripe
preflight and shared aggregation. URI errors retain precedence; a late Stripe error
overrides earlier matches. No partial successful SecretScanner findings/edits escape an
error. Guard may retain earlier scanners' diagnostics/revision trace while withholding
final checked text. Guard ingress can reject before the scanner with `text_limit_exceeded`.
Sync execution has no new hard deadline; caller-owned isolation remains separate.

## Evidence and status

The [accepted contract](stripe_keys_design.md), [implementation plan](stripe_keys_implementation_plan.md)
and [versioned evaluation](../evaluation/stripe_keys/README.md) distinguish desired protection,
format-contract conformance, incidental findings and checked delivery. Original frozen
cases/expectations and SDK 0.2.0 baseline remain unchanged. Default/enabled comparisons
identify the actual source/runtime and retain expected errors, unsupported
misses, partial redactions and contextual false positives. Public AI-assisted synthetic
development cases do not establish population accuracy or production safety.

The retained [source comparison](../evaluation/stripe_keys/comparison_source_v1/REPORT.md)
matched all 1,152 main, 32 resource and four control contracts, including 39 expected main
limit ERROR outcomes. Known false positives, unsupported misses and partial protection
remain visible. Its recorded local validation passed 2,563 strict checks; the comparison
retains its original 0.2.0 version field and source hashes rather than being relabelled.

Implementation merged through PR #113 at `9087fdb97dce3ae60b527e5dbbca11848cecb622` on
2026-11-26. All 17 active PR checks passed, including the
[native matrix](https://github.com/guardtrellis/guardtrellis/actions/runs/45613735598),
[processed Python/Actions CodeQL](https://github.com/guardtrellis/guardtrellis/actions/runs/45613735643)
and separate candidate installation checks. These validate the reviewed PR revision;
final release-candidate checks, index verification and publication remain separate evidence.
