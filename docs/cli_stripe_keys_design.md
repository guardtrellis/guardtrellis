# Stripe account keys in the CLI: accepted contract

Status: **Design accepted by the maintainer, 2026-11-26; implementation not started.**
A candidate for the `0.2.2` batch, without a release commitment.
[#115](https://github.com/guardtrellis/guardtrellis/issues/115) records the accepted design;
the [organization roadmap](https://github.com/orgs/guardtrellis/projects/1) tracks it as
**Done / Now / P2**. Separate implementation
[#116](https://github.com/guardtrellis/guardtrellis/issues/116) is **Ready / Now / P2**,
awaiting an instruction to start runtime changes.

The existing [CLI contract](policy_testing_design.md), [CLI guide](cli.md) and
[Stripe account-key contract](stripe_keys.md) remain authoritative for shipped behavior.
This contract adds an explicit CLI selection of the existing SDK capability. It does
not revise the detector, frozen evaluation assets or historical accepted designs.

## Outcome and scope

A developer checks one explicitly chosen UTF-8 file or stdin fixture with the existing
`secrets` or `privacy` policy and explicitly enables Stripe account-key checking.
Both `guardtrellis check` and `python -m guardtrellis check` use the same behavior.
The selected stage remains required: `input`, `output`, `retrieval` or `tool`.
This extends the terminal/CI fixture workflow accepted in #31 and implemented in #78;
it does not establish a new external adopter or IDE enforcement boundary.

Accepted target commands, **not supported by released `0.2.1`**:

```sh
guardtrellis check --file fixture.txt --stage retrieval --policy secrets --stripe-keys --format json
python -m guardtrellis check --stdin --stage retrieval --policy privacy --stripe-keys --output checked-text
```

- Add only the exact, valueless `--stripe-keys` flag, absent by default.
- Enable it under either fixed policy; it may combine with `--connection-strings`.
  `--phone-mode` remains valid only under `privacy`.
- Reject repeated/abbreviated/unknown flags, `--stripe-keys=true`,
  `--stripe-keys=false`, a separate boolean argument and `--no-stripe-keys` before
  reading input. These are `invalid_command`, exit 2. Help/version remain standalone
  forms; combining either with the new flag is still invalid.
- Preserve explicit source selection, stage/policy validation and environment-independent
  configuration. Add no report-version selector, policy file or environment switch.

## Scanner composition and compatibility

`secrets` selects `SecretScanner(action=Action.BLOCK, connection_strings=selected,
stripe_keys=selected)`. `privacy` uses that same secret scanner followed by the existing
`PIIScanner(action=Action.REDACT, phone_mode=selected)`.

Omitting the flag keeps `stripe_keys=False` and the existing policies. In particular,
it adds no Stripe candidate walk or private Stripe limit. Selected secret detection
blocks before PII redaction. No new CLI secret WARN/REDACT action is introduced.
Results must match the same public SDK composition, input and stage.

Only the already-supported `sk_test_`, `sk_live_`, `rk_test_` and `rk_live_` account-key
shapes are selected, with existing codes, maximal-candidate parsing, delimiter rules,
Python-character spans and exclusions. Publishable `pk_test_`/`pk_live_` values add no
Stripe finding; they never exempt independent secret findings. Contextual false positives,
malformed/escaped misses and partial protection of unsupported forms remain documented.
Webhook/organization keys, generic `sk_*`, implicit JSON decoding, normalization, credential
validation, new dependencies, provider requests and directory scans are outside scope.

## Accepted report-version decision

Use **version 1 without the flag; version 2 when the flag is selected**. Select the
version from validated configuration, never from the scan outcome or whether a key was
found. An unsupported version must fail closed in a consumer; never retry without the
flag or silently strip its metadata to satisfy a version-1 consumer.

| Invocation | JSON `report_version` | Exact `options` keys |
| --- | ---: | --- |
| Any existing invocation, flag absent | 1 | `connection_strings`, `phone_mode` |
| Valid configuration with `--stripe-keys` | 2 | `connection_strings`, `phone_mode`, `stripe_keys` |

Version 2 retains the exact version-1 top-level keys: `report_version`, `sdk_version`,
`stage`, `policy`, `options`, `result`, `error`. The version is an integer, not a boolean.
`connection_strings` is a strict boolean; `phone_mode` is null for `secrets` and the
selected `contiguous`/`formatted` string for `privacy`; `stripe_keys` is the strict boolean
`true`. This CLI emits no version-2/`stripe_keys=false` combination in this increment.
Do not add `stripe_keys:false` to version 1. `sdk_version` continues reporting the
installed package version, independently of the report schema version.

An illustrative selected-mode ALLOW envelope is:

```json
{"report_version":2,"sdk_version":"<installed version>","stage":"retrieval","policy":"secrets","options":{"connection_strings":false,"phone_mode":null,"stripe_keys":true},"result":{"action":"allow","stage":"retrieval","findings":[],"trace":[{"scanner":"secrets","scanner_index":0,"action":"allow","revision_before":0,"revision_after":0}]},"error":null}
```

Retain the existing one-line UTF-8 JSON encoding, ASCII escaping, compact separators,
key order and final LF. With the same package version, existing invocation/input reports
remain byte-identical. Help gains one static flag description; `--version` keeps its
existing installed-version behavior. No package version is changed by this design.

Human text reports retain their existing grammar without the flag. When selected, append
the static ` stripe_keys=true` immediately before LF on both result and wrapper-error
reports. There is no false marker on old commands. JSON carries selection only in
`options`, rather than adding another result or finding field.

After valid configuration, version 2 and the selected marker also apply to input/encoding/
ingress failures, handled preparation interrupts and runtime errors whenever a structured
report is produced. Preserve `result:null` plus static `error.code` for wrapper failures;
SDK ERROR keeps diagnostics in `result` and `error:null`.

Distinguish output-destination validation from input-source validation. The following
paths assume otherwise valid arguments and successful report writes/flushes:

| Terminal condition | Phase and outcome | Report channel and form |
| --- | --- | --- |
| `--output checked-text` with terminal stdout, either source | Reject before probing/reading input or scanning; exit 2. This output gate wins even when selected stdin is also a terminal. | Empty stdout; exact static ASCII `guardtrellis: invalid_configuration\n` on stderr, including with `--format json`. No schema-version field or selected marker. |
| `--stdin` with terminal stdin, `--output metadata` | After configuration, reject the input source without reading bytes or scanning; exit 2. Terminal stdout is allowed in metadata mode. | One selected-format `invalid_source` wrapper report on stdout; empty stderr. |
| `--stdin` with terminal stdin, `--output checked-text` and non-terminal stdout | After destination validation, reject the input source without reading bytes or scanning; exit 2. | One selected-format `invalid_source` wrapper report on stderr; empty stdout. |

For both terminal-stdin paths, JSON contains `result:null` and
`error:{"code":"invalid_source"}`: version 2 with `options.stripe_keys:true` when the
flag is selected, otherwise the unchanged exact version-1 schema. Text uses
`stage=<selected-stage> error=invalid_source stripe_keys=true\n` when selected, otherwise
the existing line without that marker. `--file` never probes unused stdin or rejects
because stdin is a terminal; its checked-text stdout gate still applies.

Other existing configuration rejections, outer fallback interrupts/errors and broken-output
fallback lines remain static ASCII without a JSON envelope, as in the shipped contract.
Failed/partial streams never promise a complete schema record. Existing output-failure
and interruption precedence also applies to the terminal-error reports above.

`examples/cli_ci.py` deliberately validates its exact version-1 privacy/URI/formatted-phone
invocation. Keep that invocation and strict validator unchanged: selected-mode version-2
records must be rejected by it, including a superficially clean ALLOW. Document that
Stripe-aware machine consumers must explicitly support version 2 and validate the selected
options plus existing result/error/exit/delivery requirements. Do not add a second consumer
or relax the old gate solely to demonstrate this flag.

Alternatives rejected for this slice: adding an optional key under version 1 breaks exact
consumers; upgrading every command to version 2 changes old workflows; a separate report
version flag adds negotiation and invalid combinations without a demonstrated caller need.

## Bounds, errors and checked delivery

Preserve existing CLI ceilings: 400,000 ingress bytes, 100,000 decoded Python characters,
128 KiB encoded metadata and 400,000-byte/100,000-character checked output. Preserve strict
UTF-8, literal CRLF/BOM/NUL handling, file-type checks, no file rewriting and no hard command
deadline. Shell redirection can still truncate an input before the CLI starts.

Enabled Stripe checking retains the SDK's private 100,000-character input, 255-character
candidate, 256 eligible-prefix-attempt and shared 256-finding limits. Ingress overflow is
exit 2 before scanning. Stripe candidate/attempt overflow yields SDK
`stripe_key_limit_exceeded` ERROR, and shared finding overflow retains
`finding_limit_exceeded`; both are exit 3, never successful detections. Preserve URI
configuration/preflight precedence, complete Stripe preflight and atomic secret-check
errors. No partial successful secret findings or checked bytes escape a late ERROR.

Keep exit codes 0 accepted/help/version, 1 BLOCK, 2 configuration/input failure, 3 SDK/
runtime/report/output failure and 130 handled interruption, including existing precedence.
Metadata remains on stdout by default. `--output checked-text` requires non-terminal
stdout, sends metadata to stderr, then writes only accepted `require_text()` UTF-8 bytes
after a successful metadata write/flush. BLOCK/ERROR withholds checked stdout; output failure
may leave partial accepted bytes, which the caller must discard on nonzero exit.
No report includes payload, replacement text, argv, path, exception message or timings.
Existing sensitive-offset/count caveats and downstream-only enforcement still apply.

## Implementation acceptance gates

1. This contract is accepted; #116 scopes implementation separately. Review that scope
   and obtain a separate instruction before runtime changes.
2. Extend only CLI parsing/configuration, existing scanner construction and metadata rendering.
   Keep scanner/Guard behavior, dependencies, version and frozen evidence unchanged.
3. Prove old-command/report equivalence and unchanged strict version-1 consumer behavior.
   Cover parser rejection before reads, both policies/all four stages, both sources,
   both metadata formats and output modes, and combinations with URI/formatted-phone options.
4. Check all four supported account prefixes, publishable/benign/malformed/escaped controls,
   mixed legacy/Stripe/PII inputs and parity with the selected SDK composition. Assert exact
   checked bytes and static metadata without sensitive fixture/path canaries.
5. Cover candidate/attempt/shared-finding boundaries and late failures; retain separate SDK
   ERROR versus wrapper input/runtime errors, selected version-2 error envelopes and
   output write/flush/interrupt withholding. Cover old-consumer rejection of version 2
   and the explicit terminal regression requirements below.
6. Update CLI/coverage/compatibility documentation and bounded installed wheel/sdist smokes
   for both launchers. Follow repository-required checks; native Windows/macOS/Linux and
   processed Python/Actions CodeQL are submission gates after separate push authorization.

### Required terminal regressions for the implementation

These are future behavior/protocol tests, not tests run or implemented by this design change.
Use simulated stream/probe failures for portable coverage, including native Windows CI;
retain the existing real POSIX terminal coverage separately, without claiming Windows ran it.

- Exercise the terminal matrix above with the flag absent/selected, both policies,
  both metadata formats and applicable output modes. Assert exact channel placement,
  error code, exit status, strict version/options shape or text marker, and no input-byte
  reads or scanner invocation on rejection. Metadata stdout may itself be a terminal.
- For checked-text stdout TTY, cover `--stdin` and `--file`, including empty, benign
  and potentially blocked fixtures. Assert the exact static stderr line and empty stdout
  before any stdin probe, file open/read or scan. When both streams are terminals,
  `invalid_configuration` wins over `invalid_source` in checked-text mode; metadata mode
  instead produces the selected-format terminal-stdin wrapper.
- For terminal stdin with non-terminal checked-text stdout, assert `invalid_source` on
  stderr and no checked bytes. For metadata mode assert the same wrapper on stdout and
  empty stderr. JSON must have `result:null`, the exact static error object, version 2
  plus boolean `stripe_keys:true` when selected, and the unchanged version-1 shape otherwise.
- For `--file`, use an unused stdin probe that would fail if called: an eligible regular
  file must still be checked in metadata mode, including terminal stdout, and in checked-text
  mode with non-terminal stdout. Preserve the separate output-TTY rejection before file reads.
- Preserve probe-failure phases with fault injection: checked-text stdout `isatty()`
  ordinary failure gives static stderr `output_io_error`/exit 3 before input and retains
  failed-stdout cleanup; interruption gives static stderr `interrupted`/130. Selected
  stdin `isatty()` `OSError`/`ValueError`/`AttributeError` gives a selected-format
  `input_io_error` wrapper/2, another ordinary exception gives `runtime_error`/3, and
  interruption gives `interrupted`/130. On input-probe failure, assert zero byte reads and
  no scanner invocation; route wrappers by output mode and retain selected version 2/marker
  or absent-flag version 1.
- For emitted terminal/probe-error reports, retain output write/flush failure precedence,
  payload withholding, no raw fallback, no sensitive canaries and no second report.
  A broken channel may leave a partial record; only successful emission promises the exact
  complete record. Keep the selected text marker and final LF within the metadata byte cap.

The organization roadmap records design #115 as **Done / Now / P2 / S / design /
python-runtime** and separate implementation #116 as **Ready / Now / P2 / M / feature /
python-runtime**, without an assignee or delivery date. Ready means scoped work awaiting
a separate start instruction, not implementation in progress. Feed relevant evidence to
#45/#46 without closing their broader work or counting tests/docs as another release
improvement. Webhook coverage is a separate proposed update and is not accepted or
implemented by these issues.

Current authorization permits accepting this design, updating its issue and board status,
and creating/scoping #116. SDK behavior remains unchanged and implementation has not started.
It does not authorize commit, push, merge, security-setting changes or publication.
