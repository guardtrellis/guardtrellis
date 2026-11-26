# Check one local fixture

Added in `0.1.9` through [#78](https://github.com/sahilmathur254/guardtrellis/issues/78).
See [PyPI](https://pypi.org/project/guardtrellis/0.1.9/) for availability.
The `0.1.8` package has no CLI. From this checkout, install into an activated
environment with `python -m pip install -e .`, or use the repository's locked `uv sync`.
Both `guardtrellis check` and `python -m guardtrellis check` use the same core implementation;
optional provider dependencies and credentials are unnecessary. No network requests occur.

```sh
guardtrellis check --file fixture.txt --stage retrieval --policy privacy --format json
python -m guardtrellis check --stdin --stage retrieval --policy secrets --connection-strings
```

Select exactly one source (`--file PATH` or `--stdin`), one explicit `--stage`
(`input`, `output`, `retrieval`, `tool`) and one `--policy`. `secrets` blocks selected secret
signatures. `privacy` blocks secrets first, then redacts supported personal details.
There is no default/empty policy, automatic stdin selection, payload argument, recursive
scan, manifest, custom scanner/action or file rewrite. `tool` is a text-scanning stage;
tool schema checks and authorization remain with `ToolGuard` and its host.

| Option | Default and meaning |
| --- | --- |
| `--connection-strings` | Absent/false. Explicitly enable BLOCK-only supported PostgreSQL/MongoDB credential URIs. |
| `--stripe-keys` | **Unreleased source checkout only; unavailable in published `0.2.1`.** Absent/false; select the existing bounded Stripe account-key detector with BLOCK under either policy. |
| `--phone-mode contiguous\|formatted` | `contiguous` under `privacy`; invalid with `secrets`, including an explicit `contiguous`. |
| `--format text\|json` | `text`; affects metadata only. |
| `--output metadata\|checked-text` | `metadata`; checked text requires non-terminal stdout. |
| `--help` / `-h`, `--version` | Use alone, optionally after `check`; no input is read. |

Valued options may use `--name=value`. The valueless `--connection-strings` and
`--stripe-keys` flags do not accept `=true`, `=false` or a separate Boolean value.
Unknown, repeated, abbreviated, conflicting and invalid
options reject before reading input, even if help or JSON was also requested.
Configuration is independent of environment variables. Source paths can still be exposed
by the caller's shell tracing or CI logs.

## Reports and checked delivery

Default output contains only metadata. Human reports contain the selected stage, action,
finding count and static finding codes. When `--stripe-keys` is absent, JSON retains the
version-1 envelope and exactly the two option keys shown below. This historical example
uses SDK `0.1.9`; `sdk_version` always identifies the actual installed package:

```json
{"report_version":1,"sdk_version":"0.1.9","stage":"retrieval","policy":"secrets","options":{"connection_strings":false,"phone_mode":null},"result":{"action":"allow","stage":"retrieval","findings":[],"trace":[{"scanner":"secrets","scanner_index":0,"action":"allow","revision_before":0,"revision_after":0}]},"error":null}
```

**Unreleased source behavior:** selecting `--stripe-keys` selects `report_version: 2`,
with the same exact top-level keys (`report_version`, `sdk_version`, `stage`, `policy`,
`options`, `result`, `error`). Its exact options object adds `"stripe_keys":true` to
`connection_strings` and `phone_mode`. `connection_strings` is a Boolean; `phone_mode`
is null under `secrets` and `"contiguous"` or `"formatted"` under `privacy`.
There is no emitted version-2 false setting and no added `stripe_keys` key in version 1.
Selection determines the schema even for ALLOW, zero findings and structured failures;
it does not change `sdk_version`. JSON remains one compact ASCII-escaped UTF-8 line
with a final LF. Selected human reports append the exact static ` stripe_keys=true`
immediately before the LF, including wrapper-error reports. Existing human reports
remain unchanged when the flag is absent.

`result` is the SDK's `Result.diagnostics()` structure. A wrapper error sets `result` to
null and `error` to `{"code":"STATIC_CODE"}`. An SDK ERROR keeps SDK diagnostics in `result`
and leaves `error` null. No report contains source/checked text, replacements, source paths,
argv, environment values, exception messages or timings. Offsets and counts are still
potentially sensitive metadata. See [the accepted contract](policy_testing_design.md)
for the original static error-code set and failure precedence, and the
[accepted Stripe CLI contract](cli_stripe_keys_design.md) for the selected schema.

`--output checked-text` sends the report to stderr and accepted UTF-8 bytes to stdout.
The command buffers and bounds both, then writes and flushes the report before releasing
payload bytes. Stdout is exactly `result.require_text()` with no added newline. BLOCK and
ERROR produce no checked text. A direct stdout TTY destination rejects before source
probes, reads or scanning, even for empty or blocked content. It exits 2 with empty
stdout and only `guardtrellis: invalid_configuration` plus LF on stderr, including
JSON/Stripe selections. This gate precedes terminal-stdin rejection. There is no
unsafe-terminal override. Accepted escape
sequences remain unchanged in a pipe/file; a later renderer is the host's responsibility.

An output failure exits 3. A metadata failure withholds all payload; a payload failure can
leave a prefix after a successful scan record. No second report is appended. Always discard
checked stdout on nonzero exit; the scan record alone does not prove successful delivery.
Successful writes/flushes guarantee a complete report; a broken channel may contain only
a partial record. Failed standard streams are neutralized for interpreter cleanup.

| Exit | Meaning |
| --- | --- |
| 0 | ALLOW, REDACT or WARN; also help/version. These profiles have no WARN scanner. |
| 1 | BLOCK. |
| 2 | Invalid command/configuration/source, input I/O, encoding or ingress bounds. |
| 3 | SDK ERROR, wrapper/runtime/output/report failure. Overrides ordinary 0/1/2. |
| 130 | Handled KeyboardInterrupt, including failure of its best-effort report. |

Configuration failures always use one static ASCII stderr line and empty stdout, even
with `--format json`. Once configuration is valid, input/runtime errors retain the selected
report format and output channel. Unexpected failures after entry are sanitized.
Shell launch errors or broken imports before entry are outside this report contract.

## Bytes, files and deadlines

Input is strict UTF-8, at most 400,000 bytes and 100,000 Python characters. The reader
consumes at most 400,001 bytes. Invalid UTF-8/surrogate encodings reject. Empty input is
valid. BOM, CRLF/LF, NUL and Unicode are preserved without normalization. Files must be
regular both before opening and at descriptor validation; symlinks to regular files are
allowed. This is no filesystem sandbox or immutable snapshot. A selected pipe requires
EOF. `--stdin` rejects terminal stdin as a valid-configuration `invalid_source` report:
metadata mode writes that report to stdout with empty stderr (stdout may itself be a
TTY); checked-text mode with non-terminal stdout writes it to stderr and leaves stdout
empty. Both exit 2. A valid `--file` selection never probes unused stdin, while the
checked-output TTY gate still runs before opening the file.

Reports are at most 128 KiB including their final LF. Checked output is at most 400,000
bytes/100,000 characters. Overflow becomes a compact static error rather than truncating
findings or text. The fixed Guard uses the existing scanner finding and URI work budgets.
Selecting unreleased `--stripe-keys` also inherits the SDK's 100,000-character input,
255-character maximal-candidate and 256 eligible-candidate-attempt limits, plus the
shared 256-finding cap. Candidate/attempt exhaustion is an SDK ERROR with no checked
bytes, rather than a detection result. URI/Stripe work exhaustion exits 3, distinct
from CLI ingress overflow (exit 2). See the [Stripe grammar and limits](stripe_keys.md).

The CLI opens input files read-only. **Never redirect stdout or stderr to that input or an
alias:** shells can truncate it before Python starts. Use process capture or a distinct
destination, then check the status. The CLI cannot restore prior shell truncation.

There is no built-in hard I/O or whole-command deadline. A stalled pipe, output consumer,
or changing filesystem can block. The host owns a process timeout, termination and reaping;
the [CI example](../examples/cli_ci.py) uses `subprocess.run(..., timeout=15)` for this boundary.
External termination retains platform-specific status. It is separate from handled Ctrl-C.

## Strict PII CI and limitations

REDACT exits zero because the transformed value is accepted. For a zero-findings gate,
retain `privacy` and inspect the report; changing to `secrets` removes PII coverage.
The bounded [Python CI example](../examples/cli_ci.py) requires exit 0, empty stderr, a
complete version-1 report matching the selected stage/policy/options, ALLOW and no findings.
It rejects malformed/duplicate/mismatched/error reports and prints no captured content:

```sh
python examples/cli_ci.py fixture.txt
```

That example stays a strict version-1 consumer: it rejects every version-2 report,
including a clean Stripe-selected ALLOW. A Stripe-aware integration must explicitly
support version 2 and validate its complete schema, selected options, result/error,
exit status and successful delivery. Do not strip the new option, downgrade reports,
retry without the flag or fall back to raw input after rejection.

The CLI preserves the [connection-URI grammar and exclusions](connection_strings.md).
URI passwords can pass the default secrets policy; enable `--connection-strings` explicitly.
The privacy policy without that option can redact only an incidental email-like URI portion.
Raw escaped JSON remains raw; decoding belongs to the application. No driver validation,
database connection or guarantee about arbitrary secrets is added. Detection and delivery
remain distinct, as in the [control coverage](coverage.md) and [limitations](limitations.md).
The unreleased Stripe selection uses the same existing account-key grammar under both
policies: supported `sk_test_`, `sk_live_`, `rk_test_` and `rk_live_` candidates block
before privacy redaction. Publishable `pk_` shapes are benign for this detector and do
not exempt independent findings. It adds no webhook/organization-key coverage, live
credential validation, implicit decoding or provider calls. The flag can combine with
`--connection-strings`; `--phone-mode` remains exclusive to `privacy`.

If the command is unavailable, verify `python -m pip show guardtrellis` in the active
environment and reinstall the intended version. `python -m guardtrellis --version` avoids
a stale console launcher but still needs a working installation and dependencies.
Supported native CI targets remain Linux Python 3.11–3.14, macOS and Windows. Both wheel
and sdist installed launchers run byte-protocol smokes outside the checkout; local macOS
results alone do not establish native Windows success.
Native Windows CI for the unreleased `--stripe-keys` change remains unverified until
an authorized push and its checks complete.

See the [local validation record](cli_validation.md) for executed checks, connection-URI
comparison results and the remaining native-platform gate.
