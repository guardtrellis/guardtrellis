"""Explicit Stripe CLI selection and byte-compatible reports; synthetic, offline inputs."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from guardtrellis import Action, Guard, PIIScanner, SecretScanner, Stage, __version__, _cli
from guardtrellis import scanners as scanner_module
from tests.test_cli import capture

PREFIXES = (
    ("sk_test_", "secret_stripe_secret_test"),
    ("sk_live_", "secret_stripe_secret_live"),
    ("rk_test_", "secret_stripe_restricted_test"),
    ("rk_live_", "secret_stripe_restricted_live"),
)
CANARY = "NeverDiscloseStripeCliFixture42"
LEGACY = "ghp_" + "L" * 36
URI = "postgresql://app:FabricatedCliPassword42@db.example.invalid/demo"
V1 = json.loads((Path(__file__).parent / "fixtures" / "cli_v1_reports.json").read_text())


def token(prefix="sk_test_", suffix=24):
    return prefix + "Q" * suffix


def argv(*, stage="retrieval", policy="secrets", fmt="json", output="checked-text", selected=True):
    return [
        "check",
        "--stdin",
        "--stage",
        stage,
        "--policy",
        policy,
        "--format",
        fmt,
        "--output",
        output,
        *(["--stripe-keys"] if selected else []),
    ]


def assert_v2(report, *, stage="retrieval", policy="secrets", uri=False, phone=None):
    assert list(report) == [
        "report_version",
        "sdk_version",
        "stage",
        "policy",
        "options",
        "result",
        "error",
    ]
    assert type(report["report_version"]) is int and report["report_version"] == 2
    assert report["sdk_version"] == __version__
    assert report["stage"] == stage and report["policy"] == policy
    assert list(report["options"]) == ["connection_strings", "phone_mode", "stripe_keys"]
    assert report["options"] == {
        "connection_strings": uri,
        "phone_mode": phone,
        "stripe_keys": True,
    }
    assert type(report["options"]["connection_strings"]) is bool
    assert type(report["options"]["stripe_keys"]) is bool


@pytest.mark.parametrize("case", V1["cases"], ids=lambda case: case["name"])
def test_unselected_reports_match_independently_captured_original_bytes(monkeypatch, case):
    # These records were captured from git-show e45c759 before the CLI was changed.
    # Only the separately versioned package identifier can vary in a later release.
    data = bytes.fromhex(case["input_hex"]) if "input_hex" in case else case["input"].encode()
    status, stdout, stderr, _, _ = capture(monkeypatch, case["argv"], data)
    original_version = f'"sdk_version":"{V1["sdk_version"]}"'.encode()
    installed_version = f'"sdk_version":"{__version__}"'.encode()
    expected = [
        (
            bytes.fromhex(case[f"{name}_hex"]) if f"{name}_hex" in case else case[name].encode()
        ).replace(original_version, installed_version)
        for name in ("stdout", "stderr")
    ]
    assert (status, stdout, stderr) == (case["status"], *expected)


@pytest.mark.parametrize("prefix,code", PREFIXES)
@pytest.mark.parametrize("stage", list(Stage))
@pytest.mark.parametrize("policy", ["secrets", "privacy"])
@pytest.mark.parametrize("source", ["stdin", "file"])
@pytest.mark.parametrize("fmt", ["json", "text"])
@pytest.mark.parametrize("output", ["metadata", "checked-text"])
def test_supported_keys_block_with_whole_spans_in_every_cli_selection(
    monkeypatch, tmp_path, prefix, code, stage, policy, source, fmt, output
):
    before = f"🪴 {CANARY}: <"
    text = before + token(prefix) + "> Contact demo@example.org"
    command = argv(stage=stage.value, policy=policy, fmt=fmt, output=output)
    path = tmp_path / f"{CANARY} file.txt"
    if source == "file":
        path.write_bytes(text.encode())
        command[1:2] = ["--file", str(path)]
    status, stdout, stderr, read, _ = capture(monkeypatch, command, text.encode())
    metadata = stderr if output == "checked-text" else stdout
    assert status == 1 and not (stdout if output == "checked-text" else stderr)
    assert read == (len(text.encode()) if source == "stdin" else 0)
    if source == "file":
        assert path.read_bytes() == text.encode()
    if fmt == "json":
        report = json.loads(metadata)
        assert_v2(
            report,
            stage=stage.value,
            policy=policy,
            phone="contiguous" if policy == "privacy" else None,
        )
        assert report["error"] is None
        result = report["result"]
        assert result["action"] == "block"
        assert [(item["code"], item["start"], item["end"]) for item in result["findings"]] == [
            (code, len(before), len(before) + len(token(prefix)))
        ]
        assert len(result["trace"]) == 1 and result["trace"][0]["scanner"] == "secrets"
    else:
        assert (
            metadata
            == (
                f"stage={stage.value} action=block findings=1 codes={code} stripe_keys=true\n"
            ).encode()
        )
    assert metadata.endswith(b"\n") and len(metadata.splitlines()) == 1
    assert metadata.isascii()
    for sensitive in (CANARY, token(prefix), "demo@example.org", str(path)):
        assert sensitive.encode() not in metadata


@pytest.mark.parametrize("stage", list(Stage))
@pytest.mark.parametrize("policy", ["secrets", "privacy"])
@pytest.mark.parametrize(
    "text,options",
    [
        ("Opening hours: 9am to 5pm. 🪴\r\n\x00", []),
        ("pk_test_" + "Q" * 24 + " pk_live_" + "Q" * 24, []),
        (token(suffix=9) + " sk_live_abc_defghijklmnop", []),
        (r"sk_\u0074est_QQQQQQQQQQQQQQQQQQQQQQQQ", []),
        ('"' + token() + r'\n"', []),
        ("Contact demo@example.org", []),
        ("Contact +1 (202) 555-0123", ["--phone-mode", "formatted"]),
        (URI, []),
        (URI, ["--connection-strings"]),
        (LEGACY + " " + token() + " Contact demo@example.org", []),
        (
            URI + " " + token() + " Contact +1 (202) 555-0123",
            ["--connection-strings", "--phone-mode", "formatted"],
        ),
    ],
)
def test_selected_policy_matches_public_sdk_without_decoding_or_new_exemptions(
    monkeypatch, stage, policy, text, options
):
    if policy == "secrets" and "--phone-mode" in options:
        status, stdout, stderr, read, _ = capture(
            monkeypatch, argv(stage=stage.value, policy=policy) + options, text.encode()
        )
        assert (status, stdout, stderr, read) == (
            2,
            b"",
            b"guardtrellis: invalid_configuration\n",
            0,
        )
        return
    connection_strings = "--connection-strings" in options
    phone = "formatted" if "--phone-mode" in options else "contiguous"
    scanners = [
        SecretScanner(action=Action.BLOCK, connection_strings=connection_strings, stripe_keys=True)
    ]
    if policy == "privacy":
        scanners.append(PIIScanner(action=Action.REDACT, phone_mode=phone))
    expected = Guard(**{f"{stage.value}_scanners": scanners}).scan(text, stage=stage)
    status, stdout, stderr, _, _ = capture(
        monkeypatch, argv(stage=stage.value, policy=policy) + options, text.encode()
    )
    assert status == (0 if expected.accepted else 1)
    assert stdout == (expected.require_text().encode() if expected.accepted else b"")
    report = json.loads(stderr)
    assert_v2(
        report,
        stage=stage.value,
        policy=policy,
        uri=connection_strings,
        phone=phone if policy == "privacy" else None,
    )
    assert report["result"] == expected.diagnostics() and report["error"] is None
    assert text.encode() not in stderr if text else True


@pytest.mark.parametrize(
    "extra",
    [
        ["--stripe-keys", "--stripe-keys"],
        ["--stripe-keys=true"],
        ["--stripe-keys=false"],
        ["--stripe-keys="],
        ["--stripe-keys", "true"],
        ["--stripe-keys", "false"],
        ["--stripe-key"],
        ["--stripe"],
        ["--no-stripe-keys"],
        ["--stripe-keys", "--help"],
        ["--stripe-keys", "--version"],
    ],
)
def test_invalid_flag_grammar_rejects_before_source_or_scanner(monkeypatch, extra):
    forbidden = Mock(side_effect=AssertionError("Input and scanner must remain untouched"))
    monkeypatch.setattr(_cli, "_read", forbidden)
    monkeypatch.setattr(_cli, "_scan", forbidden)
    status, stdout, stderr, read, _ = capture(
        monkeypatch, argv(selected=False) + extra, CANARY.encode()
    )
    assert (status, stdout, stderr, read) == (2, b"", b"guardtrellis: invalid_command\n", 0)
    forbidden.assert_not_called()


@pytest.mark.parametrize("standalone", [["--help"], ["-h"], ["--version"], ["check", "--help"]])
def test_selected_flag_does_not_turn_help_or_version_into_a_combined_command(
    monkeypatch, standalone
):
    status, stdout, stderr, read, _ = capture(
        monkeypatch, standalone + ["--stripe-keys"], CANARY.encode()
    )
    assert (status, stdout, stderr, read) == (2, b"", b"guardtrellis: invalid_command\n", 0)


def test_secrets_phone_option_remains_invalid_before_read(monkeypatch):
    status, stdout, stderr, read, _ = capture(
        monkeypatch, argv() + ["--phone-mode", "formatted"], CANARY.encode()
    )
    assert (status, stdout, stderr, read) == (2, b"", b"guardtrellis: invalid_configuration\n", 0)


def test_omitted_flag_never_enters_stripe_helper_or_candidate_limits(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Stripe preflight must remain disabled"))
    monkeypatch.setattr(scanner_module, "find_stripe_keys", forbidden)
    text = " ".join([token(suffix=248)] * 257)
    assert len(text) < _cli.MAX_CHARS
    status, stdout, stderr, _, _ = capture(monkeypatch, argv(selected=False), text.encode())
    assert status == 0 and stdout == text.encode()
    report = json.loads(stderr)
    assert report["report_version"] == 1 and "stripe_keys" not in report["options"]
    assert report["result"]["findings"] == []
    forbidden.assert_not_called()


@pytest.mark.parametrize("fmt", ["json", "text"])
@pytest.mark.parametrize("wrapper", [False, True])
def test_selected_report_exact_bytes_and_cap_include_marker_and_final_lf(monkeypatch, fmt, wrapper):
    config = _cli._parse(argv(fmt=fmt))
    result = None if wrapper else _cli._scan(config, "Public")
    error = "invalid_encoding" if wrapper else None
    if fmt == "json":
        result_bytes = (
            "null"
            if wrapper
            else '{"action":"allow","stage":"retrieval","findings":[],"trace":'
            '[{"scanner":"secrets","scanner_index":0,"action":"allow","revision_before":0,"revision_after":0}]}'
        )
        error_bytes = '{"code":"invalid_encoding"}' if wrapper else "null"
        expected = (
            '{"report_version":2,"sdk_version":"'
            + __version__
            + '","stage":"retrieval","policy":"secrets","options":'
            '{"connection_strings":false,"phone_mode":null,"stripe_keys":true},"result":'
            + result_bytes
            + ',"error":'
            + error_bytes
            + "}\n"
        ).encode()
    else:
        expected = (
            b"stage=retrieval error=invalid_encoding stripe_keys=true\n"
            if wrapper
            else b"stage=retrieval action=allow findings=0 codes= stripe_keys=true\n"
        )
    monkeypatch.setattr(_cli, "MAX_REPORT_BYTES", len(expected))
    assert _cli._report(config, result, error) == expected
    monkeypatch.setattr(_cli, "MAX_REPORT_BYTES", len(expected) - 1)
    with pytest.raises(_cli._Failure) as caught:
        _cli._report(config, result, error)
    assert (caught.value.code, caught.value.status) == ("report_limit_exceeded", 3)


@pytest.mark.parametrize("output", ["metadata", "checked-text"])
@pytest.mark.parametrize("size,expected_status", [(255, 1), (256, 3)])
def test_real_candidate_boundary_is_block_or_atomic_sdk_error(
    monkeypatch, output, size, expected_status
):
    text = LEGACY + " " + token() + " " + token(suffix=size - 8)
    status, stdout, stderr, _, _ = capture(monkeypatch, argv(output=output), text.encode())
    report = json.loads(stderr if output == "checked-text" else stdout)
    assert status == expected_status and not (stdout if output == "checked-text" else stderr)
    assert_v2(report)
    assert report["error"] is None
    if size == 256:
        assert report["result"]["action"] == "error"
        assert [(f["code"], f["start"], f["end"]) for f in report["result"]["findings"]] == [
            ("stripe_key_limit_exceeded", None, None)
        ]
    else:
        assert report["result"]["action"] == "block" and len(report["result"]["findings"]) == 3
        final = report["result"]["findings"][-1]
        assert (final["start"], final["end"]) == (len(text) - 255, len(text))


def test_late_malformed_oversize_candidate_never_releases_earlier_successes(monkeypatch):
    malformed = "sk_test_" + "_" + "Q" * 247
    assert len(malformed) == 256
    text = " ".join([LEGACY, token(), malformed])
    status, stdout, stderr, _, _ = capture(monkeypatch, argv(), text.encode())
    assert status == 3 and stdout == b""
    report = json.loads(stderr)
    assert_v2(report)
    assert report["error"] is None and report["result"]["action"] == "error"
    assert [(f["code"], f["start"], f["end"]) for f in report["result"]["findings"]] == [
        ("stripe_key_limit_exceeded", None, None)
    ]


@pytest.mark.parametrize(
    "count,status,code", [(256, 1, None), (257, 3, "stripe_key_limit_exceeded")]
)
def test_real_eligible_attempt_boundary_includes_malformed_candidates(
    monkeypatch, count, status, code
):
    # Malformed candidates still consume attempts; all inputs stay below CLI ingress caps.
    text = LEGACY + " " + " ".join(["rk_live_bad_suffix"] * (count - 1) + [token()])
    observed, stdout, stderr, _, _ = capture(monkeypatch, argv(), text.encode())
    assert observed == status and stdout == b""
    report = json.loads(stderr)
    assert_v2(report)
    assert report["error"] is None
    findings = report["result"]["findings"]
    if code:
        assert report["result"]["action"] == "error"
        assert [(f["code"], f["start"], f["end"]) for f in findings] == [(code, None, None)]
    else:
        assert [f["code"] for f in findings] == [
            "secret_github_classic",
            "secret_stripe_secret_test",
        ]


@pytest.mark.parametrize("with_uri", [False, True])
@pytest.mark.parametrize("overflow", [False, True])
def test_shared_finding_boundary_combines_old_new_and_selected_uri(monkeypatch, with_uri, overflow):
    legacy_count = (254 if with_uri else 255) + overflow
    text = " ".join([LEGACY] * legacy_count + [token()] + ([URI] if with_uri else []))
    assert len(text) < _cli.MAX_CHARS
    status, stdout, stderr, _, _ = capture(
        monkeypatch, argv() + (["--connection-strings"] if with_uri else []), text.encode()
    )
    assert status == (3 if overflow else 1) and stdout == b""
    report = json.loads(stderr)
    assert_v2(report, uri=with_uri)
    assert report["error"] is None
    findings = report["result"]["findings"]
    if overflow:
        assert report["result"]["action"] == "error"
        assert [(f["code"], f["start"], f["end"]) for f in findings] == [
            ("finding_limit_exceeded", None, None)
        ]
    else:
        assert report["result"]["action"] == "block" and len(findings) == 256
        assert "secret_stripe_secret_test" in [f["code"] for f in findings]
        assert ("secret_postgresql_uri" in [f["code"] for f in findings]) == with_uri


def test_uri_preflight_error_precedes_stripe_error_and_withholds_early_secrets(monkeypatch):
    text = " ".join(
        [LEGACY, token(), "postgresql://app:" + "P" * 8200 + "@db.invalid/x", token(suffix=248)]
    )
    status, stdout, stderr, _, _ = capture(
        monkeypatch, argv() + ["--connection-strings"], text.encode()
    )
    assert status == 3 and stdout == b""
    report = json.loads(stderr)
    assert_v2(report, uri=True)
    assert report["error"] is None and report["result"]["action"] == "error"
    assert [f["code"] for f in report["result"]["findings"]] == ["connection_string_limit_exceeded"]
    assert LEGACY.encode() not in stderr and b"P" * 100 not in stderr


@pytest.mark.parametrize(
    "data",
    [b"x" * 100_001, "😀".encode() * 100_000 + b"x"],
    ids=["character-limit", "byte-limit"],
)
def test_ingress_overflow_is_wrapper_exit_two_before_any_stripe_scan(monkeypatch, data):
    forbidden = Mock(side_effect=AssertionError("Oversize ingress must not scan"))
    monkeypatch.setattr(_cli, "_scan", forbidden)
    status, stdout, stderr, _, _ = capture(monkeypatch, argv(), data)
    assert status == 2 and stdout == b""
    report = json.loads(stderr)
    assert_v2(report)
    assert report["result"] is None and report["error"] == {"code": "input_limit_exceeded"}
    forbidden.assert_not_called()


def test_selected_mode_accepts_the_real_character_and_utf8_byte_ingress_maximum(monkeypatch):
    data = "😀".encode() * 100_000
    assert len(data) == _cli.MAX_BYTES
    status, stdout, stderr, _, _ = capture(monkeypatch, argv(), data)
    assert status == 0 and stdout == data
    report = json.loads(stderr)
    assert_v2(report)
    assert report["error"] is None and report["result"]["action"] == "allow"


def test_selected_report_overflow_withholds_otherwise_accepted_checked_bytes(monkeypatch):
    monkeypatch.setattr(_cli, "MAX_REPORT_BYTES", 400)
    status, stdout, stderr, _, _ = capture(
        monkeypatch, argv(policy="privacy"), b"demo@example.org " * 20
    )
    assert status == 3 and stdout == b"" and len(stderr) <= 400
    report = json.loads(stderr)
    assert_v2(report, policy="privacy", phone="contiguous")
    assert report["result"] is None and report["error"] == {"code": "report_limit_exceeded"}
    assert b"demo@example.org" not in stderr
