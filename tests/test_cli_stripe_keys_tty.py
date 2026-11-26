"""Portable terminal/probe protocol checks; these do not exercise native terminals."""

import io
import json
import sys

import pytest

from guardtrellis import __version__, _cli
from tests.test_cli import CANARY, Sink, capture, install_streams


class NoRead(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.read_calls = 0

    def read(self, *_):
        self.read_calls += 1
        raise AssertionError(CANARY)


def args(selected, policy, format, output, source=None):
    command = [
        "check",
        *(["--stdin"] if source is None else ["--file", str(source)]),
        "--stage",
        "retrieval",
        "--policy",
        policy,
        "--format",
        format,
        "--output",
        output,
    ]
    return command + (["--stripe-keys"] if selected else [])


def guarded_streams(monkeypatch, *, out=None, err=None):
    _, stdout, stderr, quarantined = install_streams(monkeypatch, out=out, err=err)
    stdin = NoRead(CANARY.encode())
    sys.stdin.buffer = stdin
    return stdin, stdout, stderr, quarantined


def forbidden(*_, **__):
    raise AssertionError(CANARY)


def forbid_read_and_scan(monkeypatch, reader="_read_bounded"):
    calls = []

    def tracked(*_, **__):
        calls.append("read_or_scan")
        raise AssertionError(CANARY)

    monkeypatch.setattr(_cli, reader, tracked)
    monkeypatch.setattr(_cli, "_scan", tracked)
    return calls


def wrapper_bytes(selected, policy, format, code):
    if format == "text":
        marker = " stripe_keys=true" if selected else ""
        return f"stage=retrieval error={code}{marker}\n".encode("ascii")
    options = {
        "connection_strings": False,
        "phone_mode": "contiguous" if policy == "privacy" else None,
    }
    if selected:
        options["stripe_keys"] = True
    report = {
        "report_version": 2 if selected else 1,
        "sdk_version": __version__,
        "stage": "retrieval",
        "policy": policy,
        "options": options,
        "result": None,
        "error": {"code": code},
    }
    return (json.dumps(report, ensure_ascii=True, separators=(",", ":")) + "\n").encode()


@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("policy", ["secrets", "privacy"])
@pytest.mark.parametrize("format", ["text", "json"])
@pytest.mark.parametrize(
    "output,stdout_tty", [("metadata", False), ("metadata", True), ("checked-text", False)]
)
def test_terminal_stdin_retains_selected_wrapper_phase(
    monkeypatch, selected, policy, format, output, stdout_tty
):
    stdin, stdout, stderr, quarantined = guarded_streams(monkeypatch)
    calls = forbid_read_and_scan(monkeypatch)
    sys.stdin.isatty = lambda: True
    sys.stdout.isatty = lambda: stdout_tty

    assert _cli.main(args(selected, policy, format, output)) == 2
    report, other = (stderr, stdout) if output == "checked-text" else (stdout, stderr)
    assert report.getvalue() == wrapper_bytes(selected, policy, format, "invalid_source")
    assert other.getvalue() == b"" and not quarantined
    assert stdin.read_calls == 0 and stdin.tell() == 0 and not calls
    assert CANARY.encode() not in report.getvalue()


@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("policy", ["secrets", "privacy"])
@pytest.mark.parametrize("format", ["text", "json"])
@pytest.mark.parametrize("file_source", [False, True])
def test_terminal_stdout_wins_before_both_sources_and_stdin_probe(
    monkeypatch, tmp_path, selected, policy, format, file_source
):
    stdin, stdout, stderr, quarantined = guarded_streams(monkeypatch)
    probes = []

    def terminal_stdin():
        probes.append("stdin")
        return True

    sys.stdin.isatty = terminal_stdin
    sys.stdout.isatty = lambda: True
    calls = forbid_read_and_scan(monkeypatch, "_read")
    source = tmp_path / CANARY if file_source else None
    assert _cli.main(args(selected, policy, format, "checked-text", source)) == 2
    assert stdout.getvalue() == b""
    assert stderr.getvalue() == b"guardtrellis: invalid_configuration\n"
    assert not probes and stdin.read_calls == 0 and not quarantined and not calls


@pytest.mark.parametrize("data", [b"", ("sk_test_" + "A" * 24).encode()], ids=["empty", "blocked"])
@pytest.mark.parametrize("file_source", [False, True])
def test_selected_terminal_stdout_never_inspects_empty_or_blocked_fixtures(
    monkeypatch, tmp_path, data, file_source
):
    stdin, stdout, stderr, _ = install_streams(monkeypatch, data=data)
    sys.stdout.isatty = lambda: True
    sys.stdin.isatty = forbidden
    calls = forbid_read_and_scan(monkeypatch, "_read")
    source = tmp_path / CANARY if file_source else None
    if source is not None:
        source.write_bytes(data)
    assert _cli.main(args(True, "privacy", "json", "checked-text", source)) == 2
    assert (stdout.getvalue(), stderr.getvalue(), stdin.tell()) == (
        b"",
        b"guardtrellis: invalid_configuration\n",
        0,
    )
    assert not calls
    if source is not None:
        assert source.read_bytes() == data


@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("policy", ["secrets", "privacy"])
@pytest.mark.parametrize("format", ["text", "json"])
@pytest.mark.parametrize(
    "output,stdout_tty", [("metadata", False), ("metadata", True), ("checked-text", False)]
)
def test_regular_file_ignores_unused_failing_stdin_probe(
    monkeypatch, tmp_path, selected, policy, format, output, stdout_tty
):
    source = tmp_path / f"{CANARY}.txt"
    payload = b"Public " + CANARY.encode()
    source.write_bytes(payload)
    stdin, stdout, stderr, quarantined = guarded_streams(monkeypatch)
    sys.stdin.isatty = forbidden
    sys.stdout.isatty = lambda: stdout_tty

    assert _cli.main(args(selected, policy, format, output, source)) == 0
    report = (stderr if output == "checked-text" else stdout).getvalue()
    if format == "json":
        envelope = json.loads(report)
        assert envelope["report_version"] == (2 if selected else 1)
        assert envelope["result"]["action"] == "allow" and envelope["error"] is None
    else:
        marker = b" stripe_keys=true" if selected else b""
        assert report == b"stage=retrieval action=allow findings=0 codes=" + marker + b"\n"
    assert CANARY.encode() not in report
    assert (stdout.getvalue() if output == "checked-text" else stderr.getvalue()) == (
        payload if output == "checked-text" else b""
    )
    assert stdin.read_calls == 0 and not quarantined and source.read_bytes() == payload


@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("format", ["text", "json"])
@pytest.mark.parametrize("output", ["metadata", "checked-text"])
@pytest.mark.parametrize(
    "failure,code,status",
    [
        (OSError, "input_io_error", 2),
        (ValueError, "input_io_error", 2),
        (AttributeError, "input_io_error", 2),
        (RuntimeError, "runtime_error", 3),
        (KeyboardInterrupt, "interrupted", 130),
    ],
)
def test_stdin_probe_failure_is_after_configuration(
    monkeypatch, selected, format, output, failure, code, status
):
    stdin, stdout, stderr, quarantined = guarded_streams(monkeypatch)
    calls = forbid_read_and_scan(monkeypatch)

    def broken():
        raise failure(CANARY)

    sys.stdin.isatty = broken
    assert _cli.main(args(selected, "privacy", format, output)) == status
    report, other = (stderr, stdout) if output == "checked-text" else (stdout, stderr)
    assert report.getvalue() == wrapper_bytes(selected, "privacy", format, code)
    assert other.getvalue() == b"" and stdin.read_calls == 0 and not quarantined and not calls
    assert CANARY.encode() not in report.getvalue()


@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("format", ["text", "json"])
@pytest.mark.parametrize("file_source", [False, True])
@pytest.mark.parametrize("failure,status", [(OSError, 3), (KeyboardInterrupt, 130)])
def test_stdout_probe_failure_remains_static_before_input(
    monkeypatch, tmp_path, selected, format, file_source, failure, status
):
    stdin, stdout, stderr, quarantined = guarded_streams(monkeypatch)
    sys.stdin.isatty = forbidden
    calls = forbid_read_and_scan(monkeypatch, "_read")

    def broken():
        raise failure(CANARY)

    sys.stdout.isatty = broken
    source = tmp_path / CANARY if file_source else None
    assert _cli.main(args(selected, "privacy", format, "checked-text", source)) == status
    code = b"interrupted" if status == 130 else b"output_io_error"
    assert stderr.getvalue() == b"guardtrellis: " + code + b"\n"
    assert stdout.getvalue() == b"" and stdin.read_calls == 0 and not calls
    assert quarantined == ([] if status == 130 else ["stdout"])


@pytest.mark.parametrize("format", ["text", "json"])
@pytest.mark.parametrize("output", ["metadata", "checked-text"])
@pytest.mark.parametrize("failure", ["write", "flush", "zero", "interrupt", "interrupt_flush"])
def test_selected_terminal_error_emission_does_not_retry_or_leak(
    monkeypatch, format, output, failure
):
    sink = Sink(fail=failure)
    stdin, stdout, stderr, quarantined = guarded_streams(
        monkeypatch, **{"err" if output == "checked-text" else "out": sink}
    )
    calls = forbid_read_and_scan(monkeypatch)
    sys.stdin.isatty = lambda: True
    interrupted = failure.startswith("interrupt")
    assert _cli.main(args(True, "privacy", format, output)) == (130 if interrupted else 3)
    assert quarantined == ["stderr" if output == "checked-text" else "stdout"]
    expected = wrapper_bytes(True, "privacy", format, "invalid_source")
    assert sink.getvalue() == (expected if "flush" in failure else b"")
    if output == "checked-text":
        assert stdout.getvalue() == b""
    else:
        assert stderr.getvalue() == (b"" if interrupted else b"guardtrellis: output_io_error\n")
    assert stdin.read_calls == 0 and not calls
    assert CANARY.encode() not in stdout.getvalue() + stderr.getvalue()


@pytest.mark.parametrize("output", ["metadata", "checked-text"])
@pytest.mark.parametrize("failure", ["write", "flush"])
def test_interrupted_input_probe_keeps_130_after_error_report_write_failure(
    monkeypatch, output, failure
):
    sink = Sink(fail=failure)
    stdin, stdout, stderr, _ = guarded_streams(
        monkeypatch, **{"err" if output == "checked-text" else "out": sink}
    )
    calls = forbid_read_and_scan(monkeypatch)

    def interrupted():
        raise KeyboardInterrupt(CANARY)

    sys.stdin.isatty = interrupted
    assert _cli.main(args(True, "privacy", "json", output)) == 130
    if output == "checked-text":
        assert stdout.getvalue() == b""
    assert stdin.read_calls == 0 and not calls
    assert CANARY.encode() not in stdout.getvalue() + stderr.getvalue()


@pytest.mark.parametrize("format", ["text", "json"])
def test_selected_metadata_flush_precedes_exact_payload_with_short_writes(monkeypatch, format):
    events = []
    out = Sink(chunk=2, events=events, name="out")
    err = Sink(chunk=7, events=events, name="err")
    payload = b"Public " + CANARY.encode()
    status, stdout, stderr, _, quarantined = capture(
        monkeypatch,
        args(True, "privacy", format, "checked-text"),
        payload,
        out=out,
        err=err,
    )
    assert status == 0 and stdout == payload and not quarantined
    assert CANARY.encode() not in stderr and stderr.endswith(b"\n")
    assert events.index(("err", "flush")) < events.index(("out", "write"))
    assert events[-1] == ("out", "flush")


@pytest.mark.parametrize("format", ["text", "json"])
@pytest.mark.parametrize("failure", ["write", "flush", "zero", "interrupt", "interrupt_flush"])
def test_selected_payload_failure_keeps_one_metadata_record(monkeypatch, format, failure):
    original = b"Contact demo@example.org " + CANARY.encode()
    checked = b"Contact [PII] " + CANARY.encode()
    status, stdout, stderr, _, quarantined = capture(
        monkeypatch,
        args(True, "privacy", format, "checked-text"),
        original,
        out=Sink(fail=failure),
    )
    assert status == (130 if failure.startswith("interrupt") else 3)
    assert stdout == (checked if "flush" in failure else b"")
    assert stderr.count(b"\n") == 1 and CANARY.encode() not in stderr
    assert b"demo@example.org" not in stdout + stderr and quarantined == ["stdout"]
    if format == "json":
        report = json.loads(stderr)
        assert report["report_version"] == 2 and report["options"]["stripe_keys"] is True
        assert report["result"]["action"] == "redact"
    else:
        assert stderr.endswith(b" stripe_keys=true\n")


@pytest.mark.parametrize("format", ["text", "json"])
def test_selected_error_metadata_bound_includes_marker_and_final_lf(monkeypatch, format):
    config = _cli._parse(args(True, "privacy", format, "metadata"))
    expected = wrapper_bytes(True, "privacy", format, "invalid_source")
    monkeypatch.setattr(_cli, "MAX_REPORT_BYTES", len(expected))
    assert _cli._report(config, None, "invalid_source") == expected
    monkeypatch.setattr(_cli, "MAX_REPORT_BYTES", len(expected) - 1)
    with pytest.raises(_cli._Failure) as caught:
        _cli._report(config, None, "invalid_source")
    assert caught.value.code == "report_limit_exceeded" and caught.value.status == 3
