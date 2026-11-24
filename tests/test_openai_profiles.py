"""OpenAI/Azure profile validation must observe the selected environment and fail closed."""

import importlib
import json
import socket
import subprocess
import sys
import tempfile
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

from scripts import openai_profiles as profiles

DIRECT = {"openai": "3.0.0", "httpx2": "2.12.0"}
LOCKED = {"openai": "3.50.0", "httpx2": "2.16.0"}


def exported_profile(monkeypatch, content):
    calls = []

    def export(command, **options):
        calls.append((command, options))
        assert options["cwd"] == profiles.ROOT and options["check"] is True
        assert command[:2] == ["uv", "export"]
        assert "--frozen" in command and "--no-dev" in command
        assert command[command.index("--extra") + 1] == "openai"
        assert "--no-emit-project" in command
        assert options.get("shell", False) is False
        if content is not None:
            Path(command[command.index("--output-file") + 1]).write_bytes(content)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(profiles.subprocess, "run", export)
    return calls


def test_minimum_profile_matches_both_declared_direct_floors(tmp_path):
    constraints, expected = profiles.profile_constraints(tmp_path, "minimum")
    requirements = {
        name: version
        for line in constraints.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
        for name, version in [line.split("==")]
    }
    assert requirements == expected == profiles.MINIMUM == DIRECT
    metadata = tomllib.loads((profiles.ROOT / "pyproject.toml").read_text())
    declared = {
        requirement.name: requirement
        for text in metadata["project"]["optional-dependencies"]["openai"]
        for requirement in [Requirement(text)]
    }
    assert set(declared) == set(DIRECT)
    for name, version in expected.items():
        floors = [item.version for item in declared[name].specifier if item.operator == ">="]
        assert len(floors) == 1 and Version(floors[0]) == Version(version)
    assert not set(DIRECT).intersection(
        Requirement(text).name for text in metadata["project"]["dependencies"]
    )


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_locked_profile_preserves_the_full_exported_dependency_closure(
    tmp_path, monkeypatch, newline
):
    exported = newline.join(
        [
            "# Reviewed complete OpenAI dependency closure",
            "openai==3.50.0",
            "httpx2==2.16.0",
            "anyio==4.11.0 ; python_version >= '3.11'",
            "certifi==2026.1.0",
            "typing-extensions==4.15.0",
            "",
        ]
    ).encode()
    calls = exported_profile(monkeypatch, exported)
    constraints, expected = profiles.profile_constraints(tmp_path, "locked")
    assert constraints.read_bytes() == exported
    assert expected == LOCKED and len(calls) == 1


@pytest.mark.parametrize(
    "exported",
    [
        b"",
        b"openai==3.50.0\n",
        b"httpx2==2.16.0\n",
        b"openai==3.0.0\nopenai==3.50.0\nhttpx2==2.16.0\n",
        b"openai==3.50.0\nhttpx2==2.12.0\nhttpx2==2.16.0\n",
        b"openai>=3\nhttpx2==2.16.0\n",
        b"openai==not-a-version\nhttpx2==2.16.0\n",
        b"openai==3.50.0\nhttpx2==not-a-version\n",
        None,
    ],
)
def test_missing_ambiguous_or_malformed_lock_export_is_rejected(tmp_path, monkeypatch, exported):
    exported_profile(monkeypatch, exported)
    with pytest.raises((ValueError, FileNotFoundError)):
        profiles.profile_constraints(tmp_path, "locked")


@pytest.mark.parametrize("profile", ["other", "", "Minimum", "disabled"])
def test_unknown_profile_never_falls_back_to_unconstrained_install(tmp_path, monkeypatch, profile):
    def forbidden(*args, **kwargs):
        raise AssertionError("Unknown profile entered the resolver")

    monkeypatch.setattr(profiles.subprocess, "run", forbidden)
    with pytest.raises(ValueError, match="Unknown"):
        profiles.profile_constraints(tmp_path, profile)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "platform, executable", [("nt", "Scripts/python.exe"), ("posix", "bin/python")]
)
def test_fresh_environment_uses_native_argv_with_spaces_and_unicode(
    tmp_path, monkeypatch, platform, executable
):
    work = tmp_path / "consumer environment 雪"
    work.mkdir()
    calls = []

    def create(command, **options):
        calls.append((command, options))
        assert options["check"] is True and options.get("shell", False) is False
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(profiles, "os", SimpleNamespace(name=platform, environ=profiles.os.environ))
    monkeypatch.setattr(profiles.subprocess, "run", create)
    python = profiles.fresh_environment(work)
    assert python == work / "venv" / executable
    assert len(calls) == 1
    command = calls[0][0]
    assert command[:2] == ["uv", "venv"]
    assert command[command.index("--python") + 1] == profiles.sys.executable
    assert command[-1] == str(work / "venv")


@pytest.mark.parametrize(
    "failure",
    [subprocess.CalledProcessError(1, ["uv"]), subprocess.TimeoutExpired(["uv"], timeout=1)],
)
def test_environment_subprocess_failure_is_not_retried_or_reported_as_validation(
    tmp_path, monkeypatch, failure
):
    calls = []

    def fail(command, **options):
        calls.append(command)
        raise failure

    monkeypatch.setattr(profiles.subprocess, "run", fail)
    with pytest.raises(type(failure)) as caught:
        profiles.fresh_environment(tmp_path)
    assert caught.value is failure and len(calls) == 1


def regression_report(*, tests=2, skipped=0, failures=0, errors=0):
    return (
        f'<testsuite tests="{tests}" skipped="{skipped}" failures="{failures}" errors="{errors}">'
        '<testcase classname="test_openai_example" name="checked_request"/>'
        '<testcase classname="test_azure_openai_example" name="checked_request"/>'
        "</testsuite>"
    )


@pytest.mark.parametrize("root", ["testsuite", "testsuites"])
def test_regression_gate_accepts_actual_nonempty_zero_skip_results(tmp_path, root):
    report = tmp_path / "focused regressions 雪.xml"
    suite = regression_report()
    report.write_text(suite if root == "testsuite" else f"<testsuites>{suite}</testsuites>")
    profiles.assert_regression_report(report)


@pytest.mark.parametrize(
    "counts",
    [
        {"tests": 0},
        {"tests": -1},
        {"tests": "not-a-count"},
        {"skipped": 1},
        {"failures": 1},
        {"errors": 1},
        {"skipped": -1},
        {"failures": -1},
        {"errors": -1},
    ],
)
def test_regression_gate_rejects_empty_skipped_failed_or_malformed_counts(tmp_path, counts):
    report = tmp_path / "regressions.xml"
    report.write_text(f"<testsuites>{regression_report(**counts)}</testsuites>")
    with pytest.raises(ValueError):
        profiles.assert_regression_report(report)


def test_one_bad_suite_cannot_hide_behind_another_successful_suite(tmp_path):
    report = tmp_path / "regressions.xml"
    report.write_text(
        "<testsuites>" + regression_report() + regression_report(skipped=1) + "</testsuites>"
    )
    with pytest.raises(ValueError):
        profiles.assert_regression_report(report)


@pytest.mark.parametrize("xml", [None, "", "<testsuites>", "<testsuites/>", "<report/>"])
def test_missing_or_invalid_regression_report_cannot_claim_validation(tmp_path, xml):
    report = tmp_path / "regressions.xml"
    if xml is not None:
        report.write_text(xml)
    with pytest.raises((ValueError, FileNotFoundError, ET.ParseError)):
        profiles.assert_regression_report(report)


RUNTIME = {**DIRECT, "anyio": "4.11.0", "certifi": "2026.1.0"}


@pytest.mark.parametrize(
    "current",
    [
        {**RUNTIME, "openai": "3.50.0"},
        {**RUNTIME, "httpx2": "2.16.0"},
        {**RUNTIME, "anyio": "4.12.0"},
        {key: value for key, value in RUNTIME.items() if key != "certifi"},
    ],
)
def test_runtime_closure_rejects_direct_transitive_and_missing_distribution_drift(
    tmp_path, monkeypatch, current
):
    monkeypatch.setattr(profiles, "snapshot_runtime_closure", lambda *args: current.copy())
    with pytest.raises(ValueError):
        profiles.assert_runtime_closure(tmp_path / "python", tmp_path, RUNTIME)


def test_runtime_closure_allows_added_test_tooling_without_changing_original_versions(
    tmp_path, monkeypatch
):
    installed = {**RUNTIME, "pytest": "9.0.0", "pluggy": "1.6.0"}
    monkeypatch.setattr(profiles, "snapshot_runtime_closure", lambda *args: installed.copy())
    profiles.assert_runtime_closure(tmp_path / "python", tmp_path, RUNTIME)


def test_runtime_environment_sanitizes_only_child_configuration(monkeypatch):
    controlled = (
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_ORG_ID",
        "OPENAI_PROJECT_ID",
        "OPENAI_LOG",
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_AD_TOKEN",
        "OPENAI_API_VERSION",
        "GUARDTRELLIS_OPENAI_LIVE",
        "GUARDTRELLIS_AZURE_OPENAI_LIVE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONOPTIMIZE",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
    )
    ambient = dict.fromkeys(controlled, "synthetic-ambient-configuration")
    ambient.update(
        {"PROFILE_TEST_KEEP": "keep this host value", "PATH": "controlled native tools 雪"}
    )
    monkeypatch.setattr(profiles, "os", SimpleNamespace(environ=ambient))
    original = ambient.copy()
    environment = profiles.runtime_environment()
    assert not set(controlled).intersection(environment)
    assert environment["PROFILE_TEST_KEEP"] == "keep this host value"
    assert environment["PATH"] == original["PATH"]
    assert ambient == original


def regression_process(tmp_path, monkeypatch, *, drift_phase=None, drift_name="anyio"):
    installed = RUNTIME.copy()
    events = []
    python = tmp_path / "venv with spaces 雪" / "python"

    def snapshot(selected_python, work):
        assert selected_python == python and work == tmp_path
        events.append("snapshot")
        return installed.copy()

    def run(command, **options):
        assert options["check"] is True and options.get("shell", False) is False
        if command[:2] == ["uv", "export"]:
            events.append("export")
            Path(command[command.index("--output-file") + 1]).write_text(
                "pytest==9.0.0 --hash=sha256:fixture\npytest-asyncio==1.5.0 --hash=sha256:fixture\n"
            )
        elif command[:3] == ["uv", "pip", "install"]:
            events.append("install")
            assert command[command.index("--python") + 1] == str(python)
            assert "--require-hashes" in command
            freeze = Path(command[command.index("--constraint") + 1])
            assert dict(line.split("==") for line in freeze.read_text().splitlines()) == RUNTIME
            installed["pytest"] = "9.0.0"
            if drift_phase == "after_tooling":
                installed[drift_name] = "99.0.0"
        elif command[:3] == ["uv", "pip", "check"]:
            events.append("pip_check")
        elif command[0] == str(python):
            events.append("tests")
            assert "-I" in command and "-c" in command
            assert options["cwd"] == profiles.ROOT
            assert options["timeout"] == profiles.REGRESSION_TIMEOUT
            (tmp_path / "openai-regressions.xml").write_text(regression_report())
            if drift_phase == "after_tests":
                installed[drift_name] = "99.0.0"
        else:
            raise AssertionError(f"Unexpected validation subprocess: {command}")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(profiles, "snapshot_runtime_closure", snapshot)
    monkeypatch.setattr(profiles.subprocess, "run", run)
    return python, events


def test_regression_orchestration_freezes_and_rechecks_the_whole_runtime(tmp_path, monkeypatch):
    python, events = regression_process(tmp_path, monkeypatch)
    profiles.run_regressions(python, tmp_path, DIRECT)
    install, tests = events.index("install"), events.index("tests")
    assert "snapshot" in events[:install]
    assert "snapshot" in events[install + 1 : tests]
    assert "snapshot" in events[tests + 1 :]
    assert json.loads((tmp_path / "runtime-closure.json").read_text()) == RUNTIME


@pytest.mark.parametrize("phase", ["after_tooling", "after_tests"])
@pytest.mark.parametrize("name", ["openai", "anyio"])
def test_regression_orchestration_rejects_drift_at_each_mutating_phase(
    tmp_path, monkeypatch, phase, name
):
    python, events = regression_process(tmp_path, monkeypatch, drift_phase=phase, drift_name=name)
    with pytest.raises(ValueError, match="closure changed"):
        profiles.run_regressions(python, tmp_path, DIRECT)
    assert "snapshot" in events[: events.index("install")]
    assert ("tests" in events) is (phase == "after_tests")


@pytest.fixture
def checker(monkeypatch):
    monkeypatch.syspath_prepend(str(profiles.ROOT / "scripts"))
    return importlib.import_module("check_openai_profile")


def checker_process(tmp_path, monkeypatch, checker, *, failure_at=None, failure=None):
    events, workspaces, commands = [], [], []
    source = tmp_path / "source checkout 雪"
    source.mkdir()
    real_temporary_directory = tempfile.TemporaryDirectory

    def temporary_directory(*, prefix):
        context = real_temporary_directory(prefix=prefix + "spaces 雪 ", dir=tmp_path)
        workspaces.append(Path(context.name))
        return context

    def enter(event):
        assert workspaces[0].is_dir()
        events.append(event)
        if event == failure_at:
            raise failure

    def fresh(work):
        (work / "partially-created-environment").write_text("temporary test data")
        enter("venv")
        return work / "venv with spaces 雪" / "Scripts" / "python.exe"

    def constraints(work, profile):
        enter("constraints:" + profile)
        target = work / f"selected-{profile}.txt"
        target.write_text("controlled constraints")
        return target, DIRECT.copy() if profile == "minimum" else LOCKED.copy()

    def run(command, **options):
        commands.append((command, options))
        assert options["check"] is True and options.get("shell", False) is False
        enter("install" if command[:3] == ["uv", "pip", "install"] else "pip_check")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(checker, "ROOT", source)
    monkeypatch.setattr(
        checker, "tempfile", SimpleNamespace(TemporaryDirectory=temporary_directory)
    )
    monkeypatch.setattr(checker, "fresh_environment", fresh)
    monkeypatch.setattr(checker, "profile_constraints", constraints)
    monkeypatch.setattr(checker, "build_options", lambda *args: [])
    monkeypatch.setattr(checker, "subprocess", SimpleNamespace(run=run))
    monkeypatch.setattr(checker, "print_evidence", lambda *args: enter("evidence"))
    monkeypatch.setattr(checker, "assert_openai_profile", lambda *args: enter("probe"))
    monkeypatch.setattr(checker, "run_mocked_examples", lambda *args: enter("examples"))
    monkeypatch.setattr(checker, "run_regressions", lambda *args: enter("regressions"))
    return events, workspaces, commands, source


@pytest.mark.parametrize("profile", ["minimum", "locked"])
@pytest.mark.parametrize("regressions", [False, True])
def test_checker_selects_one_profile_and_runs_optional_regressions_after_isolation(
    tmp_path, monkeypatch, checker, profile, regressions
):
    events, workspaces, commands, source = checker_process(tmp_path, monkeypatch, checker)
    argv = ["check_openai_profile.py", "--profile", profile]
    if regressions:
        argv.append("--regressions")
    monkeypatch.setattr(sys, "argv", argv)
    checker.main()
    assert events.count("constraints:" + profile) == 1
    assert events.index("install") < events.index("probe") < events.index("examples")
    assert ("regressions" in events) is regressions
    if regressions:
        assert events.index("examples") < events.index("regressions")
    command, options = commands[0]
    assert command[-1] == f"{source}[openai]"
    assert command[command.index("--constraint") + 1] == str(
        workspaces[0] / f"selected-{profile}.txt"
    )
    assert command[command.index("--python") + 1] == str(
        workspaces[0] / "venv with spaces 雪" / "Scripts" / "python.exe"
    )
    assert options["cwd"] == workspaces[0]
    assert workspaces and all(not path.exists() for path in workspaces)


@pytest.mark.parametrize("phase", ["venv", "install", "probe", "regressions"])
@pytest.mark.parametrize("failure_type", [subprocess.CalledProcessError, subprocess.TimeoutExpired])
def test_checker_cleans_partial_environments_after_subprocess_failure_or_timeout(
    tmp_path, monkeypatch, checker, phase, failure_type
):
    failure = (
        subprocess.CalledProcessError(1, ["controlled-process"])
        if failure_type is subprocess.CalledProcessError
        else subprocess.TimeoutExpired(["controlled-process"], timeout=1)
    )
    events, workspaces, _, _ = checker_process(
        tmp_path, monkeypatch, checker, failure_at=phase, failure=failure
    )
    monkeypatch.setattr(
        sys, "argv", ["check_openai_profile.py", "--profile", "minimum", "--regressions"]
    )
    with pytest.raises(failure_type) as caught:
        checker.main()
    assert caught.value is failure and events[-1] == phase
    assert workspaces and all(not path.exists() for path in workspaces)


def test_checker_rejects_unknown_profile_before_preparing_an_environment(
    tmp_path, monkeypatch, checker
):
    def forbidden(*args, **kwargs):
        raise AssertionError("Invalid CLI profile entered environment preparation")

    monkeypatch.setattr(checker, "fresh_environment", forbidden)
    monkeypatch.setattr(sys, "argv", ["check_openai_profile.py", "--profile", "unknown"])
    with pytest.raises(SystemExit) as caught:
        checker.main()
    assert caught.value.code == 2 and not list(tmp_path.iterdir())


def test_network_audit_blocks_real_dns_and_connect_in_an_isolated_interpreter(tmp_path):
    code = f"""
import json
import runpy
import socket
import sys

checks = runpy.run_path({str(Path(profiles.__file__).resolve())!r})
checks['_deny_network']()
blocked = []
with socket.socket() as client:
    operations = (
        lambda: socket.getaddrinfo('127.0.0.1', 0, flags=socket.AI_NUMERICHOST),
        lambda: client.connect(('127.0.0.1', 0)),
    )
    for operation in operations:
        try:
            operation()
        except AssertionError:
            blocked.append(True)
        else:
            raise AssertionError('Network audit failed to block an actual socket operation')
    for event in (
        'socket.gethostbyname', 'socket.gethostbyaddr',
        'socket.getnameinfo', 'socket.sendto', 'socket.sendmsg',
    ):
        try:
            sys.audit(event)
        except AssertionError:
            blocked.append(True)
        else:
            raise AssertionError('Network audit did not reject a protected event')
print(json.dumps({{'blocked_operations': len(blocked)}}))
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code],
        cwd=tmp_path,
        env=profiles.runtime_environment(),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert json.loads(completed.stdout) == {"blocked_operations": 7}
    assert completed.stderr == ""


@pytest.mark.skipif(not hasattr(socket.socket, "sendmsg"), reason="Requires POSIX socket.sendmsg")
def test_network_audit_blocks_actual_posix_sendmsg_without_delivering_bytes(tmp_path):
    code = f"""
import json
import runpy
import socket

checks = runpy.run_path({str(Path(profiles.__file__).resolve())!r})
sender, receiver = socket.socketpair()
with sender, receiver:
    receiver.settimeout(0.1)
    payload = b'synthetic-profile-probe'
    # Establish that this local socketpair supports the real operation before denial.
    assert sender.sendmsg([payload]) == len(payload)
    assert receiver.recv(len(payload)) == payload
    checks['_deny_network']()
    try:
        sender.sendmsg([payload])
    except AssertionError as error:
        assert str(error) == 'Network access is forbidden in OpenAI profile runtime checks'
    else:
        raise AssertionError('Network audit allowed an actual socket.sendmsg call')
    try:
        receiver.recv(len(payload))
    except TimeoutError:
        pass
    else:
        raise AssertionError('Network audit allowed sendmsg bytes to reach the receiver')
print(json.dumps({{'sendmsg_blocked': True, 'receiver_empty': True}}))
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code],
        cwd=tmp_path,
        env=profiles.runtime_environment(),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert json.loads(completed.stdout) == {"sendmsg_blocked": True, "receiver_empty": True}
    assert completed.stderr == ""
