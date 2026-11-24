"""Isolated, network-forbidden compatibility checks for the two OpenAI recipes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ("minimum", "locked")
MINIMUM = {"openai": "3.0.0", "httpx2": "2.12.0"}
PREPARATION_TIMEOUT = 300
RUNTIME_TIMEOUT = 30
REGRESSION_TIMEOUT = 120
EXAMPLES = ("openai_app.py", "azure_openai_app.py")
REGRESSIONS = ("tests/test_openai_example.py", "tests/test_azure_openai_example.py")
NON_REGRESSION_TOOLS = ("hatchling", "pyyaml", "ruff", "mypy", "types-jsonschema")
_VERSION = re.compile(
    r"(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?"
    r"(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?",
    re.IGNORECASE,
)


def runtime_environment() -> dict[str, str]:
    """Preserve platform essentials, removing ambient provider and test configuration."""
    prefixes = ("OPENAI_", "AZURE_OPENAI_", "GUARDTRELLIS_", "OTEL_", "PYTHON", "PYTEST_")
    removed = {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    }
    return {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(prefixes) and key.upper() not in removed
    }


def _exact_version(value: str) -> str:
    if _VERSION.fullmatch(value) is None:
        raise ValueError("Dependency profile requires a valid exact package version")
    return value


def profile_constraints(work: Path, profile: str) -> tuple[Path, dict[str, str]]:
    """Keep the complete locked export, or constrain the declared two direct floors."""
    if profile not in PROFILES:
        raise ValueError("Unknown OpenAI dependency profile")
    requirements = work / f"openai-{profile}.txt"
    if profile == "minimum":
        requirements.write_bytes((ROOT / "scripts/constraints/openai-minimum.txt").read_bytes())
        return requirements, MINIMUM.copy()
    subprocess.run(
        [
            "uv",
            "export",
            "--frozen",
            "--no-dev",
            "--extra",
            "openai",
            "--no-emit-project",
            "--no-hashes",
            "--output-file",
            str(requirements),
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
        timeout=PREPARATION_TIMEOUT,
    )
    exported = requirements.read_text(encoding="utf-8")
    expected = {}
    for name in MINIMUM:
        pins = re.findall(rf"^{re.escape(name)}==([^\s;\\]+)", exported, re.MULTILINE)
        if len(pins) != 1:
            raise ValueError("Locked OpenAI profile must select one direct package version")
        expected[name] = _exact_version(pins[0])
    return requirements, expected


def fresh_environment(work: Path) -> Path:
    environment = work / "venv"
    subprocess.run(
        ["uv", "venv", "--python", sys.executable, str(environment)],
        check=True,
        timeout=PREPARATION_TIMEOUT,
    )
    return environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def build_options(python: Path, work: Path, artifact: Path) -> list[str]:
    """Seed only reviewed build tooling when installing source or a source archive."""
    if artifact.suffix == ".whl":
        return []
    requirements = work / "build-requirements.txt"
    subprocess.run(
        [
            "uv",
            "export",
            "--frozen",
            "--only-group",
            "build",
            "--no-emit-project",
            "--output-file",
            str(requirements),
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
        timeout=PREPARATION_TIMEOUT,
    )
    subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(python),
            "--index-url",
            "https://pypi.org/simple",
            "--require-hashes",
            "--only-binary",
            ":all:",
            "--requirements",
            str(requirements),
        ],
        cwd=work,
        check=True,
        timeout=PREPARATION_TIMEOUT,
    )
    return ["--no-build-isolation-package", "guardtrellis"]


def _probe(python: Path, work: Path, function: str, *arguments) -> subprocess.CompletedProcess:
    code = (
        "import runpy\nfrom pathlib import Path\n"
        f"checks = runpy.run_path({str(Path(__file__).resolve())!r})\n"
        f"checks[{function!r}](*{arguments!r})\n"
    )
    return subprocess.run(
        [str(python), "-I", "-c", code],
        cwd=work,
        check=True,
        capture_output=True,
        text=True,
        env=runtime_environment(),
        timeout=RUNTIME_TIMEOUT,
    )


def _deny_network() -> None:
    """Audit hooks also reject socket access if imported code replaces socket methods."""

    def audit(event, args):
        if event in {
            "socket.connect",
            "socket.getaddrinfo",
            "socket.gethostbyname",
            "socket.gethostbyaddr",
            "socket.getnameinfo",
            "socket.sendto",
            "socket.sendmsg",
        }:
            raise AssertionError("Network access is forbidden in OpenAI profile runtime checks")

    sys.addaudithook(audit)


def _assert_installed(expected: dict[str, str]) -> None:
    from importlib.metadata import version
    from importlib.util import find_spec

    import guardtrellis

    assert {name: version(name) for name in expected} == expected
    assert expected["openai"].split(".")[0] == "3"
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert version("guardtrellis") == project["version"]
    origin = Path(guardtrellis.__file__).resolve()
    assert origin.is_relative_to(Path(sys.prefix).resolve()) and "site-packages" in origin.parts
    for name in ("google.genai", "fastapi", "langgraph", "httpx"):
        # A missing namespace parent also raises ModuleNotFoundError.
        try:
            spec = find_spec(name)
        except ModuleNotFoundError:
            spec = None
        assert spec is None, name


def _probe_clients(examples: list[str], expected: dict[str, str]) -> None:
    import runpy

    _deny_network()
    _assert_installed(expected)
    import httpx2

    for name in examples:
        recipe = runpy.run_path(name)
        options = {"api_key": "mock-not-a-credential", "transport": None}
        if Path(name).name == "azure_openai_app.py":
            options.update(endpoint=recipe["MOCK_ENDPOINT"], api_version=recipe["MOCK_API_VERSION"])
        with recipe["make_client"](**options) as client:
            # SDK-private inspection is limited to these selected SDK3 test profiles.
            backend = client._client
            assert isinstance(backend, httpx2.Client) and not backend.is_closed
            assert client.max_retries == 0 and not backend.follow_redirects
        assert backend.is_closed
    print(json.dumps({"versions": expected, "backend": "httpx2", "sync_closed": True}))


def _copy_examples(work: Path) -> list[str]:
    examples = []
    for name in EXAMPLES:
        copied = work / name
        copied.write_bytes((ROOT / "examples" / name).read_bytes())
        examples.append(str(copied))
    return examples


def assert_openai_profile(python: Path, work: Path, expected: dict[str, str]) -> None:
    """Construct and synchronously close both actual HTTPX2 default clients, offline."""
    completed = _probe(python, work, "_probe_clients", _copy_examples(work), expected)
    if completed.stderr:
        raise ValueError("OpenAI client profile probe emitted unexpected stderr")
    print(completed.stdout, end="", flush=True)


def _execute_example(example: str) -> None:
    import runpy

    _deny_network()
    sys.argv = [example]
    runpy.run_path(example, run_name="__main__")


def run_mocked_examples(python: Path, work: Path, expected: dict[str, str]) -> None:
    """Execute only the copied default mock commands, with socket/DNS denial."""
    for example in _copy_examples(work):
        completed = _probe(python, work, "_execute_example", example)
        lines = completed.stdout.splitlines()
        report = json.loads(lines[0])
        assert report["mode"] == "mock" and report["passed"]
        assert report["requests"] == 1 and report["blocked_input_prevented_request"]
        assert {name: report["versions"][name] for name in expected} == expected
        assert lines[1:] == ["Contact [PII]"] and not completed.stderr
        print(completed.stdout, end="", flush=True)


def _installed_versions() -> None:
    from importlib.metadata import distributions

    versions = {}
    for distribution in distributions():
        name = re.sub(r"[-_.]+", "-", distribution.metadata["Name"]).lower()
        if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) is None or name in versions:
            raise ValueError("Installed distribution metadata must have unique valid names")
        versions[name] = _exact_version(distribution.version)
    if not versions:
        raise ValueError("Installed runtime closure must not be empty")
    print(json.dumps(versions, sort_keys=True))


def snapshot_runtime_closure(python: Path, work: Path) -> dict[str, str]:
    """Read every initial installed package, including source-build seed tooling."""
    completed = _probe(python, work, "_installed_versions")
    versions = json.loads(completed.stdout)
    if not isinstance(versions, dict) or not versions:
        raise ValueError("Installed runtime closure must be a nonempty version mapping")
    for name, version in versions.items():
        if not isinstance(name, str) or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) is None:
            raise ValueError("Invalid installed package name in runtime closure")
        if not isinstance(version, str):
            raise ValueError("Invalid installed package version in runtime closure")
        _exact_version(version)
    return versions


def assert_runtime_closure(python: Path, work: Path, expected_closure: dict[str, str]) -> None:
    """Allow new test tools; reject replacement or removal of any initial distribution."""
    actual = snapshot_runtime_closure(python, work)
    if any(actual.get(name) != version for name, version in expected_closure.items()):
        raise ValueError("Initial runtime closure changed during compatibility regressions")
    print(
        json.dumps(
            {"runtime_closure_unchanged": True, "installed_closure": actual}, sort_keys=True
        ),
        flush=True,
    )


def assert_regression_report(report: Path) -> None:
    """A successful exit with empty collection or skipped adapter paths is insufficient."""
    suites = list(ElementTree.parse(report).getroot().iter("testsuite"))
    try:
        counts = [
            {
                field: int(suite.attrib[field])
                for field in ("tests", "skipped", "failures", "errors")
            }
            for suite in suites
        ]
    except (KeyError, ValueError) as error:
        raise ValueError("Incomplete OpenAI regression test report") from error
    if not sum(row["tests"] for row in counts) or any(
        value < 0 or (field != "tests" and value != 0)
        for row in counts
        for field, value in row.items()
    ):
        raise ValueError("OpenAI regressions must execute tests without skips or failures")


def _run_pytest(report: str) -> None:
    """Deny network in pytest and its two existing command-test child interpreters."""
    _deny_network()
    original_run = subprocess.run

    def guarded_run(command, *args, **kwargs):
        allowed = {str(ROOT / "examples" / name) for name in EXAMPLES}
        if len(command) != 2 or command[0] != sys.executable or command[1] not in allowed:
            raise AssertionError("Unexpected subprocess in OpenAI adapter regressions")
        runner = (
            "import runpy\n"
            f"checks = runpy.run_path({str(Path(__file__).resolve())!r})\n"
            f"checks['_execute_example']({command[1]!r})\n"
        )
        return original_run([sys.executable, "-I", "-c", runner], *args, **kwargs)

    subprocess.run = guarded_run
    import pytest

    raise SystemExit(pytest.main(["-W", "error", f"--junitxml={report}", *REGRESSIONS]))


def run_regressions(python: Path, work: Path, expected: dict[str, str]) -> None:
    """Freeze all runtime packages before adding reviewed, hash-checked test tools."""
    initial = snapshot_runtime_closure(python, work)
    if {name: initial.get(name) for name in expected} != expected:
        raise ValueError("Installed OpenAI dependency profile differs before regressions")
    (work / "runtime-closure.json").write_text(
        json.dumps(initial, sort_keys=True), encoding="utf-8"
    )
    freeze = work / "runtime-closure.txt"
    freeze.write_text(
        "".join(f"{name}=={value}\n" for name, value in sorted(initial.items())), encoding="utf-8"
    )
    print(json.dumps({"initial_runtime_closure": initial}, sort_keys=True), flush=True)
    tooling = work / "test-tooling.txt"
    subprocess.run(
        [
            "uv",
            "export",
            "--frozen",
            "--only-group",
            "dev",
            "--no-emit-project",
            *(argument for name in NON_REGRESSION_TOOLS for argument in ("--prune", name)),
            "--output-file",
            str(tooling),
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
        timeout=PREPARATION_TIMEOUT,
    )
    selected_tools = set(
        re.findall(r"^([a-z0-9][a-z0-9-]*)==", tooling.read_text(encoding="utf-8"), re.MULTILINE)
    )
    if not {"pytest", "pytest-asyncio"}.issubset(selected_tools) or selected_tools.intersection(
        NON_REGRESSION_TOOLS
    ):
        raise ValueError("Locked regression tooling must select only the pytest tool roots")
    subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(python),
            "--index-url",
            "https://pypi.org/simple",
            "--constraint",
            str(freeze),
            "--require-hashes",
            "--requirements",
            str(tooling),
        ],
        cwd=work,
        check=True,
        timeout=PREPARATION_TIMEOUT,
    )
    subprocess.run(
        ["uv", "pip", "check", "--python", str(python)], check=True, timeout=PREPARATION_TIMEOUT
    )
    assert_runtime_closure(python, work, initial)
    report = work / "openai-regressions.xml"
    runner = (
        "import runpy\n"
        f"checks = runpy.run_path({str(Path(__file__).resolve())!r})\n"
        f"checks['_run_pytest']({str(report)!r})\n"
    )
    subprocess.run(
        [str(python), "-I", "-c", runner],
        cwd=ROOT,
        check=True,
        env=runtime_environment(),
        timeout=REGRESSION_TIMEOUT,
    )
    assert_regression_report(report)
    assert_runtime_closure(python, work, initial)
    subprocess.run(
        ["uv", "pip", "check", "--python", str(python)], check=True, timeout=PREPARATION_TIMEOUT
    )


def print_evidence(python: Path, work: Path, profile: str, expected: dict[str, str]) -> None:
    """Record reproducible source identities and runtime facts without local paths."""
    files = [
        "pyproject.toml",
        "uv.lock",
        "scripts/openai_profiles.py",
        "scripts/check_openai_profile.py",
        "scripts/constraints/openai-minimum.txt",
        *(f"examples/{name}" for name in EXAMPLES),
        *REGRESSIONS,
        *(
            path.relative_to(ROOT).as_posix()
            for path in sorted((ROOT / "src/guardtrellis").rglob("*"))
            if path.is_file() and (path.suffix == ".py" or path.name == "py.typed")
        ),
    ]
    uv = subprocess.run(
        ["uv", "--version"], check=True, capture_output=True, text=True, timeout=RUNTIME_TIMEOUT
    )
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=RUNTIME_TIMEOUT,
    )
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=RUNTIME_TIMEOUT,
    )
    runtime = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            "import json,platform;print(json.dumps({"
            "'python':platform.python_version(),"
            "'implementation':platform.python_implementation(),"
            "'system':platform.system(),'machine':platform.machine()}))",
        ],
        cwd=work,
        check=True,
        capture_output=True,
        text=True,
        env=runtime_environment(),
        timeout=RUNTIME_TIMEOUT,
    )
    print(
        json.dumps(
            {
                "profile": profile,
                "selected_versions": expected,
                "base_revision": revision.stdout.strip(),
                "worktree_dirty": bool(status.stdout.strip()),
                "source_sha256": {
                    name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in files
                },
                "uv": uv.stdout.strip(),
                "runtime": json.loads(runtime.stdout),
                "initial_installed_closure": snapshot_runtime_closure(python, work),
            },
            sort_keys=True,
        ),
        flush=True,
    )
