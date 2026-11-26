"""Install each built distribution into a fresh environment outside the source tree.

Run `uv build --offline --no-build-isolation` with the locked build group first.
Dependencies must be cached when running with UV_OFFLINE=1.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from gemini_profiles import (
    PROFILES,
    assert_gemini_profile,
    build_options,
    fresh_environment,
    profile_constraints,
    run_mocked_example,
)
from openai_profiles import (
    PROFILES as OPENAI_PROFILES,
)
from openai_profiles import (
    assert_openai_profile,
    print_evidence,
    run_mocked_examples,
)
from openai_profiles import (
    build_options as openai_build_options,
)
from openai_profiles import (
    fresh_environment as openai_environment,
)
from openai_profiles import (
    profile_constraints as openai_constraints,
)

ROOT = Path(__file__).resolve().parents[1]
CORE_EXAMPLES = (
    "plain_callable.py",
    "retrieval_tools.py",
    "policy_operations.py",
    "decoded_query.py",
    "decoded_contact.py",
    "tool_result_handoff.py",
)
SMOKE = """
from pathlib import Path
import guardtrellis
from importlib.util import find_spec
from importlib.metadata import distributions
from guardtrellis import Action, Guard, JSONScanner, PIIScanner, SecretScanner, Stage, ToolGuard

assert 'site-packages' in str(Path(guardtrellis.__file__).resolve())
assert Path(guardtrellis.__file__).with_name('py.typed').is_file()
assert find_spec('fastapi') is None and find_spec('langgraph') is None
assert find_spec('openai') is None
assert find_spec('httpx') is None and find_spec('httpx2') is None
assert 'google-genai' not in {package.metadata['Name'] for package in distributions()}
assert Guard(input_scanners=[PIIScanner()]).scan('a@example.org').text == '[PII]'
invalid = Guard(output_scanners=[JSONScanner()]).scan('{invalid}', stage=Stage.OUTPUT)
assert invalid.action == Action.BLOCK
assert ToolGuard({'search': {'type':'object'}}).validate('search', '{}').accepted
calls = []
rejected = Guard(input_scanners=[JSONScanner()]).run('invalid JSON', calls.append)
assert not calls and rejected.text is None and rejected.action == Action.BLOCK
for uri in (
    'postgresql://db.example.invalid/demo?password=SyntheticPackage42',
    'mongodb+srv://app:SyntheticPackage43@cluster.example.invalid/demo',
):
    assert Guard(input_scanners=[SecretScanner()]).scan(uri).action == Action.ALLOW
    rejected = Guard(input_scanners=[SecretScanner(connection_strings=True)]).run(uri, calls.append)
    assert not calls and rejected.text is None and rejected.action == Action.BLOCK
    finding = rejected.input_result.findings[0]
    assert (finding.start, finding.end) == (0, len(uri))
print('Installed package smoke passed:', guardtrellis.__version__)
"""


OPENAI_SMOKE = """
from importlib.util import find_spec
from importlib.metadata import version

assert version('openai').split('.')[0] == '3'
assert find_spec('httpx2') is not None and find_spec('httpx') is None
assert find_spec('fastapi') is None and find_spec('langgraph') is None
print('OpenAI-only extra smoke passed')
"""


def smoke_cli(python: Path, work: Path) -> None:
    """Exercise real installed launchers with byte streams on every native CI OS."""
    console = python.with_name("guardtrellis.exe" if os.name == "nt" else "guardtrellis")
    source = work / "fixture with spaces 雪.txt"
    payload = "\ufeffOpening hours\r\n雪\x00\x1b[31m".encode("utf-8")
    source.write_bytes(payload)
    canary = b"SyntheticCliSmokeCanary91"
    stripe_source = work / (canary.decode("ascii") + " with spaces 雪.txt")
    key = b"sk_test_" + b"S" * 24
    publishable = b"pk_live_" + b"P" * 24

    def metadata(
        raw: bytes,
        policy: str,
        action: str,
        codes: tuple[str, ...],
        *,
        stripe_keys: bool = False,
        connection_strings: bool = False,
    ) -> None:
        # Installed-smoke assertions, not a reusable version-2 application consumer.
        assert len(raw) <= 128 * 1024 and raw.endswith(b"\n") and raw.count(b"\n") == 1
        assert b"\r" not in raw and canary not in raw and key not in raw and publishable not in raw
        assert b"demo@example.org" not in raw and b"SyntheticInstall42" not in raw
        report = json.loads(raw)
        assert set(report) == {
            "report_version",
            "sdk_version",
            "stage",
            "policy",
            "options",
            "result",
            "error",
        }
        assert type(report["report_version"]) is int
        assert report["report_version"] == (2 if stripe_keys else 1)
        assert report["sdk_version"] == installed_version
        assert report["stage"] == "retrieval" and report["policy"] == policy
        options = report["options"]
        assert set(options) == (
            {"connection_strings", "phone_mode", "stripe_keys"}
            if stripe_keys
            else {"connection_strings", "phone_mode"}
        )
        assert type(options["connection_strings"]) is bool
        assert options["connection_strings"] is connection_strings
        assert options["phone_mode"] == ("contiguous" if policy == "privacy" else None)
        if stripe_keys:
            assert options["stripe_keys"] is True
        assert report["error"] is None
        result = report["result"]
        assert set(result) == {"action", "stage", "findings", "trace"}
        assert result["action"] == action and result["stage"] == "retrieval"
        assert [item["code"] for item in result["findings"]] == list(codes)
        for item in result["findings"]:
            assert set(item) == {"code", "start", "end", "scanner", "scanner_index", "revision"}
            if action == "error":
                assert item["start"] is None and item["end"] is None
        for item in result["trace"]:
            assert set(item) == {
                "scanner",
                "scanner_index",
                "action",
                "revision_before",
                "revision_after",
            }

    for command in ([str(console)], [str(python), "-I", "-m", "guardtrellis"]):
        version = subprocess.run(
            [*command, "--version"], capture_output=True, cwd=work, timeout=15, check=True
        )
        assert version.stdout.startswith(b"guardtrellis ") and not version.stderr
        installed_version = version.stdout.removeprefix(b"guardtrellis ").strip().decode("ascii")
        for selection in (["--stdin"], ["--file", str(source)]):
            checked = subprocess.run(
                [
                    *command,
                    "check",
                    *selection,
                    "--stage",
                    "tool",
                    "--policy",
                    "secrets",
                    "--format",
                    "json",
                    "--output",
                    "checked-text",
                ],
                input=payload,
                capture_output=True,
                cwd=work,
                timeout=15,
                check=True,
            )
            assert checked.stdout == payload
            assert json.loads(checked.stderr)["result"]["action"] == "allow"
        for data, options, status, action in (
            (b"Contact demo@example.org", [], 0, "redact"),
            (
                b"postgresql://app:SyntheticInstall42@db.invalid/demo",
                ["--connection-strings"],
                1,
                "block",
            ),
        ):
            checked = subprocess.run(
                [
                    *command,
                    "check",
                    "--stdin",
                    "--stage",
                    "retrieval",
                    "--policy",
                    "privacy",
                    "--format",
                    "json",
                    "--output",
                    "checked-text",
                    *options,
                ],
                input=data,
                capture_output=True,
                cwd=work,
                timeout=15,
            )
            assert checked.returncode == status
            assert checked.stdout == (b"Contact [PII]" if status == 0 else b"")
            metadata(
                checked.stderr,
                "privacy",
                action,
                ("pii_email",) if status == 0 else ("secret_postgresql_uri",),
                connection_strings=bool(options),
            )
        for data, policy, selected, status, action, expected, codes in (
            (canary + b" " + key, "secrets", False, 0, "allow", canary + b" " + key, ()),
            (canary + b" " + key, "secrets", True, 1, "block", b"", ("secret_stripe_secret_test",)),
            (
                payload + b" " + canary + b" " + publishable,
                "secrets",
                True,
                0,
                "allow",
                payload + b" " + canary + b" " + publishable,
                (),
            ),
            (
                b"Contact demo@example.org ; " + canary,
                "privacy",
                True,
                0,
                "redact",
                b"Contact [PII] ; " + canary,
                ("pii_email",),
            ),
            (
                canary + b" " + key + b" " + b"rk_test_" + b"Z" * 248,
                "secrets",
                True,
                3,
                "error",
                b"",
                ("stripe_key_limit_exceeded",),
            ),
        ):
            stripe_source.write_bytes(data)
            for selection in (["--stdin"], ["--file", str(stripe_source)]):
                checked = subprocess.run(
                    [
                        *command,
                        "check",
                        *selection,
                        "--stage",
                        "retrieval",
                        "--policy",
                        policy,
                        "--format",
                        "json",
                        "--output",
                        "checked-text",
                        *(["--stripe-keys"] if selected else []),
                    ],
                    input=data if selection == ["--stdin"] else b"UnusedStdinCliSmokeCanary92",
                    capture_output=True,
                    cwd=work,
                    timeout=15,
                )
                assert checked.returncode == status and checked.stdout == expected
                metadata(checked.stderr, policy, action, codes, stripe_keys=selected)
                assert stripe_source.read_bytes() == data
        marked = subprocess.run(
            [
                *command,
                "check",
                "--stdin",
                "--stage",
                "retrieval",
                "--policy",
                "secrets",
                "--stripe-keys",
                "--format",
                "text",
            ],
            input=canary,
            capture_output=True,
            cwd=work,
            timeout=15,
            check=True,
        )
        assert marked.stdout == b"stage=retrieval action=allow findings=0 codes= stripe_keys=true\n"
        assert not marked.stderr
    assert source.read_bytes() == payload
    example = work / "cli_ci.py"
    shutil.copyfile(ROOT / "examples" / "cli_ci.py", example)
    example_source = work / "ci-example-fixture.txt"
    example_source.write_bytes(b"Opening hours: 9am to 5pm.")
    subprocess.run(
        [str(python), "-I", str(example), str(example_source)], cwd=work, check=True, timeout=20
    )
    assert source.read_bytes() == payload
    assert example_source.read_bytes() == b"Opening hours: 9am to 5pm."


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--gemini-profile", choices=PROFILES, default="locked")
    parser.add_argument("--openai-profile", choices=OPENAI_PROFILES, default="locked")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--gemini-only", action="store_true")
    selection.add_argument("--openai-only", action="store_true")
    args = parser.parse_args()
    directory = args.dist_dir.resolve()
    wheels = list(directory.glob("*.whl"))
    sdists = list(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("Expected exactly one wheel and one source distribution in dist/")
    # Keep OpenAI isolated before other extras can mask its dependency requirements.
    stages = (
        ("", SMOKE, CORE_EXAMPLES),
        ("[openai]", OPENAI_SMOKE, ("openai_app.py", "azure_openai_app.py")),
        (
            "[fastapi,langgraph,openai,gemini]",
            None,
            (
                *CORE_EXAMPLES,
                "fastapi_app.py",
                "langgraph_app.py",
                "openai_app.py",
                "azure_openai_app.py",
                "gemini_app.py",
            ),
        ),
    )
    for artifact in wheels + sdists:
        # Gemini's environment is fresh for each artifact and profile. Running it
        # earlier in the shared stages below would still leak core/OpenAI extras.
        if not args.openai_only:
            smoke_gemini(artifact, args.gemini_profile)
        if not args.gemini_only:
            smoke_openai(artifact, args.openai_profile)
        if args.gemini_only or args.openai_only:
            continue
        with tempfile.TemporaryDirectory(prefix="guardtrellis-install-") as directory:
            work = Path(directory)
            environment = work / "venv"
            python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            subprocess.run(["uv", "venv", "--python", sys.executable, str(environment)], check=True)
            build_options = []
            if artifact.suffix != ".whl":
                # Seed disposable source-install environments with the reviewed backend,
                # rather than resolving another build backend during the smoke.
                requirements = work / "build-requirements.txt"
                subprocess.run(
                    [
                        "uv",
                        "export",
                        "--locked",
                        "--only-group",
                        "build",
                        "--no-emit-project",
                        "--output-file",
                        str(requirements),
                    ],
                    cwd=ROOT,
                    check=True,
                )
                subprocess.run(
                    [
                        "uv",
                        "pip",
                        "install",
                        "--python",
                        str(python),
                        "--require-hashes",
                        "--only-binary",
                        ":all:",
                        "--requirements",
                        str(requirements),
                    ],
                    cwd=work,
                    check=True,
                )
                build_options = ["--no-build-isolation-package", "guardtrellis"]
            for extras, smoke, examples in stages:
                subprocess.run(
                    [
                        "uv",
                        "pip",
                        "install",
                        "--python",
                        str(python),
                        "--index-url",
                        "https://pypi.org/simple",
                        *build_options,
                        f"{artifact}{extras}",
                    ],
                    cwd=work,
                    check=True,
                )
                subprocess.run(["uv", "pip", "check", "--python", str(python)], check=True)
                if smoke is not None:
                    subprocess.run([str(python), "-I", "-c", smoke], cwd=work, check=True)
                if extras == "":
                    smoke_cli(python, work)
                for filename in examples:
                    example = work / filename
                    shutil.copyfile(ROOT / "examples" / filename, example)
                    subprocess.run([str(python), "-I", str(example)], cwd=work, check=True)
            print(f"Verified {artifact.name}", flush=True)


def smoke_gemini(artifact: Path, profile: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"guardtrellis-gemini-{profile}-") as directory:
        work = Path(directory)
        python = fresh_environment(work)
        constraints, expected = profile_constraints(work, profile)
        options = build_options(python, work, artifact)
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
                str(constraints),
                *options,
                f"{artifact}[gemini]",
            ],
            cwd=work,
            check=True,
        )
        subprocess.run(["uv", "pip", "check", "--python", str(python)], check=True)
        assert_gemini_profile(python, work, expected)
        run_mocked_example(python, work, expected)
        print(f"Verified {artifact.name}: Gemini-only {profile}", flush=True)


def smoke_openai(artifact: Path, profile: str) -> None:
    """Verify both provider examples in a fresh, explicitly constrained consumer."""
    with tempfile.TemporaryDirectory(prefix=f"guardtrellis-openai-{profile}-") as directory:
        work = Path(directory)
        python = openai_environment(work)
        constraints, expected = openai_constraints(work, profile)
        options = openai_build_options(python, work, artifact)
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
                str(constraints),
                *options,
                f"{artifact}[openai]",
            ],
            cwd=work,
            check=True,
            timeout=180,
        )
        subprocess.run(["uv", "pip", "check", "--python", str(python)], check=True, timeout=30)
        print(
            json.dumps(
                {
                    "artifact": artifact.name,
                    "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        print_evidence(python, work, profile, expected)
        assert_openai_profile(python, work, expected)
        run_mocked_examples(python, work, expected)
        print(f"Verified {artifact.name}: OpenAI/Azure-only {profile}", flush=True)


if __name__ == "__main__":
    main()
