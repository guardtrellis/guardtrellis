"""Fresh optional metrics environments; no installed GuardTrellis observability extra."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ("disabled", "minimum", "locked")
MINIMUM = {"opentelemetry-api": "1.45.2", "opentelemetry-sdk": "1.45.2"}


def profile_constraints(work: Path, profile: str) -> tuple[Path | None, dict[str, str]]:
    """Export a complete locked closure, or constrain the two declared direct floors."""
    if profile not in PROFILES:
        raise ValueError("Unknown observability dependency profile")
    if profile == "disabled":
        return None, {}
    requirements = work / f"observability-{profile}.txt"
    if profile == "minimum":
        requirements.write_bytes(
            (ROOT / "scripts/constraints/observability-minimum.txt").read_bytes()
        )
        return requirements, MINIMUM.copy()
    subprocess.run(
        [
            "uv",
            "export",
            "--frozen",
            "--no-dev",
            "--group",
            "observability",
            "--no-emit-project",
            "--no-hashes",
            "--output-file",
            str(requirements),
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    exported = requirements.read_text(encoding="utf-8")
    expected = {}
    for name in MINIMUM:
        versions = set(re.findall(rf"^{re.escape(name)}==([^\s;\\]+)", exported, re.MULTILINE))
        if len(versions) != 1:
            raise ValueError("Locked observability profile must select one direct package version")
        expected[name] = versions.pop()
    if len(set(expected.values())) != 1:
        raise ValueError("The selected OpenTelemetry API and SDK versions must agree")
    return requirements, expected


def fresh_environment(work: Path) -> Path:
    environment = work / "venv"
    subprocess.run(["uv", "venv", "--python", sys.executable, str(environment)], check=True)
    return environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def install_profile(python: Path, work: Path, profile: str) -> dict[str, str]:
    """Install a wheel with published core dependencies, plus explicitly opted-in metrics."""
    constraints, expected = profile_constraints(work, profile)
    artifacts = work / "artifacts"
    subprocess.run(
        [
            "uv",
            "build",
            "--wheel",
            "--offline",
            "--no-build-isolation",
            "--out-dir",
            str(artifacts),
        ],
        cwd=ROOT,
        check=True,
    )
    wheels = list(artifacts.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("Observability profile must install exactly one SDK wheel")
    command = [
        "uv",
        "pip",
        "install",
        "--python",
        str(python),
        "--index-url",
        "https://pypi.org/simple",
    ]
    if constraints is not None:
        command.extend(["--constraint", str(constraints), "opentelemetry-api", "opentelemetry-sdk"])
    subprocess.run([*command, str(wheels[0])], cwd=work, check=True)
    subprocess.run(["uv", "pip", "check", "--python", str(python)], check=True)
    return expected


def assert_healthy_export_schema(payload) -> None:
    """Inspect the serialized healthy export; unknown non-canary metadata also fails."""
    assert set(payload) == {"resource_metrics"} and len(payload["resource_metrics"]) == 1
    resource = payload["resource_metrics"][0]
    assert set(resource) - {"schema_url"} == {"resource", "scope_metrics"}
    assert resource.get("schema_url") in (None, "")
    assert set(resource["resource"]) - {"schema_url"} == {"attributes"}
    assert resource["resource"]["attributes"] == {"service.name": "guardtrellis-observability-demo"}
    assert resource["resource"].get("schema_url") in (None, "")
    assert len(resource["scope_metrics"]) == 1
    scoped = resource["scope_metrics"][0]
    assert set(scoped) - {"schema_url"} == {"scope", "metrics"}
    assert scoped.get("schema_url") in (None, "")
    scope = scoped["scope"]
    assert set(scope) - {"schema_url", "attributes"} == {"name", "version"}
    assert scope["name"] == "guardtrellis.examples.tool_result_metrics"
    assert scope["version"] == "1" and scope.get("schema_url") in (None, "")
    assert scope.get("attributes") is None or scope["attributes"] == {}
    definitions = {
        "guardtrellis.checks": (
            "{check}",
            "Number of retrieval scan attempts that completed or raised.",
        ),
        "guardtrellis.check.duration": (
            "s",
            "Elapsed time of a retrieval scan attempt in seconds.",
        ),
    }
    assert len(scoped["metrics"]) == 2
    assert {metric["name"] for metric in scoped["metrics"]} == set(definitions)
    for metric in scoped["metrics"]:
        assert set(metric) == {"name", "unit", "description", "data"}
        assert (metric["unit"], metric["description"]) == definitions[metric["name"]]
        histogram = metric["name"] == "guardtrellis.check.duration"
        data = metric["data"]
        assert set(data) == {"data_points", "aggregation_temporality"} | (
            set() if histogram else {"is_monotonic"}
        )
        assert len(data["data_points"]) == 1
        point = data["data_points"][0]
        assert set(point) == {
            "attributes",
            "start_time_unix_nano",
            "time_unix_nano",
            "exemplars",
        } | (
            {"count", "sum", "bucket_counts", "explicit_bounds", "min", "max"}
            if histogram
            else {"value"}
        )
        assert point["attributes"] == {"stage": "retrieval", "outcome": "redact"}
        assert point["exemplars"] == []


def probe_recipe(example: Path, expected: dict[str, str]) -> None:
    """Run only in an isolated consumer process, using a copied source recipe."""
    import contextlib
    import io
    import json
    import logging
    import math
    import os
    import runpy
    import socket
    import sys
    from importlib.metadata import version
    from importlib.util import find_spec

    def forbidden(*args, **kwargs):
        raise AssertionError("Unexpected network, global-provider or handoff lifecycle call")

    socket.create_connection = forbidden
    socket.socket.connect = forbidden
    socket.socket.connect_ex = forbidden
    socket.getaddrinfo = forbidden
    for name in ("openai", "google", "fastapi", "langgraph", "httpx", "httpx2"):
        assert find_spec(name) is None, name
    assert not any(
        name == "opentelemetry" or name.startswith("opentelemetry.") for name in sys.modules
    )
    if not expected:
        assert find_spec("opentelemetry") is None
        original_getitem = type(os.environ).__getitem__

        def guarded_getitem(self, key):
            if isinstance(key, str) and key.startswith("OTEL_"):
                raise AssertionError("Disabled recipe read telemetry configuration")
            return original_getitem(self, key)

        type(os.environ).__getitem__ = guarded_getitem

    recipe = runpy.run_path(str(example))
    assert not any(
        name == "opentelemetry" or name.startswith("opentelemetry.") for name in sys.modules
    )
    if not expected:
        state = []
        assert (
            recipe["scan_and_consume"](
                "Contact privacy-probe@example.org", state.append, clock=forbidden
            )
            == "Contact [PII]"
        )
        assert state == ["Contact [PII]"]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            recipe["main"]([])
        assert output.getvalue() == "Checked handoff completed (metrics disabled).\n"
        assert not any(
            name == "opentelemetry" or name.startswith("opentelemetry.") for name in sys.modules
        )
        print(
            json.dumps(
                {"profile": "disabled", "opentelemetry_absent": True, "checked_delivery": True}
            )
        )
        return

    assert {name: version(name) for name in expected} == expected
    from opentelemetry import metrics, trace
    from opentelemetry.sdk import resources
    from opentelemetry.sdk.metrics.export import Histogram, Sum

    metrics.set_meter_provider = forbidden
    metrics.get_meter_provider = forbidden
    trace.set_tracer_provider = forbidden
    resources.Resource.create = forbidden
    resources.get_aggregated_resources = forbidden

    logs = io.StringIO()
    handler = logging.StreamHandler(logs)
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.DEBUG)
    demo = recipe["create_demo_metrics"]()
    state = []
    ticks = iter((10.0, 10.125))
    trace_id = 0xABCDEF0123456789ABCDEF0123456789
    span_id = 0xABCDEF0123456789
    active = trace.NonRecordingSpan(
        trace.SpanContext(trace_id, span_id, False, trace.TraceFlags.SAMPLED)
    )
    originals = []
    for target, name in (
        (demo.provider, "force_flush"),
        (demo.provider, "shutdown"),
        (demo.reader, "collect"),
        (demo.reader, "get_metrics_data"),
    ):
        originals.append((target, name, getattr(target, name)))
        setattr(target, name, forbidden)
    try:
        with trace.use_span(active):
            checked = recipe["scan_and_consume"](
                "CANARY_RETURN Contact privacy-probe@example.org",
                state.append,
                instruments=demo.instruments,
                clock=lambda: next(ticks),
            )
        assert state == [checked] == ["CANARY_RETURN Contact [PII]"]
    finally:
        for target, name, method in originals:
            setattr(target, name, method)

    try:
        data = demo.reader.get_metrics_data()
        assert data is not None and len(data.resource_metrics) == 1
        resource = data.resource_metrics[0]
        assert dict(resource.resource.attributes) == {
            "service.name": "guardtrellis-observability-demo"
        }
        assert resource.resource.schema_url in (None, "") and resource.schema_url in (None, "")
        assert len(resource.scope_metrics) == 1
        scope_metrics = resource.scope_metrics[0]
        scope = scope_metrics.scope
        assert scope.name == "guardtrellis.examples.tool_result_metrics" and scope.version == "1"
        assert scope.schema_url in (None, "") and scope_metrics.schema_url in (None, "")
        assert dict(scope.attributes or {}) == {}
        definitions = {
            "guardtrellis.checks": (
                Sum,
                "{check}",
                "Number of retrieval scan attempts that completed or raised.",
            ),
            "guardtrellis.check.duration": (
                Histogram,
                "s",
                "Elapsed time of a retrieval scan attempt in seconds.",
            ),
        }
        assert len(scope_metrics.metrics) == 2
        assert {metric.name for metric in scope_metrics.metrics} == set(definitions)
        for metric in scope_metrics.metrics:
            kind, unit, description = definitions[metric.name]
            assert isinstance(metric.data, kind)
            assert (metric.unit, metric.description) == (unit, description)
            assert len(metric.data.data_points) == 1
            assert metric.data.aggregation_temporality in (1, 2)
            point = metric.data.data_points[0]
            assert dict(point.attributes) == {"stage": "retrieval", "outcome": "redact"}
            assert list(point.exemplars) == []
            assert type(point.start_time_unix_nano) is int and type(point.time_unix_nano) is int
            assert 0 < point.start_time_unix_nano <= point.time_unix_nano
            if isinstance(metric.data, Sum):
                assert metric.data.is_monotonic is True and point.value == 1
            else:
                assert point.count == 1 and math.isclose(point.sum, 0.125)
                assert sum(point.bucket_counts) == point.count
                assert len(point.bucket_counts) == len(point.explicit_bounds) + 1
                assert all(type(value) is int and value >= 0 for value in point.bucket_counts)
                assert math.isclose(point.min, 0.125) and math.isclose(point.max, 0.125)
        serialized = data.to_json()
        assert_healthy_export_schema(json.loads(serialized))
        combined = serialized + logs.getvalue()
        for canary in (
            "CANARY_RETURN",
            "privacy-probe@example.org",
            "CANARY_RESOURCE",
            "CANARY_SERVICE",
            format(trace_id, "032x"),
            format(span_id, "016x"),
        ):
            assert canary not in combined, canary
        assert {name: version(name) for name in expected} == expected
        print(
            json.dumps(
                {
                    "profile_versions": expected,
                    "exported_metrics": 2,
                    "checked_delivery": True,
                    "envelope_privacy": True,
                },
                sort_keys=True,
            )
        )
    finally:
        demo.provider.shutdown()


def assert_recipe_profile(python: Path, work: Path, expected: dict[str, str]) -> None:
    """Inspect actual exports in isolated hostile Resource environments, with sockets blocked."""
    example = work / "tool_result_metrics.py"
    example.write_bytes((ROOT / "examples/tool_result_metrics.py").read_bytes())
    probe = (
        "import runpy\nfrom pathlib import Path\n"
        f"checks = runpy.run_path({str(Path(__file__).resolve())!r})\n"
        f"checks['probe_recipe'](Path({str(example)!r}), {expected!r})\n"
    )
    variants = ("disabled",) if not expected else ("empty", "well-formed", "malformed")
    for variant in variants:
        environment = os.environ.copy()
        # Only the isolated test process is configured; the recipe never mutates ambient settings.
        environment["OTEL_SDK_DISABLED"] = "false"
        environment["OTEL_METRICS_EXEMPLAR_FILTER"] = "always_on"
        environment["OTEL_SERVICE_NAME"] = "CANARY_SERVICE"
        environment["OTEL_RESOURCE_ATTRIBUTES"] = {
            "disabled": "CANARY_RESOURCE=disabled",
            "empty": "",
            "well-formed": "private.setting=CANARY_RESOURCE",
            "malformed": "CANARY_RESOURCE",
        }[variant]
        completed = subprocess.run(
            [str(python), "-I", "-c", probe],
            cwd=work,
            env=environment,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        assert not completed.stderr, completed.stderr
        report = json.loads(completed.stdout)
        report["resource_environment"] = variant
        print(json.dumps(report, sort_keys=True), flush=True)


def assert_regression_report(report: Path) -> None:
    """Optional-test skips or empty collection are not profile compatibility evidence."""
    suites = list(ElementTree.parse(report).getroot().iter("testsuite"))
    if not sum(int(suite.get("tests", "0")) for suite in suites) or any(
        int(suite.get(field, "0"))
        for suite in suites
        for field in ("skipped", "failures", "errors")
    ):
        raise ValueError("Observability regressions must execute tests without skips or failures")


def run_regressions(python: Path, work: Path, expected: dict[str, str]) -> None:
    """Add only locked test tooling after proving the consumer profile is isolated."""
    tooling = work / "test-tooling.txt"
    subprocess.run(
        [
            "uv",
            "export",
            "--frozen",
            "--only-group",
            "dev",
            "--no-emit-project",
            "--output-file",
            str(tooling),
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(python),
            "--require-hashes",
            "--requirements",
            str(tooling),
        ],
        cwd=work,
        check=True,
    )
    report = work / "observability-regressions.xml"
    subprocess.run(
        [
            str(python),
            "-I",
            "-m",
            "pytest",
            "-W",
            "error",
            f"--junitxml={report}",
            "tests/test_tool_result_metrics.py",
        ],
        cwd=ROOT,
        check=True,
        timeout=120,
    )
    assert_regression_report(report)
    # A tooling install must not silently replace the dependency versions just tested.
    subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            "from importlib.metadata import version\n"
            f"expected = {expected!r}\n"
            "assert {name: version(name) for name in expected} == expected\n",
        ],
        cwd=work,
        check=True,
    )
