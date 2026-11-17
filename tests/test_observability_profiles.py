"""Optional metrics profiles fail closed and never silently use a different environment."""

import tomllib
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import observability_profiles as profiles


def test_minimum_profile_matches_the_source_only_direct_dependency_floors(tmp_path):
    constraints, expected = profiles.profile_constraints(tmp_path, "minimum")
    assert constraints is not None
    requirements = {
        line.split("==")[0]: line.split("==")[1]
        for line in constraints.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    }
    assert (
        requirements == expected == {"opentelemetry-api": "1.45.2", "opentelemetry-sdk": "1.45.2"}
    )
    metadata = tomllib.loads((profiles.ROOT / "pyproject.toml").read_text())
    assert set(metadata["dependency-groups"]["observability"]) == {
        f"{name}>={version},<2" for name, version in expected.items()
    }
    assert not any("opentelemetry" in value for value in metadata["project"]["dependencies"])
    assert "observability" not in metadata["project"]["optional-dependencies"]


def test_disabled_profile_does_not_create_constraints_or_opt_in(tmp_path):
    assert profiles.profile_constraints(tmp_path, "disabled") == (None, {})
    assert not list(tmp_path.iterdir())


def test_locked_profile_keeps_the_full_exported_dependency_closure(tmp_path, monkeypatch):
    exported = "opentelemetry-api==1.45.2\nopentelemetry-sdk==1.45.2\ntyping-extensions==4.15.0\n"

    def export(command, *, cwd, check, stdout):
        assert cwd == profiles.ROOT and check
        assert stdout == profiles.subprocess.DEVNULL
        assert "--frozen" in command and "--no-dev" in command
        assert command[command.index("--group") + 1] == "observability"
        Path(command[command.index("--output-file") + 1]).write_text(exported, encoding="utf-8")

    monkeypatch.setattr(profiles.subprocess, "run", export)
    constraints, expected = profiles.profile_constraints(tmp_path, "locked")
    assert constraints is not None and constraints.read_text(encoding="utf-8") == exported
    assert expected == {"opentelemetry-api": "1.45.2", "opentelemetry-sdk": "1.45.2"}


@pytest.mark.parametrize(
    "exported",
    [
        "opentelemetry-api==1.45.2\n",
        "opentelemetry-sdk==1.45.2\n",
        "opentelemetry-api==1.45.1\nopentelemetry-api==1.45.2\nopentelemetry-sdk==1.45.2\n",
        "opentelemetry-api==1.45.1\nopentelemetry-sdk==1.45.2\n",
    ],
)
def test_incomplete_ambiguous_or_incompatible_profiles_cannot_claim_validation(
    tmp_path, monkeypatch, exported
):
    def export(command, *, cwd, check, stdout):
        Path(command[command.index("--output-file") + 1]).write_text(exported, encoding="utf-8")

    monkeypatch.setattr(profiles.subprocess, "run", export)
    with pytest.raises(ValueError):
        profiles.profile_constraints(tmp_path, "locked")


def test_unknown_profile_cannot_fall_back_to_an_unconstrained_install(tmp_path):
    with pytest.raises(ValueError, match="Unknown observability"):
        profiles.profile_constraints(tmp_path, "other")
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "platform, executable", [("nt", "Scripts/python.exe"), ("posix", "bin/python")]
)
def test_fresh_profile_uses_native_paths_with_spaces_and_unicode(
    tmp_path, monkeypatch, platform, executable
):
    work = tmp_path / "consumer environment 雪"
    work.mkdir()
    commands = []

    def create(command, *, check):
        assert check
        commands.append(command)

    monkeypatch.setattr(profiles, "os", SimpleNamespace(name=platform))
    monkeypatch.setattr(profiles.subprocess, "run", create)
    python = profiles.fresh_environment(work)
    assert python == work / "venv" / executable
    assert commands == [["uv", "venv", "--python", profiles.sys.executable, str(work / "venv")]]


@pytest.mark.parametrize("tests,skipped", [(0, 0), (119, 1)])
def test_optional_skips_and_empty_collection_are_not_profile_validation(tmp_path, tests, skipped):
    report = tmp_path / "profile.xml"
    report.write_text(
        f'<testsuites><testsuite tests="{tests}" skipped="{skipped}" '
        'failures="0" errors="0"/></testsuites>'
    )
    with pytest.raises(ValueError, match="without skips or failures"):
        profiles.assert_regression_report(report)


def test_successful_profile_requires_actual_non_skipped_regressions(tmp_path):
    report = tmp_path / "profile.xml"
    report.write_text(
        '<testsuites><testsuite tests="119" skipped="0" failures="0" errors="0"/></testsuites>'
    )
    profiles.assert_regression_report(report)


def healthy_export():
    counter_description = "Number of retrieval scan attempts that completed or raised."
    duration_description = "Elapsed time of a retrieval scan attempt in seconds."
    common = {
        "attributes": {"stage": "retrieval", "outcome": "redact"},
        "start_time_unix_nano": 1,
        "time_unix_nano": 2,
        "exemplars": [],
    }
    return {
        "resource_metrics": [
            {
                "resource": {"attributes": {"service.name": "guardtrellis-observability-demo"}},
                "scope_metrics": [
                    {
                        "scope": {
                            "name": "guardtrellis.examples.tool_result_metrics",
                            "version": "1",
                        },
                        "metrics": [
                            {
                                "name": "guardtrellis.checks",
                                "unit": "{check}",
                                "description": counter_description,
                                "data": {
                                    "aggregation_temporality": 2,
                                    "is_monotonic": True,
                                    "data_points": [{**deepcopy(common), "value": 1}],
                                },
                            },
                            {
                                "name": "guardtrellis.check.duration",
                                "unit": "s",
                                "description": duration_description,
                                "data": {
                                    "aggregation_temporality": 2,
                                    "data_points": [
                                        {
                                            **deepcopy(common),
                                            "count": 1,
                                            "sum": 0.125,
                                            "bucket_counts": [1],
                                            "explicit_bounds": [],
                                            "min": 0.125,
                                            "max": 0.125,
                                        }
                                    ],
                                },
                            },
                        ],
                    }
                ],
            }
        ]
    }


@pytest.mark.parametrize(
    "location",
    [
        "envelope",
        "resource_metrics",
        "resource",
        "scope_metrics",
        "scope",
        "metric",
        "data",
        "point",
    ],
)
def test_hostile_environment_export_probe_rejects_unknown_noncanary_metadata(location):
    payload = healthy_export()
    profiles.assert_healthy_export_schema(payload)
    resource = payload["resource_metrics"][0]
    scoped = resource["scope_metrics"][0]
    metric = scoped["metrics"][0]
    target = {
        "envelope": payload,
        "resource_metrics": resource,
        "resource": resource["resource"],
        "scope_metrics": scoped,
        "scope": scoped["scope"],
        "metric": metric,
        "data": metric["data"],
        "point": metric["data"]["data_points"][0],
    }[location]
    target["unreviewed_metadata"] = "ordinary-not-a-canary"
    with pytest.raises(AssertionError):
        profiles.assert_healthy_export_schema(payload)


def test_hostile_environment_probe_rejects_empty_healthy_exports():
    with pytest.raises(AssertionError):
        profiles.assert_healthy_export_schema({"resource_metrics": []})
