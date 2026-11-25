"""Comparison policy attribution, expected errors and bounded worker evidence."""

import copy
import json
import re
import subprocess
import sys
import time

import pytest

from evaluation.stripe_keys import assets, contract, run

CASES, EXPECTATIONS, RESOURCES, CONTROLS, FREEZE = assets.load_frozen()
SDK_VERSION = "0.2.0"
SDK_SHA = "1" * 64
RUNTIME_SHA = "2" * 64


def authored_row(case, expected):
    """Protocol fixtures from frozen data, never an SDK observation or shadow detector."""
    target, desired = expected["contract"], expected["desired"]
    primary = [
        [item["code"], item["start"], item["end"]]
        for item in target["findings"]
        if item["code"] in run.PRIMARY_CODES
    ]
    return {
        "id": case["id"],
        "representation": expected["representation"],
        "action": target["action"],
        "accepted": target["action"] in ("allow", "warn", "redact"),
        "primary": primary,
        "incidental": target["incidental"],
        "findings": target["findings"],
        "consumer_calls": target["consumer_calls"],
        "comparisons": {
            "action": target["action"] == desired["action"],
            "spans": [item[1:] for item in primary] == desired["spans"],
            "text": target["text"] == desired["text"],
            "delivery": (target["consumer_calls"], target["text"])
            == (desired["consumer_calls"], desired["text"]),
        },
        "contract_comparisons": dict.fromkeys(run.CONTRACT_COMPARISONS, True),
        "delivery_integrity": True,
        "contract_match": True,
        "privacy_ok": True,
    }


def protocol_events(cell=0, detector_mode="enabled"):
    context = run.worker_context(True, detector_mode, "main", cell)
    profile, _ = run.CELLS[cell]
    events = [
        {
            "event": "identity",
            "sdk_version": SDK_VERSION,
            "sdk_sha256": SDK_SHA,
            "runtime_sha256": RUNTIME_SHA,
            **context,
        }
    ]
    for case, representation in run.cell_cases(CASES, cell):
        expected = EXPECTATIONS[case["id"], profile, representation, detector_mode]
        events.append({"event": "row", "row": authored_row(case, expected)})
    events.append(
        {
            "event": "complete",
            "count": 48,
            "sdk_version": SDK_VERSION,
            "sdk_sha256": SDK_SHA,
            "runtime_sha256": RUNTIME_SHA,
            "limits": dict.fromkeys(
                ("cpu_seconds", "address_space_bytes", "core_bytes", "output_file_bytes")
            ),
            "resources": {"process_cpu_ms": 0.0, "peak_rss_bytes": None},
            **context,
        }
    )
    return copy.deepcopy(events)


def parse(events, *, cell=0, detector_mode="enabled"):
    encoded = b"".join((json.dumps(item) + "\n").encode() for item in events)
    return run.read_protocol(
        encoded,
        CASES,
        EXPECTATIONS,
        cell,
        SDK_VERSION,
        SDK_SHA,
        runtime_sha=RUNTIME_SHA,
        compare=True,
        detector_mode=detector_mode,
    )


def test_comparison_record_and_inventory_are_complete_and_sdk_free():
    record = run.load_comparison_record(CASES, RESOURCES, CONTROLS)
    assert record["original_freeze_sha256"] == assets.FREEZE_SHA256
    inventory = run.comparison_inventory(CASES, RESOURCES, CONTROLS)
    assert inventory["counts"] == {"main": 1152, "resource": 32, "control": 4, "children": 44}
    assert len(inventory["main_workers"]) == 24
    assert len(inventory["resource_workers"]) == 16
    assert len(inventory["control_workers"]) == 4
    assert len(run.CELLS) == 12 and len(run.inventory(CASES, EXPECTATIONS)) == 576
    assert len(run.inventory(CASES, EXPECTATIONS, compare=True)) == 1152
    code = (
        "import sys; sys.path.insert(0,sys.argv[1]); "
        "from evaluation.stripe_keys import assets,run; "
        "c,e,r,h,f=assets.load_frozen(); run.load_comparison_record(c,r,h); "
        "assert 'guardtrellis' not in sys.modules"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, str(run.ROOT)], capture_output=True, timeout=10
    )
    assert result.returncode == 0 and not result.stdout and not result.stderr


@pytest.mark.parametrize("name", [*run.COMPARISON_FILES, "comparison_v1.json"])
def test_comparison_record_tampering_is_rejected(tmp_path, monkeypatch, name):
    for source in (*run.COMPARISON_FILES, "comparison_v1.json"):
        (tmp_path / source).write_bytes(run.HERE.with_name(source).read_bytes())
    with (tmp_path / name).open("ab") as stream:
        stream.write(b"\n")
    monkeypatch.setattr(run, "HERE", tmp_path / "run.py")
    with pytest.raises(ValueError, match="Comparison protocol or receipt is invalid"):
        run.load_comparison_record(CASES, RESOURCES, CONTROLS)


@pytest.mark.parametrize("profile", contract.PROFILES)
def test_factories_select_the_real_policy_without_adding_option_to_baseline(monkeypatch, profile):
    import guardtrellis

    original, calls = guardtrellis.SecretScanner, []

    def record(**kwargs):
        calls.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(guardtrellis, "SecretScanner", record)
    run.guard_for_mode(profile, "default")
    assert len(calls) == 1 and "stripe_keys" not in calls[0]
    run.guard_for_mode(profile, "enabled")
    assert calls[1]["stripe_keys"] is True


def test_worker_runtime_fingerprint_never_launches_nested_processes(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Workers must not spawn git or other nested processes")

    monkeypatch.setattr(run.subprocess, "run", forbidden)
    assert re.fullmatch(r"[0-9a-f]{64}", run.execution_fingerprint(compare=True))


@pytest.mark.parametrize(
    "field,value",
    [
        ("detector_mode", "default"),
        ("worker_kind", "resource"),
        ("worker_cell", 1),
        ("worker_cell", False),
    ],
)
def test_wrong_policy_kind_or_cell_cannot_contribute_rows(field, value):
    events = protocol_events()
    events[0][field] = value
    rows, _, valid = parse(events)
    assert rows == [] and not valid


def test_completion_policy_mismatch_discards_otherwise_valid_rows():
    events = protocol_events()
    events[-1]["detector_mode"] = "default"
    rows, _, valid = parse(events)
    assert rows == [] and not valid


def test_exact_expected_errors_remain_outside_confusion_counts():
    rows = []
    for detector_mode in contract.MODES:
        for cell in range(12):
            observed, _, valid = parse(
                protocol_events(cell, detector_mode), cell=cell, detector_mode=detector_mode
            )
            assert valid
            rows.extend(observed)
    summary = run.summarize(rows, run.inventory(CASES, EXPECTATIONS, compare=True), compare=True)
    assert summary["expected_error_observations"] == summary["expected_errors"] == 39
    assert summary["unexpected_errors"] == 0 and summary["errors"] == 39
    assert sum(summary[key] for key in ("tp", "fp", "tn", "fn", "errors")) == 1152
    errors = [row for row in rows if row["action"] == "error"]
    assert all(not row["primary"] and not all(row["comparisons"].values()) for row in errors)


def test_wrong_reason_is_an_unexpected_error_even_at_an_expected_error_coordinate():
    events = protocol_events()
    target = next(event["row"] for event in events if event.get("row", {}).get("action") == "error")
    target["findings"][0]["code"] = "scanner_error"
    target["incidental"] = [["scanner_error", None, None]]
    target["contract_comparisons"]["findings"] = False
    target["contract_match"] = False
    rows, _, valid = parse(events)
    assert valid
    summary = run.summarize(rows, run.inventory(CASES, EXPECTATIONS, compare=True), compare=True)
    assert summary["unexpected_errors"] == 1 and summary["contract_failures"] == 1
    assert summary["expected_errors"] == summary["errors"] - 1


def test_expected_errors_do_not_fail_completed_main_contracts():
    runs = []
    for detector_mode in contract.MODES:
        for cell in range(12):
            rows, _, valid = parse(
                protocol_events(cell, detector_mode), cell=cell, detector_mode=detector_mode
            )
            assert valid
            result = run.pending_run("main", cell, compare=True, detector_mode=detector_mode)
            result.update(status="completed", child_reaped=True, rows=rows)
            runs.append(result)
    # This unit isolates main-pass acceptance; the real CLI always supplies all
    # eight resource recipes and four controls through its verified inventory.
    report = run.build_report(CASES, EXPECTATIONS, FREEZE, runs, False, {}, compare=True)
    assert report["measurement_checks_passed"] and report["contract_checks_passed"]
    assert report["summary"]["expected_errors"] == 39
    bad = copy.deepcopy(runs)
    row = next(row for item in bad for row in item["rows"] if row["action"] == "error")
    row["contract_match"] = False
    report = run.build_report(CASES, EXPECTATIONS, FREEZE, bad, False, {}, compare=True)
    assert not report["measurement_checks_passed"] and not report["contract_checks_passed"]


def test_resource_interface_and_detector_mode_are_independent():
    schedule = run.comparison_inventory(CASES, RESOURCES, CONTROLS)["resource_workers"]
    assert len(schedule) == 16 and {row["detector_mode"] for row in schedule} == set(contract.MODES)
    assert all(row["interfaces"] == ["direct", "guard"] for row in schedule)
    recipe = RESOURCES[3]
    assert contract.resource_expectation(recipe, "direct", "default")["action"] == "allow"
    assert contract.resource_expectation(recipe, "direct", "enabled")["action"] == "error"


@pytest.mark.parametrize("detector_mode", contract.MODES)
@pytest.mark.parametrize("cell", [0, 4, 11])
def test_native_comparison_child_has_exact_policy_attribution(detector_mode, cell):
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    result = run.measure(
        cell,
        CASES,
        EXPECTATIONS,
        time.perf_counter() + 20,
        sdk_version,
        sdk_sha,
        compare=True,
        detector_mode=detector_mode,
        runtime_sha=run.execution_fingerprint(compare=True),
    )
    assert result["status"] == "completed" and result["child_reaped"]
    assert len(result["rows"]) == 48
    assert all(
        row["detector_mode"] == detector_mode and row["contract_match"] for row in result["rows"]
    )


@pytest.mark.parametrize("detector_mode", contract.MODES)
@pytest.mark.parametrize("cell", range(8))
def test_direct_guard_resource_comparison_matches_exact_frozen_contract(detector_mode, cell):
    for interface in ("direct", "guard"):
        row = run.observe_resource(RESOURCES[cell], interface, detector_mode)
        assert row["mode"] == interface and row["contract_match"] and row["privacy_ok"]


def test_exhausted_comparison_budget_retains_full_missing_inventory(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "TOTAL_SECONDS", 0)
    monkeypatch.setattr(run, "load_comparison_record", lambda *_args: {})
    monkeypatch.setattr(run, "git_identity", lambda: {})
    monkeypatch.setattr(
        run.subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("No child may start")
    )
    target = tmp_path / "empty-comparison"
    assert run.main(["--compare", "--report-dir", str(target)]) == 1
    report = json.loads((target / "results.json").read_text())
    assert report["summary"]["observations"] == 0
    assert report["summary"]["incomplete_observations"] == 1152
    assert report["resource_summary"]["incomplete_observations"] == 32
    assert report["control_summary"]["incomplete_observations"] == 4
    assert len(report["runs"]) == 44


def test_windows_comparison_command_retains_venv_and_explicit_policy(monkeypatch):
    monkeypatch.setattr(run.sys, "platform", "win32")
    command, environment = run.child_command("main", 0, compare=True, detector_mode="enabled")
    assert command[0] == sys._base_executable
    assert environment["__PYVENV_LAUNCHER__"] == sys.executable
    assert command[-3:] == ["--compare", "--detector-mode", "enabled"]
