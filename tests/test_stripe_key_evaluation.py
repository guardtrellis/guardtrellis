"""Frozen Stripe development evidence, representation contracts and bounded execution."""

import ast
import copy
import json
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from evaluation.stripe_keys import assets, contract, run
from guardtrellis import Action, Finding, Guard, PIIScanner, Result, SecretScanner, Stage

CASES, EXPECTATIONS, RESOURCES, CONTROLS, FREEZE = assets.load_frozen()
BY_ID = {case["id"]: case for case in CASES}
CANARY = "NeverIncludeThisPrivateStripePayload84"


def guard(profile):
    scanners = [SecretScanner(action=Action.REDACT if profile == "secret_redact" else Action.BLOCK)]
    if profile == "handoff":
        scanners.append(PIIScanner())
    return Guard(retrieval_scanners=scanners, max_chars=contract.MAX_INPUT_CHARS)


def observed(case_id, profile="secret_block", representation="plain", **kwargs):
    return run.observe(
        BY_ID[case_id],
        EXPECTATIONS[case_id, profile, representation, "default"],
        guard(profile).scan,
        **kwargs,
    )


def events(cell=0):
    profile = run.CELLS[cell][0]
    scanner = guard(profile)
    output = [
        {
            "event": "row",
            "row": run.observe(
                case,
                EXPECTATIONS[case["id"], profile, representation, "default"],
                scanner.scan,
            ),
        }
        for case, representation in run.cell_cases(CASES, cell)
    ]
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    output.insert(
        0,
        {
            "event": "identity",
            "sdk_version": sdk_version,
            "sdk_sha256": sdk_sha,
            "runtime_sha256": run.execution_fingerprint(),
        },
    )
    output.append(
        {
            "event": "complete",
            "count": 48,
            "limits": {
                key: None
                for key in ("cpu_seconds", "address_space_bytes", "core_bytes", "output_file_bytes")
            },
            "resources": {"process_cpu_ms": 0.0, "peak_rss_bytes": None},
            "sdk_version": sdk_version,
            "sdk_sha256": sdk_sha,
            "runtime_sha256": run.execution_fingerprint(),
        }
    )
    return output


def encoded(stream):
    return b"".join((json.dumps(event) + "\n").encode() for event in stream)


def parse(stream, cell=0):
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    return run.read_protocol(encoded(stream), CASES, EXPECTATIONS, cell, sdk_version, sdk_sha)


def test_frozen_inventory_keeps_future_predictions_separate_from_observations():
    assert assets.digest((assets.HERE / "freeze_v1.json").read_bytes()) == assets.FREEZE_SHA256
    assert len(CASES) == 48 and len(EXPECTATIONS) == 1152
    assert len(RESOURCES) == 8
    assert [case["id"] for case in CASES] == [f"S{i:02}" for i in range(1, 49)]
    assert set(contract.PROFILES) == {"secret_block", "secret_redact", "handoff"}
    assert set(contract.REPRESENTATIONS) == {"plain", "json_literal", "json_escaped", "decoded"}
    assert set(contract.MODES) == {"default", "enabled"}
    assert len(run.inventory(CASES, EXPECTATIONS)) == 576
    assert all(len(run.cell_cases(CASES, index)) == 48 for index in range(12))
    assert len(run.CELLS) == 12


def test_frozen_loader_uses_no_sdk_or_shadow_detector():
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "from evaluation.stripe_keys import assets; assets.load_frozen(); "
        "assert 'guardtrellis' not in sys.modules"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code, str(run.ROOT)], capture_output=True, timeout=10
    )
    assert completed.returncode == 0 and not completed.stdout and not completed.stderr
    tree = ast.parse((assets.HERE / "contract.py").read_text())
    imports = [
        node.module if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in (node.names if isinstance(node, ast.Import) else [None])
    ]
    assert not any(name and name.startswith("guardtrellis") for name in imports)
    runner = ast.parse(Path(run.__file__).read_text())
    for node in ast.walk(runner):
        if isinstance(node, ast.Call) and (
            isinstance(node.func, ast.Name)
            and node.func.id == "SecretScanner"
            or isinstance(node.func, ast.Attribute)
            and node.func.attr == "SecretScanner"
        ):
            assert all(keyword.arg != "stripe_keys" for keyword in node.keywords)


@pytest.mark.parametrize(
    "name",
    [
        "corpus_v1.jsonl",
        "expectations_v1.json",
        "resource_cases_v1.json",
        "harness_controls_v1.jsonl",
        "PROTOCOL_v1.md",
        "contract.py",
        "freeze_v1.json",
    ],
)
def test_frozen_asset_tampering_is_rejected(tmp_path, name):
    for source in [*FREEZE["files"], "freeze_v1.json"]:
        (tmp_path / source).write_bytes((assets.HERE / source).read_bytes())
    with (tmp_path / name).open("ab") as stream:
        stream.write(b"\n")
    with pytest.raises(ValueError) as caught:
        assets.load_frozen(tmp_path)
    assert CANARY not in str(caught.value)


@pytest.mark.parametrize(
    "wire",
    ['{"value":"a","value":"b"}', '{"value":NaN}', '{"value":1}', '{"other":"a"}', '"a"'],
)
def test_fixed_decoding_rejects_ambiguous_or_wrong_shape_inputs(wire):
    with pytest.raises(ValueError):
        contract.decode_value(wire)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_representation_projection_preserves_exact_desired_intervals(case):
    assert len(case["text"]) <= 1024
    assert contract.decode_value(contract.wire(case["text"])) == case["text"]
    assert contract.decode_value(contract.wire(case["text"], True)) == case["text"]
    original_spans = contract.represented(case, "plain")[1]
    for representation in contract.REPRESENTATIONS:
        text, spans = contract.represented(case, representation)
        assert len(text) <= 8192
        for (start, end), (left, right) in zip(spans, original_spans, strict=True):
            original = case["text"][left:right]
            fragment = (
                "".join(map(contract.escaped_character, original))
                if representation == "json_escaped"
                else json.dumps(original, ensure_ascii=True)[1:-1]
                if representation == "json_literal"
                else original
            )
            assert text[start:end] == fragment
        for profile in contract.PROFILES:
            for mode in contract.MODES:
                assert EXPECTATIONS[case["id"], profile, representation, mode] == (
                    contract.expectation(case, profile, representation, mode)
                )


def test_raw_unicode_json_is_a_no_decoding_control_for_both_modes():
    for case in CASES:
        for profile in contract.PROFILES:
            for mode in contract.MODES:
                expected = EXPECTATIONS[case["id"], profile, "json_escaped", mode]["contract"]
                assert expected["primary"] == [] and expected["action"] == "allow"


def test_json_escaping_changes_authored_contracts_instead_of_copying_plain_eligibility():
    differences = [
        case
        for case in CASES
        if EXPECTATIONS[case["id"], "secret_block", "plain", "enabled"]["contract"]["action"]
        != EXPECTATIONS[case["id"], "secret_block", "json_literal", "enabled"]["contract"]["action"]
    ]
    assert any('"' in case["text"] for case in differences)
    assert any("\n" in case["text"] for case in differences)
    assert any(
        EXPECTATIONS[case["id"], "secret_block", "plain", "enabled"]["contract"]["action"]
        == "block"
        and EXPECTATIONS[case["id"], "secret_block", "json_literal", "enabled"]["contract"][
            "action"
        ]
        == "error"
        for case in differences
    )


def test_baseline_has_no_stripe_primary_signal_even_when_incidental_secrets_block():
    incidental = []
    for case in CASES:
        expected = EXPECTATIONS[case["id"], "secret_block", "plain", "default"]["contract"]
        assert expected["primary"] == []
        if expected["action"] == "block":
            incidental.append(case["id"])
    assert incidental
    row = observed(incidental[0])
    assert row["primary"] == [] and row["incidental"] and row["contract_match"]
    assert row["action"] == "block" and row["consumer_calls"] == 0


def test_error_is_not_a_true_positive_or_a_silent_missing_observation():
    case = next(case for case in CASES if case["label"] == "sensitive")
    row = run.observe(
        case,
        EXPECTATIONS[case["id"], "secret_block", "plain", "default"],
        lambda *_args, **_kwargs: Result(Action.ERROR, Stage.RETRIEVAL, None),
    )
    row.update(label=case["label"], family=case["family"], profile="secret_block")
    summary = run.summarize([row], run.inventory(CASES, EXPECTATIONS))
    assert summary["errors"] == 1 and summary["tp"] == summary["fn"] == 0
    assert summary["observations"] == 1 and summary["incomplete_observations"] == 575


def test_corrupted_checked_delivery_is_detected_without_copying_payload():
    def corrupt(_result, consumer):
        consumer(CANARY)

    row = observed("S01", delivery=corrupt)
    assert not row["delivery_integrity"] and not row["comparisons"]["delivery"]
    assert CANARY not in json.dumps(row)


def test_payload_in_diagnostics_is_flagged_without_copying_payload(monkeypatch):
    monkeypatch.setattr(Result, "diagnostics", lambda self: {"raw": CANARY})
    case = copy.deepcopy(BY_ID["S01"])
    case["privacy_markers"] = [*case["privacy_markers"], CANARY]
    row = run.observe(
        case,
        EXPECTATIONS[case["id"], "secret_block", "plain", "default"],
        guard("secret_block").scan,
    )
    assert not row["privacy_ok"] and CANARY not in json.dumps(row)


@pytest.mark.parametrize(
    "mutation",
    ["unknown_field", "id", "accepted", "comparison", "contract", "duplicate", "runtime", "nan"],
)
def test_worker_protocol_rejects_corruption_and_retains_valid_prefix(mutation):
    stream = events()
    target = stream[2]["row"]
    if mutation == "unknown_field":
        target[CANARY] = CANARY
    elif mutation == "id":
        target["id"] = CANARY
    elif mutation == "accepted":
        target["accepted"] = not target["accepted"]
    elif mutation == "comparison":
        target["comparisons"]["action"] = not target["comparisons"]["action"]
    elif mutation == "contract":
        target["contract_match"] = not target["contract_match"]
    elif mutation == "duplicate":
        stream.insert(2, copy.deepcopy(stream[1]))
    elif mutation == "runtime":
        stream[-1]["sdk_sha256"] = "0" * 64
    else:
        stream[-1]["resources"]["process_cpu_ms"] = float("nan")
    rows, _, valid = parse(stream)
    assert not valid
    assert len(rows) == 0 if mutation == "runtime" else 1 <= len(rows) <= 48
    assert CANARY not in json.dumps(rows)


def test_truncated_oversized_duplicate_and_missing_completion_do_not_pass():
    stream = events()
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    raw = encoded(stream)
    for payload in (
        raw[:-2],
        encoded(stream[:-1]),
        raw + encoded([stream[-1]]),
        raw + b"x" * 65537,
    ):
        rows, _, valid = run.read_protocol(payload, CASES, EXPECTATIONS, 0, sdk_version, sdk_sha)
        assert not valid and len(rows) == 48


def fake_process(monkeypatch, raw, *, interrupt=False, stderr=b"", stalled=False):
    state = {}

    class Process:
        returncode = None

        def __init__(self, args, **kwargs):
            state.update(args=args, directory=Path(kwargs["cwd"]), env=kwargs["env"])
            kwargs["stdout"].write(raw)
            kwargs["stdout"].flush()
            kwargs["stderr"].write(stderr)
            kwargs["stderr"].flush()
            if interrupt:
                signal.raise_signal(signal.SIGINT)
            if not stalled and not interrupt:
                self.returncode = 0

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            raise subprocess.TimeoutExpired("fixed worker", timeout)

    def reap(process):
        assert state["directory"].exists()
        process.returncode = -9 if stalled or interrupt else 0
        state["reaped"] = True

    monkeypatch.setattr(run.subprocess, "Popen", Process)
    monkeypatch.setattr(run.limits, "kill_and_reap", reap)
    return state


def test_post_launch_interrupt_reaps_before_temporary_directory_cleanup(monkeypatch):
    state = fake_process(monkeypatch, encoded(events()[:2]), interrupt=True)
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    previous_handler = signal.getsignal(signal.SIGINT)
    result = run.measure(0, CASES, EXPECTATIONS, time.perf_counter() + 10, sdk_version, sdk_sha)
    assert result["status"] == "interrupted" and result["child_reaped"]
    assert len(result["rows"]) == 1 and state["reaped"] and not state["directory"].exists()
    assert signal.getsignal(signal.SIGINT) == previous_handler


def test_timeout_retains_completed_prefix_and_reaps_before_cleanup(monkeypatch):
    state = fake_process(monkeypatch, encoded(events()[:2]), stalled=True)
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    clock = iter(range(0, 1000, 6))
    monkeypatch.setattr(run.time, "perf_counter", lambda: next(clock))
    result = run.measure(0, CASES, EXPECTATIONS, 100, sdk_version, sdk_sha)
    assert result["status"] == "wall_timeout" and result["child_reaped"]
    assert len(result["rows"]) == 1 and state["reaped"] and not state["directory"].exists()


def test_worker_stderr_cannot_leak_into_report(monkeypatch):
    fake_process(monkeypatch, encoded(events()), stderr=CANARY.encode())
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    result = run.measure(0, CASES, EXPECTATIONS, time.perf_counter() + 10, sdk_version, sdk_sha)
    assert result["status"] == "protocol_error" and result["stderr_bytes"] == len(CANARY)
    assert CANARY not in json.dumps(result)


def test_windows_launcher_preserves_venv_without_inheriting_host_environment(monkeypatch):
    state = fake_process(monkeypatch, encoded(events()))
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    monkeypatch.setattr(run.sys, "platform", "win32")
    result = run.measure(0, CASES, EXPECTATIONS, time.perf_counter() + 10, sdk_version, sdk_sha)
    assert result["status"] == "completed"
    assert state["args"][0] == sys._base_executable
    assert state["env"]["__PYVENV_LAUNCHER__"] == sys.executable
    assert "HOME" not in state["env"] and "PYTEST_CURRENT_TEST" not in state["env"]


@pytest.mark.parametrize("cell", range(12))
def test_native_child_keeps_all_observations_and_reaps(cell):
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    result = run.measure(cell, CASES, EXPECTATIONS, time.perf_counter() + 20, sdk_version, sdk_sha)
    assert result["status"] == "completed", result["status"]
    assert result["child_reaped"] and result["stderr_bytes"] == 0
    assert 0 < result["stdout_bytes"] <= 65536 and len(result["rows"]) == 48
    assert all(
        row["delivery_integrity"] and row["privacy_ok"] and row["contract_match"]
        for row in result["rows"]
    )


def test_exhausted_deadline_preserves_missing_observations_without_launching(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "TOTAL_SECONDS", 0)
    monkeypatch.setattr(
        run.subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("No child should start")
    )
    target = tmp_path / "incomplete"
    assert run.main(["--report-dir", str(target)]) == 1
    report = json.loads((target / "results.json").read_text())
    assert report["summary"]["observations"] == 0
    assert report["summary"]["incomplete_observations"] == 576
    assert all(item["status"] == "not_started" for item in report["runs"])
    assert all(
        item["resources"] == {"process_cpu_ms": None, "peak_rss_bytes": None}
        and all(value is None for value in item["limits"].values())
        for item in report["runs"]
    )


def test_preparation_interrupt_has_static_error_surface(monkeypatch, tmp_path, capsys):
    def interrupted(*_args):
        raise KeyboardInterrupt

    monkeypatch.setattr(run.assets, "load_frozen", interrupted)
    assert run.main(["--report-dir", str(tmp_path / "unused")]) == 130
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == "Evaluation interrupted.\n"


def test_benign_intent_and_future_shape_false_positive_are_frozen_separately():
    matching_controls = [
        case
        for case in CASES
        if case["label"] == "benign"
        and EXPECTATIONS[case["id"], "secret_block", "plain", "enabled"]["contract"]["primary"]
    ]
    assert matching_controls
    for case in matching_controls:
        expected = EXPECTATIONS[case["id"], "secret_block", "plain", "enabled"]
        assert expected["desired"]["action"] == "allow"
        assert expected["contract"]["action"] == "block"
        assert expected["contract"]["text"] is None


def test_invalid_finding_metadata_is_rejected_before_worker_serialization():
    def unsafe(text, **_kwargs):
        return Result(
            Action.ALLOW,
            Stage.RETRIEVAL,
            text,
            (Finding("secret_github_classic", 0, 4, scanner=CANARY),),
        )

    with pytest.raises(ValueError) as caught:
        run.observe(BY_ID["S01"], EXPECTATIONS["S01", "secret_block", "plain", "default"], unsafe)
    assert CANARY not in str(caught.value)


def test_rows_without_matching_start_identity_have_no_attributable_prefix():
    stream = events()
    rows, _, valid = parse(stream[1:])
    assert not valid and rows == []
    stream[0]["runtime_sha256"] = "0" * 64
    rows, _, valid = parse(stream)
    assert not valid and rows == []


@pytest.mark.parametrize("resource_index", range(8))
@pytest.mark.parametrize("interface", ["direct", "guard"])
def test_resource_observation_uses_current_default_contract(resource_index, interface):
    recipe = RESOURCES[resource_index]
    row = run.observe_resource(recipe, interface)
    expected = contract.resource_expectation(recipe, interface, "default")
    assert row["contract_match"] and row["privacy_ok"] and row["delivery_integrity"]
    assert row["finding_count"] == expected["finding_count"]
    if interface == "direct":
        assert row["consumer_calls"] is None and row["has_deliverable_text"] is None
    else:
        assert row["consumer_calls"] == expected["consumer_calls"]


@pytest.mark.parametrize("control_index", range(3))
def test_harness_controls_check_revision_offsets_and_ingress_withholding(control_index):
    row = run.observe_control(CONTROLS[control_index])
    assert row["contract_match"] and row["privacy_ok"] and row["delivery_integrity"]
    if control_index == 1:
        assert [finding["revision"] for finding in row["findings"]] == [0, 1]
        assert row["findings"] == CONTROLS[1]["expected"]["findings"]
    if control_index == 2:
        assert row["action"] == "error" and row["consumer_calls"] == 0


def test_failed_reaping_preserves_child_directory_and_reports_failure(monkeypatch):
    state = fake_process(monkeypatch, b"", stalled=True)
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    clock = iter(range(0, 1000, 6))
    monkeypatch.setattr(run.time, "perf_counter", lambda: next(clock))

    def failed_reap(_process):
        raise subprocess.TimeoutExpired("fixed cleanup", 5)

    monkeypatch.setattr(run.limits, "kill_and_reap", failed_reap)
    result = run.measure(0, CASES, EXPECTATIONS, 100, sdk_version, sdk_sha)
    try:
        assert result["status"] == "supervisor_error" and not result["child_reaped"]
        assert state["directory"].exists() and result["rows"] == []
        assert str(state["directory"]) not in json.dumps(result)
    finally:
        # The Process above is a fake, so no live process owns this retained directory.
        shutil.rmtree(state["directory"])


def test_cli_refuses_overwriting_existing_evidence_with_static_errors(tmp_path):
    target = tmp_path / CANARY
    target.mkdir()
    evidence = target / "results.json"
    evidence.write_text("retained evidence\n")
    completed = subprocess.run(
        [sys.executable, str(run.HERE), "--report-dir", str(target)],
        capture_output=True,
        timeout=10,
    )
    assert completed.returncode == 2 and not completed.stdout
    assert CANARY.encode() not in completed.stderr
    assert evidence.read_text() == "retained evidence\n"


def test_native_cleanup_control_requires_observed_timeout_and_reaping():
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    result = run.measure(
        3,
        CASES,
        EXPECTATIONS,
        time.perf_counter() + 20,
        sdk_version,
        sdk_sha,
        kind="control",
        controls=CONTROLS,
    )
    assert result["status"] == "completed" and result["child_reaped"]
    assert len(result["rows"]) == 1
    assert result["rows"][0]["status"] == "wall_timeout"
    assert result["rows"][0]["child_reaped"] and result["rows"][0]["contract_match"]
    assert result["resources"] == {"process_cpu_ms": None, "peak_rss_bytes": None}
    assert all(value is None for value in result["limits"].values())


def test_argument_parsing_interrupt_returns_static_130_without_traceback(monkeypatch, capsys):
    def interrupted(_self, *_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(run.Parser, "parse_args", interrupted)
    assert run.main(["--report-dir", CANARY]) == 130
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == "Evaluation interrupted.\n"
    assert CANARY not in captured.err
