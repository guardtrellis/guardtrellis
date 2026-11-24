"""Frozen Stripe disclosure-shape baseline; no Stripe SDK option or detector implementation."""

from __future__ import annotations

import argparse
import io
import json
import logging
import math
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from importlib.metadata import version
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

if __package__:
    from . import assets, contract
else:
    import assets
    import contract

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
SPEC = spec_from_file_location("stripe_evaluation_limits", ROOT / "evaluation/measure_resources.py")
assert SPEC is not None and SPEC.loader is not None
limits = module_from_spec(SPEC)
sys.modules[SPEC.name] = limits
SPEC.loader.exec_module(limits)
CELLS = tuple((profile, chunk) for profile in contract.PROFILES for chunk in range(4))
WALL_SECONDS = 10
TOTAL_SECONDS = 180
MAX_REPORT_BYTES = 2 * 1024 * 1024
ACTIONS = {"allow", "warn", "redact", "block", "error"}
PRIMARY_CODES = {
    "secret_stripe_secret_test",
    "secret_stripe_secret_live",
    "secret_stripe_restricted_test",
    "secret_stripe_restricted_live",
}
CODES = PRIMARY_CODES | {
    "pii_email",
    "pii_phone",
    "pii_ssn",
    "secret_github_classic",
    "secret_github_fine_grained",
    "secret_aws_access_key_id",
    "secret_private_key",
    "scanner_error",
    "invalid_check",
    "text_limit_exceeded",
    "finding_limit_exceeded",
    "connection_string_limit_exceeded",
    "connection_string_configuration_error",
    "stripe_key_limit_exceeded",
}
COMPARISONS = {"action", "spans", "text", "delivery"}
CONTRACT_COMPARISONS = {"action", "findings", "text", "delivery"}
ROW_FIELDS = {
    "id",
    "representation",
    "action",
    "accepted",
    "primary",
    "incidental",
    "findings",
    "consumer_calls",
    "comparisons",
    "contract_comparisons",
    "delivery_integrity",
    "contract_match",
    "privacy_ok",
}
DENSE_FIELDS = {
    "id",
    "mode",
    "input_chars",
    "action",
    "accepted",
    "finding_count",
    "finding_codes",
    "error_spanless",
    "has_deliverable_text",
    "consumer_calls",
    "delivery_integrity",
    "contract_match",
    "contract_comparisons",
    "privacy_ok",
    "operation_ms",
}
CONTROL_FIELDS = {
    "id",
    "action",
    "accepted",
    "findings",
    "consumer_calls",
    "contract_comparisons",
    "contract_match",
    "privacy_ok",
    "delivery_integrity",
}
CLEANUP_FIELDS = {
    "id",
    "status",
    "child_reaped",
    "contract_match",
    "privacy_ok",
    "delivery_integrity",
}


def sdk_fingerprint():
    import guardtrellis

    files = {
        f"src/guardtrellis/{path.name}": assets.digest(path.read_bytes())
        for path in sorted(Path(guardtrellis.__file__).parent.glob("*.py"))
    }
    return (
        guardtrellis.__version__,
        files,
        assets.digest(json.dumps(files, sort_keys=True).encode()),
    )


def execution_fingerprint():
    _, sdk_files, _ = sdk_fingerprint()
    files = [
        HERE,
        HERE.with_name("assets.py"),
        HERE.with_name("freeze_v1.json"),
        ROOT / "evaluation/measure_resources.py",
        ROOT / "uv.lock",
        ROOT / "pyproject.toml",
    ]
    files.extend(HERE.parent / name for name in assets.FROZEN_FILES)
    identity = {
        "sdk": sdk_files,
        "sources": {
            path.relative_to(ROOT).as_posix(): assets.digest(path.read_bytes()) for path in files
        },
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "machine": platform.machine(),
        "dependencies": {
            name: version(name)
            for name in (
                "guardtrellis",
                "jsonschema",
                "referencing",
                "attrs",
                "rpds-py",
                "jsonschema-specifications",
            )
        },
    }
    return assets.digest(json.dumps(identity, sort_keys=True).encode())


def cell_cases(cases, cell):
    _, chunk = CELLS[cell]
    return [
        (case, representation)
        for case in cases[chunk * 12 : (chunk + 1) * 12]
        for representation in contract.REPRESENTATIONS
    ]


def contains_marker(value, markers):
    surface = str(value)
    return any(
        spelling in surface
        for marker in markers
        for spelling in (
            marker,
            repr(marker),
            json.dumps(marker),
            json.dumps(marker)[1:-1],
            "".join(map(contract.escaped_character, marker)),
        )
    )


def deliver(result, consumer):
    if result.accepted:
        consumer(result.require_text())


def finding_records(result, text):
    records = []
    for finding in result.findings:
        if finding.code not in CODES:
            raise ValueError("Unknown static finding code")
        record = {
            "code": finding.code,
            "start": finding.start,
            "end": finding.end,
            "scanner": finding.scanner,
            "scanner_index": finding.scanner_index,
            "revision": finding.revision,
        }
        if not valid_finding(record, text, allow_direct=True):
            raise ValueError("Invalid static finding metadata")
        records.append(record)
    return records


def observe(case, expected, scan, delivery=deliver):
    from guardtrellis import Action, Rejected, Stage

    text = contract.represented(case, expected["representation"])[0]
    consumed = []
    log = io.StringIO()
    handler = logging.StreamHandler(log)
    logger = logging.getLogger()
    logger.addHandler(handler)
    try:
        result = scan(text, stage=Stage.RETRIEVAL)
        findings = finding_records(result, text)
        if len(findings) > 8:
            raise ValueError("Finding protocol limit")
        primary = [
            [f["code"], f["start"], f["end"]] for f in findings if f["code"] in PRIMARY_CODES
        ]
        incidental = [
            [f["code"], f["start"], f["end"]] for f in findings if f["code"] not in PRIMARY_CODES
        ]
        safe = not any(
            contains_marker(surface, case["privacy_markers"])
            for surface in (repr(result), result.diagnostics(), log.getvalue())
        )
        delivery(result, consumed.append)
        checked = result.require_text() if result.accepted else None
        integrity = consumed == ([checked] if result.accepted else [])
        if result.accepted:
            integrity &= type(checked) is str and len(checked) <= contract.MAX_INPUT_CHARS
            integrity &= result.action != Action.ALLOW or checked == text
        else:
            integrity &= result.text is None
            try:
                result.require_text()
            except Rejected as error:
                safe &= not contains_marker(str(error), case["privacy_markers"])
            else:
                integrity = False
        desired, target = expected["desired"], expected["contract"]
        comparisons = {
            "action": result.action.value == desired["action"],
            "spans": [[p[1], p[2]] for p in primary] == desired["spans"],
            "text": checked == desired["text"],
            "delivery": consumed == ([desired["text"]] if desired["consumer_calls"] else []),
        }
        contract_comparisons = {
            "action": result.action.value == target["action"],
            "findings": findings == target["findings"],
            "text": checked == target["text"],
            "delivery": consumed == ([target["text"]] if target["consumer_calls"] else []),
        }
        return {
            "id": case["id"],
            "representation": expected["representation"],
            "action": result.action.value,
            "accepted": result.accepted,
            "primary": primary,
            "incidental": incidental,
            "findings": findings,
            "consumer_calls": len(consumed),
            "comparisons": comparisons,
            "contract_comparisons": contract_comparisons,
            "delivery_integrity": bool(integrity),
            "contract_match": all(contract_comparisons.values()),
            "privacy_ok": bool(safe),
        }
    finally:
        logger.removeHandler(handler)


def contract_matches(row, expected):
    target = expected["contract"]
    return (
        row["action"] == target["action"]
        and row["findings"] == target["findings"]
        and all(row["contract_comparisons"].values())
    )


def guard_for(profile):
    from guardtrellis import Action, Guard, PIIScanner, SecretScanner

    if profile not in contract.PROFILES:
        raise ValueError("Unknown fixed profile")
    scanners = [SecretScanner(action=Action.REDACT if profile == "secret_redact" else Action.BLOCK)]
    if profile == "handoff":
        scanners.append(PIIScanner())
    return Guard(retrieval_scanners=scanners, max_chars=contract.MAX_INPUT_CHARS)


def emit(event):
    print(json.dumps(event, ensure_ascii=True, separators=(",", ":")), flush=True)


def complete(count, applied):
    sdk_version, _, sdk_sha = sdk_fingerprint()
    emit(
        {
            "event": "complete",
            "count": count,
            "limits": applied,
            "resources": limits.resource_usage(),
            "sdk_version": sdk_version,
            "sdk_sha256": sdk_sha,
            "runtime_sha256": execution_fingerprint(),
        }
    )


def worker(kind, cell):
    cases, expectations, resources, controls, _ = assets.load_frozen()
    sdk_version, _, sdk_sha = sdk_fingerprint()
    emit(
        {
            "event": "identity",
            "sdk_version": sdk_version,
            "sdk_sha256": sdk_sha,
            "runtime_sha256": execution_fingerprint(),
        }
    )
    applied = limits.apply_limits(2, 512)
    if kind == "main":
        profile, _ = CELLS[cell]
        scan = guard_for(profile).scan
        for case, representation in cell_cases(cases, cell):
            expected = expectations[case["id"], profile, representation, "default"]
            row = observe(case, expected, scan)
            emit({"event": "row", "row": validate_row(row, case, expected)})
        complete(48, applied)
    elif kind == "resource":
        case = resources[cell]
        for mode in ("direct", "guard"):
            emit({"event": "row", "row": observe_resource(case, mode)})
        complete(2, applied)
    elif kind == "control":
        if controls[cell]["kind"] == "supervised_cleanup":
            emit({"event": "cleanup_ready"})
            time.sleep(controls[cell]["expected"]["sleep_seconds"])
            return
        emit({"event": "row", "row": observe_control(controls[cell])})
        complete(1, applied)
    else:
        raise ValueError("Unknown worker kind")


def valid_finding(finding, text, *, allow_direct=False):
    return (
        type(finding) is dict
        and finding.keys() == {"code", "start", "end", "scanner", "scanner_index", "revision"}
        and finding["code"] in CODES
        and finding["scanner"]
        in (("secrets", "pii", "guard", "") if allow_direct else ("secrets", "pii", "guard"))
        and type(finding["scanner_index"]) is int
        and -1 <= finding["scanner_index"] <= 1
        and type(finding["revision"]) is int
        and 0 <= finding["revision"] <= 2
        and (
            finding["start"] is None
            and finding["end"] is None
            or type(finding["start"]) is int
            and type(finding["end"]) is int
            and 0 <= finding["start"] < finding["end"] <= len(text)
        )
    )


def validate_row(row, case, expected):
    text = contract.represented(case, expected["representation"])[0]
    if (
        type(row) is not dict
        or row.keys() != ROW_FIELDS
        or row["id"] != case["id"]
        or row["representation"] != expected["representation"]
        or row["action"] not in ACTIONS
        or any(
            type(row[k]) is not bool
            for k in ("accepted", "delivery_integrity", "contract_match", "privacy_ok")
        )
        or row["accepted"] != (row["action"] in ("allow", "warn", "redact"))
        or type(row["consumer_calls"]) is not int
        or not 0 <= row["consumer_calls"] <= 8
        or type(row["findings"]) is not list
        or len(row["findings"]) > 8
        or not all(valid_finding(item, text) for item in row["findings"])
        or type(row["primary"]) is not list
        or type(row["incidental"]) is not list
        or any(type(row[name]) is not dict for name in ("comparisons", "contract_comparisons"))
        or row["comparisons"].keys() != COMPARISONS
        or row["contract_comparisons"].keys() != CONTRACT_COMPARISONS
        or any(
            type(v) is not bool
            for name in ("comparisons", "contract_comparisons")
            for v in row[name].values()
        )
    ):
        raise ValueError("Invalid row protocol")
    primary = [
        [f["code"], f["start"], f["end"]] for f in row["findings"] if f["code"] in PRIMARY_CODES
    ]
    incidental = [
        [f["code"], f["start"], f["end"]] for f in row["findings"] if f["code"] not in PRIMARY_CODES
    ]
    target, desired = expected["contract"], expected["desired"]
    if (
        row["primary"] != primary
        or row["incidental"] != incidental
        or row["contract_comparisons"]["action"] != (row["action"] == target["action"])
        or row["contract_comparisons"]["findings"] != (row["findings"] == target["findings"])
        or row["comparisons"]["action"] != (row["action"] == desired["action"])
        or row["comparisons"]["spans"] != ([[p[1], p[2]] for p in primary] == desired["spans"])
        or row["contract_match"] != contract_matches(row, expected)
        or row["delivery_integrity"]
        and row["consumer_calls"] != int(row["accepted"])
        or contains_marker(row, case["privacy_markers"])
    ):
        raise ValueError("Contradictory or unsafe row protocol")
    return row


def observe_resource(case, mode):
    from guardtrellis import Action, Guard, Rejected, SecretScanner, Stage

    if mode not in ("direct", "guard"):
        raise ValueError("Invalid resource interface")
    text = contract.resource_text(case)
    target = contract.resource_expectation(case, mode)
    scanner = SecretScanner()
    guard = Guard(input_scanners=[scanner], max_chars=200_000)
    started = time.perf_counter()
    result = scanner.scan(text, stage=Stage.INPUT) if mode == "direct" else guard.scan(text)
    elapsed = (time.perf_counter() - started) * 1000
    findings = finding_records(result, text)
    accepted = result.action in (Action.ALLOW, Action.WARN, Action.REDACT)
    consumed, checked = [], None
    safe = not contains_marker(repr(result), [text])
    if mode == "guard":
        safe &= not contains_marker(result.diagnostics(), [text])
        deliver(result, consumed.append)
        checked = result.require_text() if accepted else None
        integrity = consumed == ([checked] if accepted else [])
        if not accepted:
            integrity &= result.text is None
            try:
                result.require_text()
            except Rejected:
                pass
            else:
                integrity = False
    else:
        integrity = not result.edits
    comparisons = {
        "action": result.action.value == target["action"],
        "findings": findings == target["findings"],
        # A direct Check has no checked-text or delivery API.
        "text": True if mode == "direct" else checked == target["text"],
        "delivery": True
        if mode == "direct"
        else consumed == ([target["text"]] if target["consumer_calls"] else []),
    }
    row = {
        "id": case["id"],
        "mode": mode,
        "input_chars": len(text),
        "action": result.action.value,
        "accepted": accepted,
        "finding_count": len(findings),
        "finding_codes": sorted({f["code"] for f in findings}),
        "error_spanless": result.action != Action.ERROR
        or all(f["start"] is None and f["end"] is None for f in findings),
        "has_deliverable_text": None if mode == "direct" else result.text is not None,
        "consumer_calls": None if mode == "direct" else len(consumed),
        "delivery_integrity": bool(integrity),
        "contract_comparisons": comparisons,
        "contract_match": all(comparisons.values()),
        "privacy_ok": bool(safe),
        "operation_ms": elapsed,
    }
    return validate_resource(row, case, mode)


def validate_resource(row, case, mode):
    target = contract.resource_expectation(case, mode)
    if (
        type(row) is not dict
        or row.keys() != DENSE_FIELDS
        or row["id"] != case["id"]
        or row["mode"] != mode
        or type(row["input_chars"]) is not int
        or row["input_chars"] != len(contract.resource_text(case))
        or row["action"] not in ACTIONS
        or any(
            type(row[k]) is not bool
            for k in (
                "accepted",
                "error_spanless",
                "delivery_integrity",
                "contract_match",
                "privacy_ok",
            )
        )
        or row["accepted"] != (row["action"] in ("allow", "warn", "redact"))
        or type(row["finding_count"]) is not int
        or not 0 <= row["finding_count"] <= 256
        or type(row["finding_codes"]) is not list
        or any(type(code) is not str or code not in CODES for code in row["finding_codes"])
        or row["finding_codes"] != sorted(set(row["finding_codes"]))
        or not finite(row["operation_ms"])
        or type(row["contract_comparisons"]) is not dict
        or row["contract_comparisons"].keys() != CONTRACT_COMPARISONS
        or any(type(v) is not bool for v in row["contract_comparisons"].values())
        or (
            mode == "direct"
            and (row["has_deliverable_text"] is not None or row["consumer_calls"] is not None)
        )
        or (
            mode == "guard"
            and (
                type(row["has_deliverable_text"]) is not bool
                or type(row["consumer_calls"]) is not int
                or not 0 <= row["consumer_calls"] <= 8
            )
        )
    ):
        raise ValueError("Invalid resource protocol")
    if (
        row["contract_comparisons"]["action"] != (row["action"] == target["action"])
        or row["contract_match"] != all(row["contract_comparisons"].values())
        or row["contract_match"]
        and (
            row["finding_count"] != target["finding_count"]
            or row["finding_codes"] != target["codes"]
            or not row["error_spanless"]
        )
        or mode == "guard"
        and row["delivery_integrity"]
        and (
            row["consumer_calls"] != int(row["accepted"])
            or row["has_deliverable_text"] != row["accepted"]
        )
    ):
        raise ValueError("Contradictory resource protocol")
    return row


def observe_control(case):
    from guardtrellis import Action, Guard, PIIScanner, SecretScanner, Stage

    scanners = []
    for name in case["scanners"]:
        if name == "pii_redact":
            scanners.append(PIIScanner())
        elif name in ("secret_redact", "secret_block"):
            scanners.append(
                SecretScanner(action=Action.REDACT if name == "secret_redact" else Action.BLOCK)
            )
        else:
            raise ValueError("Unknown fixed control scanner")
    text, target = contract.control_text(case), contract.control_expectation(case)
    result = Guard(retrieval_scanners=scanners, max_chars=case["max_chars"]).scan(
        text, stage=Stage.RETRIEVAL
    )
    findings = finding_records(result, text)
    consumed = []
    deliver(result, consumed.append)
    checked = result.require_text() if result.accepted else None
    comparisons = {
        "action": result.action.value == target["action"],
        "findings": findings == target["findings"],
        "text": checked == target["text"],
        "delivery": consumed == ([target["text"]] if target["consumer_calls"] else []),
    }
    row = {
        "id": case["id"],
        "action": result.action.value,
        "accepted": result.accepted,
        "findings": findings,
        "consumer_calls": len(consumed),
        "contract_comparisons": comparisons,
        "contract_match": all(comparisons.values()),
        "privacy_ok": not any(
            contains_marker(surface, case["privacy_markers"])
            for surface in (repr(result), result.diagnostics())
        ),
        "delivery_integrity": consumed == ([checked] if result.accepted else [])
        and (result.accepted or result.text is None),
    }
    return validate_control(row, case)


def validate_control(row, case):
    target = contract.control_expectation(case)
    if case["kind"] == "supervised_cleanup":
        if (
            type(row) is not dict
            or row.keys() != CLEANUP_FIELDS
            or row["id"] != case["id"]
            or row["status"] != target["measurement_status"]
            or row["child_reaped"] is not True
            or any(
                row[key] is not True
                for key in ("contract_match", "privacy_ok", "delivery_integrity")
            )
        ):
            raise ValueError("Invalid cleanup control protocol")
        return row
    if (
        type(row) is not dict
        or row.keys() != CONTROL_FIELDS
        or row["id"] != case["id"]
        or row["action"] not in ACTIONS
        or any(
            type(row[k]) is not bool
            for k in ("accepted", "contract_match", "privacy_ok", "delivery_integrity")
        )
        or row["accepted"] != (row["action"] in ("allow", "warn", "redact"))
        or type(row["consumer_calls"]) is not int
        or not 0 <= row["consumer_calls"] <= 8
        or type(row["findings"]) is not list
        or len(row["findings"]) > 8
        or not all(valid_finding(f, contract.control_text(case)) for f in row["findings"])
        or type(row["contract_comparisons"]) is not dict
        or row["contract_comparisons"].keys() != CONTRACT_COMPARISONS
        or any(type(v) is not bool for v in row["contract_comparisons"].values())
    ):
        raise ValueError("Invalid control protocol")
    if (
        row["contract_comparisons"]["action"] != (row["action"] == target["action"])
        or row["contract_comparisons"]["findings"] != (row["findings"] == target["findings"])
        or row["contract_match"] != all(row["contract_comparisons"].values())
        or row["delivery_integrity"]
        and row["consumer_calls"] != int(row["accepted"])
        or contains_marker(row, case["privacy_markers"])
    ):
        raise ValueError("Contradictory or unsafe control protocol")
    return row


def finite(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def validate_end(event, count, sdk_version, sdk_sha, runtime_sha=None):
    runtime_sha = runtime_sha or execution_fingerprint()
    if (
        type(event) is not dict
        or event.keys()
        != {"event", "count", "limits", "resources", "sdk_version", "sdk_sha256", "runtime_sha256"}
        or type(event["count"]) is not int
        or event["count"] != count
        or event["sdk_version"] != sdk_version
        or event["sdk_sha256"] != sdk_sha
        or event["runtime_sha256"] != runtime_sha
        or type(event["limits"]) is not dict
        or event["limits"].keys()
        != {"cpu_seconds", "address_space_bytes", "core_bytes", "output_file_bytes"}
        or any(v is not None and not finite(v) for v in event["limits"].values())
        or type(event["resources"]) is not dict
        or event["resources"].keys() != {"process_cpu_ms", "peak_rss_bytes"}
        or not finite(event["resources"]["process_cpu_ms"])
        or event["resources"]["peak_rss_bytes"] is not None
        and not finite(event["resources"]["peak_rss_bytes"])
    ):
        raise ValueError("Invalid completion protocol")


def expected_count(kind):
    return {"main": 48, "resource": 2, "control": 1}[kind]


def read_protocol(
    raw,
    cases,
    expectations,
    cell,
    sdk_version,
    sdk_sha,
    *,
    kind="main",
    resources=None,
    controls=None,
    runtime_sha=None,
):
    rows, end = [], None
    valid = len(raw) <= limits.MAX_CAPTURE_BYTES
    identity_seen = False
    cleanup_ready_seen = False
    cleanup = kind == "control" and controls[cell]["kind"] == "supervised_cleanup"
    runtime_sha = runtime_sha or execution_fingerprint()
    count = expected_count(kind)
    try:
        for line in raw.splitlines(keepends=True):
            if not line.endswith(b"\n") or end is not None:
                raise ValueError
            event = contract.strict_json(line)
            if type(event) is not dict:
                raise ValueError
            if event.get("event") == "identity" and not identity_seen and not rows:
                if (
                    event.keys() != {"event", "sdk_version", "sdk_sha256", "runtime_sha256"}
                    or event["sdk_version"] != sdk_version
                    or event["sdk_sha256"] != sdk_sha
                    or event["runtime_sha256"] != runtime_sha
                ):
                    raise ValueError
                identity_seen = True
            elif not identity_seen:
                raise ValueError
            elif cleanup and event == {"event": "cleanup_ready"} and not cleanup_ready_seen:
                cleanup_ready_seen = True
            elif event.keys() == {"event", "row"} and event["event"] == "row":
                if len(rows) >= count:
                    raise ValueError
                if kind == "main":
                    case, representation = cell_cases(cases, cell)[len(rows)]
                    profile, _ = CELLS[cell]
                    expected = expectations[case["id"], profile, representation, "default"]
                    observed = validate_row(event["row"], case, expected)
                    rows.append(
                        {
                            **observed,
                            "family": case["family"],
                            "group": case["group"],
                            "label": case["label"],
                            "profile": profile,
                            "contract_scope": expected["contract"]["scope"],
                        }
                    )
                elif kind == "resource":
                    rows.append(
                        validate_resource(
                            event["row"], resources[cell], ("direct", "guard")[len(rows)]
                        )
                    )
                else:
                    rows.append(validate_control(event["row"], controls[cell]))
            elif event.get("event") == "complete" and len(rows) == count:
                if (
                    event.get("sdk_version") != sdk_version
                    or event.get("sdk_sha256") != sdk_sha
                    or event.get("runtime_sha256") != runtime_sha
                ):
                    rows.clear()
                    raise ValueError
                validate_end(event, count, sdk_version, sdk_sha, runtime_sha)
                end = event
            else:
                raise ValueError
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        valid = False
    if cleanup:
        return (
            rows,
            end,
            valid and identity_seen and cleanup_ready_seen and not rows and end is None,
        )
    return rows, end, valid and end is not None


def child_command(kind, cell):
    executable, environment = sys.executable, limits.child_environment()
    if sys.platform == "win32":
        executable = sys._base_executable
        environment["__PYVENV_LAUNCHER__"] = sys.executable
    return [executable, str(HERE), "--worker", kind, "--cell", str(cell)], environment


def pending_run(kind, cell):
    return {
        "kind": kind,
        "cell": cell,
        "expected_observations": expected_count(kind),
        "status": "not_started",
        "child_reaped": False,
        "rows": [],
        "resources": {"process_cpu_ms": None, "peak_rss_bytes": None},
        "limits": {
            key: None
            for key in ("cpu_seconds", "address_space_bytes", "core_bytes", "output_file_bytes")
        },
    }


def measure(
    cell,
    cases,
    expectations,
    deadline,
    sdk_version,
    sdk_sha,
    *,
    kind="main",
    resources=None,
    controls=None,
    runtime_sha=None,
):
    row = pending_run(kind, cell)
    if time.perf_counter() >= deadline:
        return row
    command, environment = child_command(kind, cell)
    runtime_sha = runtime_sha or execution_fingerprint()
    cleanup = kind == "control" and controls[cell]["kind"] == "supervised_cleanup"
    cleanup_armed = False
    interrupted, handlers, process = False, {}, None

    def defer_interrupt(_signum, _frame):
        nonlocal interrupted
        interrupted = True

    started = time.perf_counter()
    directory = None
    try:
        for item in (signal.SIGINT, signal.SIGTERM):
            handlers[item] = signal.signal(item, defer_interrupt)
        directory = tempfile.mkdtemp(prefix="guardtrellis-stripe-")
        try:
            output_path, error_path = (
                Path(directory) / "stdout.jsonl",
                Path(directory) / "stderr.txt",
            )
            with output_path.open("w+b") as output, error_path.open("w+b") as errors:
                try:
                    process = subprocess.Popen(
                        command,
                        stdin=subprocess.DEVNULL,
                        stdout=output,
                        stderr=errors,
                        cwd=directory,
                        env=environment,
                        start_new_session=os.name == "posix",
                    )
                    row["status"] = "worker_error"
                    stop = min(deadline, started + WALL_SECONDS)
                    while process.poll() is None:
                        if interrupted:
                            row["status"] = "interrupted"
                            break
                        if time.perf_counter() >= stop:
                            row["status"] = "wall_timeout"
                            break
                        if any(
                            os.fstat(s.fileno()).st_size > limits.MAX_CAPTURE_BYTES
                            for s in (output, errors)
                        ):
                            row["status"] = "output_limit"
                            break
                        if cleanup and not cleanup_armed:
                            # Read via a separate file handle: seeking the inherited stdout
                            # descriptor while the child writes would race its file offset.
                            with output_path.open("rb") as captured_stream:
                                prefix = captured_stream.read(limits.MAX_CAPTURE_BYTES + 1)
                            _, _, ready = read_protocol(
                                prefix,
                                cases,
                                expectations,
                                cell,
                                sdk_version,
                                sdk_sha,
                                kind=kind,
                                resources=resources,
                                controls=controls,
                                runtime_sha=runtime_sha,
                            )
                            if ready:
                                cleanup_armed = True
                                stop = min(
                                    stop,
                                    time.perf_counter()
                                    + controls[cell]["expected"]["wall_seconds"],
                                )
                        try:
                            process.wait(timeout=min(0.05, max(0.001, stop - time.perf_counter())))
                        except subprocess.TimeoutExpired:
                            pass
                except KeyboardInterrupt:
                    interrupted = True
                    row["status"] = "interrupted"
                finally:
                    if process is not None:
                        limits.kill_and_reap(process)
                        row["child_reaped"] = process.poll() is not None
                output.seek(0)
                captured = output.read(limits.MAX_CAPTURE_BYTES + 1)
                errors.seek(0, os.SEEK_END)
                row.update(
                    stderr_bytes=errors.tell(),
                    stdout_bytes=len(captured),
                    returncode=None if process is None else process.returncode,
                )
                rows, end, valid = read_protocol(
                    captured,
                    cases,
                    expectations,
                    cell,
                    sdk_version,
                    sdk_sha,
                    kind=kind,
                    resources=resources,
                    controls=controls,
                    runtime_sha=runtime_sha,
                )
                row["rows"] = rows
                if end is not None:
                    row.update(resources=end["resources"], limits=end["limits"])
                if (
                    cleanup
                    and not interrupted
                    and valid
                    and cleanup_armed
                    and row["status"] == "wall_timeout"
                    and row["child_reaped"]
                    and row["stderr_bytes"] == 0
                ):
                    row["observed_status"] = "wall_timeout"
                    row["rows"] = [
                        validate_control(
                            {
                                "id": controls[cell]["id"],
                                "status": "wall_timeout",
                                "child_reaped": True,
                                "contract_match": True,
                                "privacy_ok": True,
                                "delivery_integrity": True,
                            },
                            controls[cell],
                        )
                    ]
                    row["status"] = "completed"
                if interrupted:
                    row["status"] = "interrupted"
                elif row["status"] == "worker_error":
                    row["status"] = (
                        "completed"
                        if valid and row["returncode"] == 0 and row["stderr_bytes"] == 0
                        else "protocol_error"
                    )
        finally:
            # An unreaped process can still own this directory on Windows. Preserve it
            # when cleanup fails; never delete its workspace while it may be running.
            if directory is not None and (process is None or process.poll() is not None):
                shutil.rmtree(directory)
    except (OSError, ValueError, subprocess.SubprocessError):
        row["status"] = "interrupted" if interrupted else "supervisor_error"
    finally:
        for item, handler in handlers.items():
            signal.signal(item, handler)
    row["wall_ms"] = (time.perf_counter() - started) * 1000
    return row


def ratio(a, b):
    return a / b if b else None


def summarize(rows, inventory):
    counts = Counter()
    for row in rows:
        if row["action"] == "error":
            counts["errors"] += 1
        else:
            positive, predicted = row["label"] == "sensitive", bool(row["primary"])
            counts[
                ("tp" if predicted else "fn") if positive else ("fp" if predicted else "tn")
            ] += 1
    return {
        "base_scenarios": len({row["id"] for row in inventory}),
        "expected_observations": len(inventory),
        "observations": len(rows),
        "incomplete_observations": len(inventory) - len(rows),
        "positive_expected": sum(row["label"] == "sensitive" for row in inventory),
        "negative_expected": sum(row["label"] == "benign" for row in inventory),
        "positive_observed": sum(row["label"] == "sensitive" for row in rows),
        "negative_observed": sum(row["label"] == "benign" for row in rows),
        "positive_errors": sum(
            row["label"] == "sensitive" and row["action"] == "error" for row in rows
        ),
        "negative_errors": sum(
            row["label"] == "benign" and row["action"] == "error" for row in rows
        ),
        **{key: counts[key] for key in ("tp", "fp", "tn", "fn", "errors")},
        "precision": ratio(counts["tp"], counts["tp"] + counts["fp"]),
        "recall": ratio(counts["tp"], counts["tp"] + counts["fn"]),
        "actions": {
            action: sum(row["action"] == action for row in rows) for action in sorted(ACTIONS)
        },
        "desired_exact": sum(all(row["comparisons"].values()) for row in rows),
        "desired_mismatches": {
            key: sum(not row["comparisons"][key] for row in rows) for key in sorted(COMPARISONS)
        },
        "contract_failures": sum(not row["contract_match"] for row in rows),
        "incidental_finding_observations": sum(bool(row["incidental"]) for row in rows),
        "delivery_integrity_failures": sum(not row["delivery_integrity"] for row in rows),
        "privacy_failures": sum(not row["privacy_ok"] for row in rows),
    }


def inventory(cases, expectations):
    return [
        {
            "id": case["id"],
            "family": case["family"],
            "group": case["group"],
            "label": case["label"],
            "profile": profile,
            "representation": representation,
            "scope": expectations[case["id"], profile, representation, "default"]["contract"][
                "scope"
            ],
        }
        for case in cases
        for profile in contract.PROFILES
        for representation in contract.REPRESENTATIONS
    ]


def metadata(freeze):
    sdk_version, sdk_files, sdk_sha = sdk_fingerprint()
    files = [
        HERE,
        HERE.with_name("assets.py"),
        HERE.with_name("freeze_v1.json"),
        *[HERE.with_name(name) for name in freeze["files"]],
        ROOT / "evaluation/measure_resources.py",
        ROOT / "uv.lock",
        ROOT / "pyproject.toml",
    ]
    return {
        "created_utc": datetime.now(UTC).isoformat(),
        "sdk_version": sdk_version,
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "logical_cpu_count": os.cpu_count(),
        "source_base_commit": freeze["source_base_commit"],
        "worktree_evidence": "source hashes identify local edits; base commit excludes this patch",
        "freeze_sha256": assets.FREEZE_SHA256,
        "freeze_receipt": assets.RECEIPT,
        "sdk_sha256": sdk_files,
        "worker_sdk_fingerprint": sdk_sha,
        "worker_runtime_fingerprint": execution_fingerprint(),
        "dependencies": {
            name: version(name)
            for name in (
                "guardtrellis",
                "jsonschema",
                "referencing",
                "attrs",
                "rpds-py",
                "jsonschema-specifications",
            )
        },
        "source_sha256": {
            path.relative_to(ROOT).as_posix(): assets.digest(path.read_bytes()) for path in files
        },
        "authorship": "AI-assisted implementation-aware synthetic development cases",
        "case_review": (
            "author self-review and internal assistant review; not external independent review"
        ),
        "independent_case_review": False,
        "license": "Apache-2.0",
        "usage": "development",
    }


def build_report(
    cases, expectations, freeze, runs, interrupted, provenance, *, resources=None, controls=None
):
    resources, controls = resources or [], controls or []
    rows = [row for run in runs if run["kind"] == "main" for row in run["rows"]]
    resource_rows = [row for run in runs if run["kind"] == "resource" for row in run["rows"]]
    control_rows = [row for run in runs if run["kind"] == "control" for row in run["rows"]]
    planned = inventory(cases, expectations)
    summary = summarize(rows, planned)
    measurement_ok = (
        not interrupted
        and len(runs) == len(CELLS) + len(resources) + len(controls)
        and all(
            run["status"] == "completed"
            and run["child_reaped"]
            and len(run["rows"]) == run["expected_observations"]
            for run in runs
        )
    )
    measurement_ok &= not any(
        summary[key]
        for key in (
            "errors",
            "incomplete_observations",
            "delivery_integrity_failures",
            "privacy_failures",
        )
    )
    ancillary_ok = all(
        row["contract_match"] and row["privacy_ok"] and row["delivery_integrity"]
        for row in resource_rows + control_rows
    )
    report = {
        "schema_version": 1,
        "dataset_version": contract.VERSION,
        "metadata": provenance,
        "configuration": {
            "stage": "retrieval",
            "mode": "default_only_baseline",
            "profiles": list(contract.PROFILES),
            "representations": list(contract.REPRESENTATIONS),
            "child_wall_seconds": WALL_SECONDS,
            "parent_observation_seconds_per_pass": TOTAL_SECONDS,
            "cleanup_allowance_seconds": 5,
            "max_capture_bytes": limits.MAX_CAPTURE_BYTES,
            "max_input_chars": contract.MAX_INPUT_CHARS,
            "expected_children": len(CELLS) + len(resources) + len(controls),
        },
        "interrupted": interrupted,
        "measurement_checks_passed": bool(measurement_ok),
        "contract_checks_passed": bool(
            measurement_ok and ancillary_ok and not summary["contract_failures"]
        ),
        "summary": summary,
        "resource_summary": {
            "expected_observations": len(resources) * 2,
            "observations": len(resource_rows),
            "incomplete_observations": len(resources) * 2 - len(resource_rows),
            "contract_failures": sum(not row["contract_match"] for row in resource_rows),
        },
        "control_summary": {
            "expected_observations": len(controls),
            "observations": len(control_rows),
            "incomplete_observations": len(controls) - len(control_rows),
            "contract_failures": sum(not row["contract_match"] for row in control_rows),
        },
        "runs": [
            {
                **{key: value for key, value in run.items() if key != "rows"},
                "observed_observations": len(run["rows"]),
            }
            for run in runs
        ],
        "rows": rows,
        "resource_rows": resource_rows,
        "control_rows": control_rows,
    }
    for dimension, values in (
        ("profile", contract.PROFILES),
        ("family", sorted({case["family"] for case in cases})),
        ("representation", contract.REPRESENTATIONS),
        ("group", ("length", "benign", "mixed")),
    ):
        report[f"by_{dimension}"] = {
            value: summarize(
                [row for row in rows if row[dimension] == value],
                [row for row in planned if row[dimension] == value],
            )
            for value in values
        }
    report["by_family_profile_representation"] = {
        f"{family}/{profile}/{representation}": summarize(
            [
                row
                for row in rows
                if (row["family"], row["profile"], row["representation"])
                == (family, profile, representation)
            ],
            [
                row
                for row in planned
                if (row["family"], row["profile"], row["representation"])
                == (family, profile, representation)
            ],
        )
        for family in sorted({case["family"] for case in cases})
        for profile in contract.PROFILES
        for representation in contract.REPRESENTATIONS
    }
    return report


def render(report):
    lines = [
        "# Stripe account-key disclosure baseline, v1",
        "",
        "48 public, AI-assisted synthetic development scenarios; "
        "no independent external case review.",
        "576 correlated baseline observations, not 576 independent examples. "
        "SDK defaults unchanged.",
        "No enabled Stripe observations, live credentials, provider requests "
        "or efficacy guarantees.",
        "",
        f"SDK {report['metadata']['sdk_version']}; {report['metadata']['system']} / "
        f"Python {report['metadata']['python']}.",
        f"Pre-observation [freeze receipt]({assets.RECEIPT}); SHA-256 `{assets.FREEZE_SHA256}`.",
        "",
        f"Measurement integrity: **{report['measurement_checks_passed']}**; "
        f"contract checks: **{report['contract_checks_passed']}**.",
        "",
        "| Profile | Observed / expected | TP / FP / TN / FN | "
        "ERROR | Desired exact | Contract failures |",
        "| --- | ---: | --- | ---: | ---: | ---: | ---: |",
    ]
    for name, row in report["by_profile"].items():
        lines.append(
            f"| {name} | {row['observations']}/{row['expected_observations']} | "
            f"{row['tp']} / {row['fp']} / {row['tn']} / {row['fn']} | "
            f"{row['errors']} | {row['desired_exact']} | {row['contract_failures']} |"
        )
    lines += [
        "",
        "Stripe primary findings alone determine TP/FP/TN/FN. "
        "Incidental legacy/PII findings are separate.",
        "ERROR and incomplete work are never true positives; undefined rates are null.",
        "Desired complete protection and exact checked delivery remain separate "
        "from current-contract conformance.",
        "Resource probes and harness controls are outside primary accuracy denominators.",
        "CPU/RSS describe whole children, not SDK performance or capacity. "
        "Local evidence is not native CI.",
        "",
        "## Retained desired mismatches",
        "",
    ]
    for row in report["rows"]:
        failed = [key for key, value in row["comparisons"].items() if not value]
        if failed or not row["contract_match"] or row["action"] == "error":
            lines.append(
                f"- `{row['id']}` / {row['profile']} / {row['representation']}: "
                f"{row['action']}; desired mismatches {', '.join(failed) or 'none'}; "
                f"contract {row['contract_match']}."
            )
    return "\n".join(lines) + "\n"


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "Invalid evaluation arguments.\n")


def write_report(report, directory):
    encoded = json.dumps(report, indent=2) + "\n"
    rendered = render(report)
    if len(encoded.encode()) + len(rendered.encode()) > MAX_REPORT_BYTES:
        raise ValueError("Report size exceeded")
    (directory / "results.json").write_text(encoded, encoding="utf-8")
    (directory / "REPORT.md").write_text(rendered, encoding="utf-8")


def main(argv=None):
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--report-dir", type=Path)
    parser.add_argument("--worker", choices=("main", "resource", "control"), help=argparse.SUPPRESS)
    parser.add_argument("--cell", type=int, help=argparse.SUPPRESS)
    try:
        args = parser.parse_args(argv)
    except KeyboardInterrupt:
        print("Evaluation interrupted.", file=sys.stderr)
        return 130
    if args.worker is not None:
        if args.report_dir is not None or args.cell is None or args.cell < 0:
            parser.error("Invalid worker arguments")
        try:
            worker(args.worker, args.cell)
            return 0
        except KeyboardInterrupt:
            emit({"event": "error", "code": "interrupted"})
            return 130
        except Exception:
            emit({"event": "error", "code": "worker_error"})
            return 1
    if args.cell is not None or args.report_dir is None or args.report_dir.exists():
        parser.error("A new report directory is required")
    try:
        cases, expectations, resources, controls, freeze = assets.load_frozen()
        provenance = metadata(freeze)
    except KeyboardInterrupt:
        print("Evaluation interrupted.", file=sys.stderr)
        return 130
    except Exception:
        print("Cannot prepare frozen evaluation.", file=sys.stderr)
        return 1
    interrupted, handlers, runs = [False], {}, []

    def defer_interrupt(_signum, _frame):
        interrupted[0] = True

    try:
        for item in (signal.SIGINT, signal.SIGTERM):
            handlers[item] = signal.signal(item, defer_interrupt)
        for kind, count in (
            ("main", len(CELLS)),
            ("resource", len(resources)),
            ("control", len(controls)),
        ):
            deadline = time.perf_counter() + TOTAL_SECONDS
            for cell in range(count):
                if interrupted[0]:
                    result = pending_run(kind, cell)
                else:
                    result = measure(
                        cell,
                        cases,
                        expectations,
                        deadline,
                        provenance["sdk_version"],
                        provenance["worker_sdk_fingerprint"],
                        kind=kind,
                        resources=resources,
                        controls=controls,
                        runtime_sha=provenance["worker_runtime_fingerprint"],
                    )
                runs.append(result)
                interrupted[0] |= result["status"] == "interrupted"
        report = build_report(
            cases,
            expectations,
            freeze,
            runs,
            interrupted[0],
            provenance,
            resources=resources,
            controls=controls,
        )
        args.report_dir.mkdir(parents=True)
        write_report(report, args.report_dir)
        if interrupted[0] and not report["interrupted"]:
            report.update(
                interrupted=True, measurement_checks_passed=False, contract_checks_passed=False
            )
            write_report(report, args.report_dir)
    except (OSError, ValueError):
        print("Cannot complete frozen evaluation.", file=sys.stderr)
        return 1
    finally:
        for item, handler in handlers.items():
            signal.signal(item, handler)
    print(
        json.dumps(
            {
                "measurement_checks_passed": report["measurement_checks_passed"],
                "contract_checks_passed": report["contract_checks_passed"],
                "summary": report["summary"],
                "resource_summary": report["resource_summary"],
                "control_summary": report["control_summary"],
            },
            sort_keys=True,
        )
    )
    return 130 if report["interrupted"] else int(not report["contract_checks_passed"])


if __name__ == "__main__":
    raise SystemExit(main())
