"""Verify pre-observation study assets without importing or observing the SDK."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

if __package__:
    from . import contract
else:
    import contract

HERE = Path(__file__).resolve().parent
FREEZE_SHA256 = "260c7743a6a45545266989087f0faad26d5cc3d3fd555516aa61ebd262728441"
RECEIPT = "https://github.com/guardtrellis/guardtrellis/issues/109#issuecomment-7130408959"
MAX_ASSET_BYTES = 4 * 1024 * 1024
FROZEN_FILES = (
    "PROTOCOL_v1.md",
    "contract.py",
    "corpus_v1.jsonl",
    "expectations_v1.json",
    "resource_cases_v1.json",
    "harness_controls_v1.jsonl",
    "sources_v1.json",
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_bounded(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_ASSET_BYTES + 1)
    if len(raw) > MAX_ASSET_BYTES:
        raise ValueError("Frozen asset exceeds size limit")
    return raw


def load_frozen(here=None):
    """Require the external receipt and exact pure authored expectations before scans."""
    root = HERE if here is None else Path(here)
    try:
        if not re.fullmatch(r"[0-9a-f]{64}", FREEZE_SHA256) or not re.fullmatch(
            r"https://github\.com/guardtrellis/guardtrellis/issues/109#issuecomment-[0-9]+",
            RECEIPT,
        ):
            raise ValueError
        raw = read_bounded(root / "freeze_v1.json")
        if digest(raw) != FREEZE_SHA256:
            raise ValueError
        manifest = contract.strict_json(raw.decode("utf-8"))
        if (
            type(manifest) is not dict
            or type(manifest.get("schema_version")) is not int
            or manifest["schema_version"] != 1
            or manifest.get("dataset_version") != contract.VERSION
            or manifest.get("phase") != "before_first_new_scenario_observation"
            or manifest.get("independent_case_review") is not False
            or manifest.get("research_scenarios") != 48
            or manifest.get("main_baseline_observations") != 576
            or manifest.get("resource_baseline_observations") != 16
            or type(manifest.get("files")) is not dict
            or set(manifest["files"]) != set(FROZEN_FILES)
        ):
            raise ValueError
        raw_assets = {}
        for name in FROZEN_FILES:
            expected_hash = manifest["files"][name]
            if type(expected_hash) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
                raise ValueError
            raw_assets[name] = read_bounded(root / name)
            if digest(raw_assets[name]) != expected_hash:
                raise ValueError
        cases = contract.validate_cases(raw_assets["corpus_v1.jsonl"])
        resources = contract.validate_resources(raw_assets["resource_cases_v1.json"])
        controls = contract.validate_controls(raw_assets["harness_controls_v1.jsonl"])
        expected = contract.strict_json(raw_assets["expectations_v1.json"].decode("utf-8"))
        if (
            type(expected) is not dict
            or set(expected) != {"schema_version", "dataset_version", "observations"}
            or type(expected["schema_version"]) is not int
            or expected["schema_version"] != 1
            or expected["dataset_version"] != contract.VERSION
            or expected["observations"] != contract.project_all(cases)
            or len(expected["observations"]) != 1152
            or len(resources) != 8
            or len(controls) != manifest.get("harness_controls")
        ):
            raise ValueError
        expectations = {
            (row["id"], row["profile"], row["representation"], row["mode"]): row
            for row in expected["observations"]
        }
        if len(expectations) != 1152:
            raise ValueError
        return cases, expectations, resources, controls, manifest
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        raise ValueError("Frozen Stripe study inputs or receipt are invalid") from None
