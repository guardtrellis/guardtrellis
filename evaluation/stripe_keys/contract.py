"""Authored Stripe evaluation projections; standard library only, never a detector."""

from __future__ import annotations

import json

VERSION = "stripe-keys-v1"
PROFILES = ("secret_block", "secret_redact", "handoff")
REPRESENTATIONS = ("plain", "json_literal", "json_escaped", "decoded")
MODES = ("default", "enabled")
MAX_INPUT_CHARS = 8_192
MAX_VALUE_CHARS = 1_024
PREFIXES = ("sk_test_", "sk_live_", "rk_test_", "rk_live_")
STRIPE_CODES = (
    "secret_stripe_secret_test",
    "secret_stripe_secret_live",
    "secret_stripe_restricted_test",
    "secret_stripe_restricted_live",
)
SCOPES = (
    "disabled_control",
    "supported",
    "excluded_grammar",
    "processing_limit",
    "contextual_shape",
    "benign_control",
    "raw_escaped_control",
    "unsupported",
)
CODES = (
    *STRIPE_CODES,
    "secret_github_classic",
    "secret_private_key",
    "pii_email",
    "stripe_key_limit_exceeded",
    "finding_limit_exceeded",
    "text_limit_exceeded",
)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("Non-finite JSON value")


def strict_json(raw):
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)


def valid_text(value, maximum=MAX_INPUT_CHARS):
    return (
        type(value) is str
        and 0 < len(value) <= maximum
        and not any(0xD800 <= ord(char) <= 0xDFFF for char in value)
    )


def escaped_character(char):
    encoded = char.encode("utf-16-be")
    return "".join(r"\u" + encoded[index : index + 2].hex() for index in range(0, len(encoded), 2))


def wire(text, escaped=False):
    content = (
        "".join(map(escaped_character, text))
        if escaped
        else json.dumps(text, ensure_ascii=True)[1:-1]
    )
    return '{"value":"' + content + '"}'


def decode_value(serialized):
    if not valid_text(serialized):
        raise ValueError("Invalid fixed-field input")
    value = strict_json(serialized)
    if (
        type(value) is not dict
        or value.keys() != {"value"}
        or not valid_text(value["value"], MAX_VALUE_CHARS)
    ):
        raise ValueError("Invalid fixed-field value")
    return value["value"]


def represented(case, representation, spans=None):
    if representation not in REPRESENTATIONS:
        raise ValueError("Invalid representation")
    text = case["text"]
    spans = case["targets"] if spans is None else spans
    if representation in ("plain", "decoded"):
        if representation == "decoded":
            left, right = decode_value(wire(text)), decode_value(wire(text, True))
            if left != right or left != text:
                raise ValueError("Unequal decoded values")
            text = left
        return text, [list(span) for span in spans]
    escaped = representation == "json_escaped"
    offsets = [len('{"value":"')]
    for char in text:
        offsets.append(
            offsets[-1]
            + len(escaped_character(char) if escaped else json.dumps(char, ensure_ascii=True)[1:-1])
        )
    return wire(text, escaped), [[offsets[a], offsets[b]] for a, b in spans]


def _replace(text, intervals, replacement):
    merged = []
    for start, end in sorted(intervals):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    for start, end in reversed(merged):
        text = text[:start] + replacement + text[end:]
    return text


def _finding(code, start, end, scanner="secrets", index=0, revision=0):
    return {
        "code": code,
        "start": start,
        "end": end,
        "scanner": scanner,
        "scanner_index": index,
        "revision": revision,
    }


def _decision(text, secret, pii, error, profile):
    """Apply fixed profile actions to authored findings; never search candidate text."""
    findings = []
    if error:
        return {
            "action": "error",
            "findings": [_finding(error, None, None)],
            "text": None,
            "consumer_calls": 0,
        }
    secret = sorted(secret, key=lambda row: (row[1], row[2], row[0]))
    findings.extend(_finding(*item) for item in secret)
    if secret and profile != "secret_redact":
        return {"action": "block", "findings": findings, "text": None, "consumer_calls": 0}
    action = "redact" if secret else "allow"
    if secret:
        text = _replace(text, [[a, b] for _, a, b in secret], "[SECRET]")
    if profile == "handoff" and pii:
        findings.extend(_finding(*item, scanner="pii", index=1) for item in pii)
        text = _replace(text, [[a, b] for _, a, b in pii], "[PII]")
        action = "redact"
    return {"action": action, "findings": findings, "text": text, "consumer_calls": 1}


def desired(case, profile, representation):
    text, spans = represented(case, representation)
    other = represented(case, representation, case["desired_other"])[1]
    pii = represented(case, representation, case["desired_pii"])[1]
    secret_spans = sorted(spans + other)
    if secret_spans:
        action = "redact" if profile == "secret_redact" else "block"
        text = _replace(text, secret_spans, "[SECRET]") if action == "redact" else None
    elif profile == "handoff" and pii:
        action, text = "redact", _replace(text, pii, "[PII]")
    else:
        action = "allow"
    return {
        "action": action,
        "text": text,
        "spans": spans,
        "consumer_calls": int(action in ("allow", "redact")),
    }


def expectation(case, profile, representation, mode="default"):
    if profile not in PROFILES or mode not in MODES or representation not in REPRESENTATIONS:
        raise ValueError("Invalid observation coordinate")
    text, _ = represented(case, representation)
    spec = case["contracts"][mode][representation]
    primary = spec["primary"]
    result = _decision(text, primary + spec["legacy"], spec["pii"], spec["error"], profile)
    result.update(
        scope=spec["scope"],
        eligible=True,
        stripe_eligibility=spec["stripe_eligibility"],
        primary=primary,
        incidental=[
            [item["code"], item["start"], item["end"]]
            for item in result["findings"]
            if item["code"] not in STRIPE_CODES
        ],
    )
    return {
        "id": case["id"],
        "profile": profile,
        "representation": representation,
        "mode": mode,
        "desired": desired(case, profile, representation),
        "contract": result,
    }


def project_all(cases):
    return [
        expectation(case, profile, representation, mode)
        for case in cases
        for profile in PROFILES
        for representation in REPRESENTATIONS
        for mode in MODES
    ]


def _spans_valid(spans, text, maximum=16):
    return (
        type(spans) is list
        and len(spans) <= maximum
        and all(
            type(span) is list
            and len(span) == 2
            and all(type(index) is int for index in span)
            and 0 <= span[0] < span[1] <= len(text)
            for span in spans
        )
        and all(a[1] <= b[0] for a, b in zip(spans, spans[1:], strict=False))
    )


def _records_valid(records, text, codes):
    return (
        type(records) is list
        and len(records) <= 16
        and all(
            type(row) is list
            and len(row) == 3
            and row[0] in codes
            and _spans_valid([row[1:]], text)
            for row in records
        )
    )


def validate_cases(raw):
    try:
        cases = [strict_json(line) for line in raw.decode("utf-8").splitlines()]
        if [case["id"] for case in cases] != [f"S{i:02}" for i in range(1, 49)]:
            raise ValueError
        fields = {
            "id",
            "dataset_version",
            "group",
            "family",
            "label",
            "language",
            "text",
            "targets",
            "desired_other",
            "desired_pii",
            "source",
            "usage",
            "license",
            "review",
            "label_basis",
            "privacy_markers",
            "contracts",
        }
        for index, case in enumerate(cases):
            if (
                type(case) is not dict
                or case.keys() != fields
                or case["dataset_version"] != VERSION
                or case["group"]
                != ("length" if index < 24 else "benign" if index < 36 else "mixed")
                or case["family"] not in (*STRIPE_CODES, "publishable", "mixed", "none")
                or case["label"] not in ("sensitive", "benign")
                or case["language"] != "en"
                or case["source"] != "original_codex_assisted_synthetic"
                or case["usage"] != "development"
                or case["license"] != "Apache-2.0"
                or case["review"] != "author_self_review_and_internal_assistant_review"
                or not valid_text(case["text"], MAX_VALUE_CHARS)
                or not _spans_valid(case["targets"], case["text"])
                or not _spans_valid(case["desired_other"], case["text"])
                or not _spans_valid(case["desired_pii"], case["text"])
                or bool(case["targets"]) != (case["label"] == "sensitive")
                or type(case["label_basis"]) is not str
                or not 1 <= len(case["label_basis"]) <= 800
                or type(case["privacy_markers"]) is not list
                or not 1 <= len(case["privacy_markers"]) <= 20
                or not all(
                    valid_text(marker, MAX_VALUE_CHARS) and len(marker) >= 8
                    for marker in case["privacy_markers"]
                )
                or type(case["contracts"]) is not dict
                or case["contracts"].keys() != set(MODES)
            ):
                raise ValueError
            for mode in MODES:
                specs = case["contracts"][mode]
                if type(specs) is not dict or specs.keys() != set(REPRESENTATIONS):
                    raise ValueError
                for representation in REPRESENTATIONS:
                    text, _ = represented(case, representation)
                    spec = specs[representation]
                    if (
                        not valid_text(text)
                        or type(spec) is not dict
                        or spec.keys()
                        != {"scope", "stripe_eligibility", "primary", "legacy", "pii", "error"}
                        or spec["scope"] not in SCOPES
                        or spec["stripe_eligibility"]
                        not in ("match", "no_match", "processing_error", "raw_escaped", "disabled")
                        or not _records_valid(spec["primary"], text, STRIPE_CODES)
                        or not _records_valid(
                            spec["legacy"], text, ("secret_github_classic", "secret_private_key")
                        )
                        or not _records_valid(spec["pii"], text, ("pii_email",))
                        or spec["error"] not in (None, "stripe_key_limit_exceeded")
                        or (mode == "default" and (spec["primary"] or spec["error"]))
                        or (spec["error"] and (spec["primary"] or spec["legacy"] or spec["pii"]))
                        or (
                            representation == "json_escaped"
                            and (spec["primary"] or spec["legacy"] or spec["pii"] or spec["error"])
                        )
                    ):
                        raise ValueError
        return cases
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise ValueError("Invalid Stripe evaluation scenarios") from None


def resource_text(recipe):
    kind, amount = recipe["kind"], recipe["amount"]
    if kind == "input_chars":
        return "x" * amount
    if kind == "candidate_chars":
        return "sk_test_" + "Q" * (amount - 8)
    if kind == "malformed_attempts":
        return " ".join(["sk_test_"] * amount)
    if kind == "combined_findings":
        return " ".join(["ghp_" + "J" * 36] * amount + ["rk_live_" + "R" * 24])
    raise ValueError("Invalid resource recipe")


def resource_expectation(recipe, interface, mode="default"):
    if interface not in ("direct", "guard") or mode not in MODES:
        raise ValueError("Invalid resource observation")
    text = resource_text(recipe)
    spec = recipe["contracts"][mode]
    if spec["error"]:
        findings = [_finding(spec["error"], None, None)]
    else:
        findings = []
        if recipe["kind"] == "combined_findings":
            findings.extend(
                _finding("secret_github_classic", index * 41, index * 41 + 40)
                for index in range(recipe["amount"])
            )
        if spec["primary_count"]:
            start = recipe["amount"] * 41 if recipe["kind"] == "combined_findings" else 0
            end = len(text)
            code = (
                "secret_stripe_restricted_live"
                if recipe["kind"] == "combined_findings"
                else "secret_stripe_secret_test"
            )
            findings.append(_finding(code, start, end))
    if interface == "direct":
        for item in findings:
            item.update(scanner="", scanner_index=-1)
    action = spec["action"]
    return {
        "id": recipe["id"],
        "interface": interface,
        "mode": mode,
        "action": action,
        "findings": findings,
        "text": text if action == "allow" else None,
        "consumer_calls": int(action == "allow") if interface == "guard" else None,
        "primary_count": spec["primary_count"],
        "finding_count": len(findings),
        "codes": sorted(set(item["code"] for item in findings)),
    }


def validate_resources(raw):
    try:
        data = strict_json(raw)
        if type(data) is not dict:
            raise ValueError
        recipes = data["recipes"]
        if (
            data.keys() != {"schema_version", "dataset_version", "recipes"}
            or type(data["schema_version"]) is not int
            or data["schema_version"] != 1
            or data["dataset_version"] != VERSION
            or type(recipes) is not list
            or [recipe["id"] for recipe in recipes] != [f"R{i:02}" for i in range(1, 9)]
        ):
            raise ValueError
        inventory = list(
            zip(
                ("input_chars",) * 2
                + ("candidate_chars",) * 2
                + ("malformed_attempts",) * 2
                + ("combined_findings",) * 2,
                (100000, 100001, 255, 256, 256, 257, 255, 256),
                strict=True,
            )
        )
        for recipe, (kind, amount) in zip(recipes, inventory, strict=True):
            if (
                type(recipe) is not dict
                or recipe.keys() != {"id", "kind", "amount", "contracts"}
                or recipe["kind"] != kind
                or type(recipe["amount"]) is not int
                or recipe["amount"] != amount
                or type(recipe["contracts"]) is not dict
                or recipe["contracts"].keys() != set(MODES)
            ):
                raise ValueError
            for mode in MODES:
                spec = recipe["contracts"][mode]
                if (
                    type(spec) is not dict
                    or spec.keys() != {"action", "error", "primary_count"}
                    or spec["action"] not in ("allow", "block", "error")
                    or spec["error"]
                    not in (None, "stripe_key_limit_exceeded", "finding_limit_exceeded")
                    or type(spec["primary_count"]) is not int
                    or spec["primary_count"] not in (0, 1)
                    or bool(spec["error"]) != (spec["action"] == "error")
                ):
                    raise ValueError
        return recipes
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise ValueError("Invalid Stripe resource recipes") from None


def control_text(control):
    return control.get("text", "")


def control_expectation(control):
    return control["expected"]


def _control_result_valid(expected, text):
    if (
        expected.keys() != {"action", "findings", "text", "consumer_calls"}
        or expected["action"] not in ("redact", "error")
        or type(expected["findings"]) is not list
        or not 1 <= len(expected["findings"]) <= 4
        or type(expected["consumer_calls"]) is not int
        or expected["consumer_calls"] != int(expected["action"] == "redact")
        or (expected["text"] is not None and not valid_text(expected["text"]))
        or (expected["action"] == "error") != (expected["text"] is None)
    ):
        return False
    for finding in expected["findings"]:
        if (
            type(finding) is not dict
            or finding.keys() != {"code", "start", "end", "scanner", "scanner_index", "revision"}
            or finding["code"] not in CODES
            or finding["scanner"] not in ("secrets", "pii", "guard")
            or type(finding["scanner_index"]) is not int
            or finding["scanner_index"] not in (-1, 0, 1)
            or type(finding["revision"]) is not int
            or finding["revision"] not in (0, 1)
            or not (
                finding["start"] is None
                and finding["end"] is None
                or _spans_valid([[finding["start"], finding["end"]]], text)
            )
        ):
            return False
    return True


def validate_controls(raw):
    try:
        controls = [strict_json(line) for line in raw.decode("utf-8").splitlines()]
        if [control["id"] for control in controls] != [f"H{i:02}" for i in range(1, 5)]:
            raise ValueError
        for control, kind in zip(
            controls,
            ("legacy_unicode", "revision_chain", "guard_ingress", "supervised_cleanup"),
            strict=True,
        ):
            if (
                type(control) is not dict
                or control.keys()
                != {"id", "kind", "text", "max_chars", "scanners", "expected", "privacy_markers"}
                or control["kind"] != kind
                or type(control["max_chars"]) is not int
                or not 1 <= control["max_chars"] <= MAX_INPUT_CHARS
                or type(control["text"]) is not str
                or len(control["text"]) > MAX_VALUE_CHARS
                or type(control["scanners"]) is not list
                or type(control["expected"]) is not dict
                or type(control["privacy_markers"]) is not list
                or len(control["privacy_markers"]) > 4
                or not all(
                    valid_text(marker, MAX_VALUE_CHARS) and len(marker) >= 8
                    for marker in control["privacy_markers"]
                )
            ):
                raise ValueError
            if kind == "supervised_cleanup":
                if (
                    control["text"] != ""
                    or control["scanners"] != []
                    or control["expected"]
                    != {
                        "worker": "sleep",
                        "sleep_seconds": 60,
                        "wall_seconds": 0.1,
                        "measurement_status": "wall_timeout",
                        "child_reaped": True,
                    }
                ):
                    raise ValueError
            elif (
                not valid_text(control["text"], MAX_VALUE_CHARS)
                or not control["privacy_markers"]
                or control["scanners"]
                != {
                    "legacy_unicode": ["secret_redact"],
                    "revision_chain": ["pii_redact", "secret_redact"],
                    "guard_ingress": ["secret_block"],
                }[kind]
                or not _control_result_valid(control["expected"], control["text"])
            ):
                raise ValueError
        return controls
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise ValueError("Invalid Stripe harness controls") from None
