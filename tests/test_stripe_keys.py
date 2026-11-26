"""Opt-in Stripe disclosure shapes, bounded work and checked-result behavior."""

import json
from unittest.mock import Mock

import pytest

from guardtrellis import Action, Guard, PIIScanner, Rejected, SecretScanner, Stage
from guardtrellis import scanners as scanner_module
from guardtrellis.models import Finding

PREFIXES = (
    ("sk_test_", "secret_stripe_secret_test"),
    ("sk_live_", "secret_stripe_secret_live"),
    ("rk_test_", "secret_stripe_restricted_test"),
    ("rk_live_", "secret_stripe_restricted_live"),
)
ACTIONS = (Action.WARN, Action.REDACT, Action.BLOCK)
DELIMITERS = "\t\n\v\f\r \"'`()[]{}<>,;:=.!?&"
LEGACY = "ghp_" + "L" * 36
URI = "postgresql://app:FabricatedUnitPassword73@db.example.invalid/demo"
CANARY = "NeverDisclosePrivateStripeUnitPayload73"


def token(prefix="sk_test_", length=24):
    # Construct independent synthetic inputs; never import the frozen evaluation corpus.
    return prefix + "Q" * length


def configured(scanner, stage=Stage.INPUT, *, max_chars=100_000):
    return Guard(**{f"{stage.value}_scanners": [scanner]}, max_chars=max_chars)


def findings(check):
    return [(item.code, item.start, item.end) for item in check.findings]


def assert_error(check, code):
    assert check.action == Action.ERROR
    assert findings(check) == [(code, None, None)]
    assert check.edits == ()


@pytest.mark.parametrize("prefix,code", PREFIXES)
@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("stage", list(Stage))
def test_each_prefix_action_and_stage_has_complete_spans_and_checked_delivery(
    prefix, code, action, stage
):
    key = token(prefix)
    before, after = "🪴 unit: ", " ; public"
    text = before + key + after
    result = configured(SecretScanner(stripe_keys=True, action=action), stage).scan(
        text, stage=stage
    )
    assert result.action == action
    assert findings(result) == [(code, len(before), len(before) + len(key))]
    item = result.findings[0]
    assert (item.scanner, item.scanner_index, item.revision) == ("secrets", 0, 0)
    consumed = []
    if result.accepted:
        consumed.append(result.require_text())
        assert consumed == [before + "[SECRET]" + after if action == Action.REDACT else text]
    else:
        assert result.text is None
        with pytest.raises(Rejected):
            result.require_text()
        assert consumed == []


@pytest.mark.parametrize("prefix,code", PREFIXES)
@pytest.mark.parametrize("length", [0, 9, 10, 24, 99, 247, 248])
def test_suffix_length_boundaries_never_accept_a_shorter_prefix(prefix, code, length):
    key = token(prefix, length)
    check = SecretScanner(stripe_keys=True, action=Action.REDACT).scan(key, stage=Stage.INPUT)
    if length == 248:
        assert_error(check, "stripe_key_limit_exceeded")
    elif length < 10:
        assert check.action == Action.ALLOW and check.findings == check.edits == ()
    else:
        assert check.action == Action.REDACT
        assert findings(check) == [(code, 0, len(key))]
        assert [(edit.start, edit.end, edit.replacement) for edit in check.edits] == [
            (0, len(key), "[SECRET]")
        ]


def test_ascii_lowercase_uppercase_and_digits_are_all_suffix_characters():
    key = "rk_live_" + "abCD0123456789"
    check = SecretScanner(stripe_keys=True).scan(key, stage=Stage.INPUT)
    assert check.action == Action.BLOCK
    assert findings(check) == [("secret_stripe_restricted_live", 0, len(key))]


@pytest.mark.parametrize("delimiter", list(DELIMITERS), ids=lambda char: f"u{ord(char):04x}")
def test_exact_ascii_delimiters_preserve_both_surrounding_characters(delimiter):
    key = token()
    text = "pre" + delimiter + key + delimiter + "post"
    result = configured(SecretScanner(stripe_keys=True, action=Action.REDACT)).scan(text)
    assert findings(result) == [("secret_stripe_secret_test", 4, 4 + len(key))]
    assert result.require_text() == "pre" + delimiter + "[SECRET]" + delimiter + "post"


@pytest.mark.parametrize(
    "char", ["x", "9", "_", "-", "/", "\\", "+", "@", "é", "\u0301", "\u200b", "\u00a0", "\u2028"]
)
def test_nondelimiter_before_prefix_makes_it_boundary_ineligible(char):
    result = SecretScanner(stripe_keys=True).scan(char + token(), stage=Stage.INPUT)
    assert result.action == Action.ALLOW and result.findings == ()


@pytest.mark.parametrize(
    "char", ["_", "-", "/", "\\", "+", "@", "é", "١", "\u0301", "\u200b", "\u00a0", "\u2028"]
)
def test_nondelimiter_continuation_invalidates_whole_candidate_without_partial_edit(char):
    text = token() + char + "trailing"
    check = SecretScanner(stripe_keys=True, action=Action.REDACT).scan(text, stage=Stage.INPUT)
    assert check.action == Action.ALLOW and check.findings == check.edits == ()


@pytest.mark.parametrize(
    "prefix", ["SK_test_", "sk_TEST_", "rk_LIVE_", "sk_org_", "sk_prod_", "whsec_", "sk_"]
)
def test_case_altered_and_deferred_prefixes_do_not_add_findings(prefix):
    check = SecretScanner(stripe_keys=True).scan(prefix + "Q" * 24, stage=Stage.INPUT)
    assert check.action == Action.ALLOW and check.findings == ()


def test_invalid_candidate_containing_nested_prefix_does_not_hide_later_separate_candidate():
    nested = token() + "_" + token("rk_live_")
    later = token("rk_test_")
    text = nested + " ; " + later
    result = configured(SecretScanner(stripe_keys=True, action=Action.REDACT)).scan(text)
    start = len(nested) + 3
    assert findings(result) == [("secret_stripe_restricted_test", start, len(text))]
    assert result.require_text() == nested + " ; [SECRET]"


def test_malformed_stripe_candidate_does_not_suppress_an_independent_embedded_legacy_match():
    prefix = token() + "-"
    text = prefix + LEGACY + "/tail"
    result = configured(SecretScanner(stripe_keys=True, action=Action.REDACT)).scan(text)
    assert findings(result) == [("secret_github_classic", len(prefix), len(prefix) + len(LEGACY))]
    assert result.require_text() == prefix + "[SECRET]/tail"


def test_delimiter_split_disclosure_keeps_unmatched_fragment_visible():
    left = token("sk_live_", 10)
    text = "masked=" + left + ".HiddenFragment"
    result = configured(SecretScanner(stripe_keys=True, action=Action.REDACT)).scan(text)
    assert findings(result) == [("secret_stripe_secret_live", 7, 7 + len(left))]
    assert result.require_text() == "masked=[SECRET].HiddenFragment"


def test_json_representation_changes_are_not_implicitly_decoded_or_shortened():
    key = token()
    scanner = SecretScanner(stripe_keys=True)
    quoted = '"' + key + '"'
    wire = json.dumps({"value": quoted}, separators=(",", ":"))
    assert scanner.scan(quoted, stage=Stage.INPUT).action == Action.BLOCK
    assert scanner.scan(wire, stage=Stage.INPUT).action == Action.ALLOW
    assert scanner.scan(json.loads(wire)["value"], stage=Stage.INPUT).action == Action.BLOCK
    leading_newline = "\n" + key
    assert scanner.scan(leading_newline, stage=Stage.INPUT).action == Action.BLOCK
    assert scanner.scan(json.dumps(leading_newline), stage=Stage.INPUT).action == Action.ALLOW
    raw = '"' + "".join(f"\\u{ord(char):04x}" for char in key) + '"'
    assert scanner.scan(raw, stage=Stage.INPUT).action == Action.ALLOW


def test_json_escape_after_maximal_valid_key_is_a_budget_error():
    key = token(length=247)
    text = json.dumps('"' + key + '"')
    assert_error(
        SecretScanner(stripe_keys=True).scan(text, stage=Stage.INPUT), "stripe_key_limit_exceeded"
    )


@pytest.mark.parametrize("value", [None, 0, 1, "true", "false", CANARY, [], {}, object()])
def test_stripe_option_requires_actual_bool_without_echoing_value(value):
    with pytest.raises(ValueError) as caught:
        SecretScanner(stripe_keys=value)
    assert CANARY not in str(caught.value)


@pytest.mark.parametrize("action", [Action.ALLOW, Action.ERROR, "block"])
def test_existing_action_validation_still_applies_to_stripe_mode(action):
    with pytest.raises(ValueError):
        SecretScanner(stripe_keys=True, action=action)


@pytest.mark.parametrize(
    "uri_enabled,action", [(False, action) for action in ACTIONS] + [(True, Action.BLOCK)]
)
def test_disabled_stripe_helper_is_never_called_and_adds_no_private_input_budget(
    monkeypatch, uri_enabled, action
):
    forbidden = Mock(side_effect=AssertionError("Disabled helper must not run"))
    monkeypatch.setattr(scanner_module, "find_stripe_keys", forbidden)
    first = SecretScanner(connection_strings=uri_enabled, action=action)
    second = SecretScanner(connection_strings=uri_enabled, stripe_keys=False, action=action)
    for text in (token(), LEGACY, URI, "plain " * 20_000):
        assert first.scan(text, stage=Stage.INPUT) == second.scan(text, stage=Stage.INPUT)
    if not uri_enabled:
        assert first.scan("x" * 100_001, stage=Stage.INPUT).action == Action.ALLOW
    forbidden.assert_not_called()


@pytest.mark.parametrize("uri_enabled", [False, True])
@pytest.mark.parametrize("stripe_enabled", [False, True])
def test_all_flag_combinations_keep_independent_legacy_uri_and_stripe_findings(
    uri_enabled, stripe_enabled
):
    key = token()
    text = " ; ".join((LEGACY, URI, key))
    codes = {"secret_github_classic"}
    if uri_enabled:
        codes.add("secret_postgresql_uri")
    if stripe_enabled:
        codes.add("secret_stripe_secret_test")
    check = SecretScanner(connection_strings=uri_enabled, stripe_keys=stripe_enabled).scan(
        text, stage=Stage.INPUT
    )
    assert check.action == Action.BLOCK and {f.code for f in check.findings} == codes


@pytest.mark.parametrize("action", [Action.WARN, Action.REDACT])
def test_uri_mode_still_rejects_non_block_actions_when_stripe_is_enabled(action):
    with pytest.raises(ValueError):
        SecretScanner(connection_strings=True, stripe_keys=True, action=action)


def test_uri_runtime_configuration_error_precedes_both_content_walks(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("No preflight should run"))
    monkeypatch.setattr(scanner_module, "find_connection_strings", forbidden)
    monkeypatch.setattr(scanner_module, "find_stripe_keys", forbidden)
    scanner = SecretScanner(connection_strings=True, stripe_keys=True)
    scanner.action = Action.REDACT
    assert_error(
        scanner.scan("x" * 100_001, stage=Stage.INPUT), "connection_string_configuration_error"
    )
    forbidden.assert_not_called()


def test_uri_input_limit_precedes_stripe_input_limit():
    assert_error(
        SecretScanner(connection_strings=True, stripe_keys=True).scan(
            "x" * 100_001, stage=Stage.INPUT
        ),
        "connection_string_limit_exceeded",
    )


@pytest.mark.parametrize("interface", ["direct", "guard"])
@pytest.mark.parametrize("length", [100_000, 100_001])
def test_stripe_input_budget_cannot_be_relaxed_by_guard_max_chars(interface, length):
    scanner = SecretScanner(stripe_keys=True)
    text = "x" * length
    if interface == "direct":
        result = scanner.scan(text, stage=Stage.INPUT)
        if length > 100_000:
            assert_error(result, "stripe_key_limit_exceeded")
    else:
        result = configured(scanner, max_chars=200_000).scan(text)
        if length > 100_000:
            assert result.action == Action.ERROR and result.text is None
            assert findings(result) == [("stripe_key_limit_exceeded", None, None)]
    if length == 100_000:
        assert result.action == Action.ALLOW and result.findings == ()


def test_supported_candidate_can_end_at_the_exact_input_limit():
    key = token("rk_live_")
    text = "x" * (100_000 - len(key) - 1) + " " + key
    check = SecretScanner(stripe_keys=True).scan(text, stage=Stage.INPUT)
    assert check.action == Action.BLOCK
    assert findings(check) == [("secret_stripe_restricted_live", 100_000 - len(key), 100_000)]


@pytest.mark.parametrize(
    "fragment", ["sk_test_", "sk_test_" + "Q" * 9, "sk_test_" + "Q" * 10 + "_"]
)
def test_empty_short_and_malformed_candidates_count_toward_attempt_limit(fragment):
    scanner = SecretScanner(stripe_keys=True)
    assert scanner.scan(" ".join([fragment] * 256), stage=Stage.INPUT).action == Action.ALLOW
    assert_error(
        scanner.scan(" ".join([fragment] * 257), stage=Stage.INPUT), "stripe_key_limit_exceeded"
    )


def test_ineligible_and_publishable_prefixes_do_not_consume_attempts():
    text = " ".join(["x" + token(), "pk_test_" + "P" * 24, "pk_live_" + "P" * 24] * 257)
    check = SecretScanner(stripe_keys=True).scan(text, stage=Stage.INPUT)
    assert check.action == Action.ALLOW and check.findings == ()


def test_valid_256_candidates_fit_and_the_257th_is_an_attempt_error():
    scanner = SecretScanner(stripe_keys=True)
    check = scanner.scan(" ".join([token()] * 256), stage=Stage.INPUT)
    assert check.action == Action.BLOCK and len(check.findings) == 256
    assert_error(
        scanner.scan(" ".join([token()] * 257), stage=Stage.INPUT), "stripe_key_limit_exceeded"
    )


@pytest.mark.parametrize("action", ACTIONS)
def test_late_malformed_candidate_overflow_is_atomic_after_legacy_and_stripe_matches(action):
    malformed = "sk_test_" + "_" + "Z" * 247
    assert len(malformed) == 256
    text = " ".join((LEGACY, token(), malformed))
    assert_error(
        SecretScanner(stripe_keys=True, action=action).scan(text, stage=Stage.INPUT),
        "stripe_key_limit_exceeded",
    )


def test_stripe_preflight_limit_precedes_potential_legacy_finding_overflow():
    text = " ".join([LEGACY] * 257 + [token(length=248)])
    assert_error(
        SecretScanner(stripe_keys=True).scan(text, stage=Stage.INPUT), "stripe_key_limit_exceeded"
    )


@pytest.mark.parametrize("with_uri", [False, True])
def test_shared_finding_limit_includes_old_new_and_uri_individual_findings(with_uri):
    scanner = SecretScanner(stripe_keys=True, connection_strings=with_uri)
    extra = [token(), URI] if with_uri else [token()]
    count = 254 if with_uri else 255
    text = " ".join([LEGACY] * count + extra)
    check = scanner.scan(text, stage=Stage.INPUT)
    assert check.action == Action.BLOCK and len(check.findings) == 256
    assert_error(scanner.scan(LEGACY + " " + text, stage=Stage.INPUT), "finding_limit_exceeded")


def test_preflights_finish_in_order_before_legacy_aggregation(monkeypatch):
    events = []

    def uri(_text):
        events.append("uri start")
        yield Finding("secret_postgresql_uri", 0, 1)
        events.append("uri end")

    def stripe(_text):
        events.append("stripe start")
        yield Finding("secret_stripe_secret_test", 2, 3)
        events.append("stripe end")

    def legacy(_text):
        events.append("legacy start")
        yield Finding("secret_github_classic", 4, 5)

    monkeypatch.setattr(scanner_module, "find_connection_strings", uri)
    monkeypatch.setattr(scanner_module, "find_stripe_keys", stripe)
    scanner = SecretScanner(connection_strings=True, stripe_keys=True)
    monkeypatch.setattr(scanner, "_find", legacy)
    check = scanner.scan("abcdef", stage=Stage.INPUT)
    assert check.action == Action.BLOCK and len(check.findings) == 3
    assert events == ["uri start", "uri end", "stripe start", "stripe end", "legacy start"]


def test_uri_preflight_failure_prevents_stripe_preflight(monkeypatch):
    def failing(_text):
        yield Finding("secret_postgresql_uri", 0, 1)
        raise scanner_module.ConnectionStringLimitError

    forbidden = Mock(side_effect=AssertionError("Stripe must not start"))
    monkeypatch.setattr(scanner_module, "find_connection_strings", failing)
    monkeypatch.setattr(scanner_module, "find_stripe_keys", forbidden)
    assert_error(
        SecretScanner(connection_strings=True, stripe_keys=True).scan("abc", stage=Stage.INPUT),
        "connection_string_limit_exceeded",
    )
    forbidden.assert_not_called()


def test_unexpected_late_helper_failure_is_payload_free_atomic_scanner_error(monkeypatch, caplog):
    key = token()

    def failing(_text):
        yield Finding("secret_stripe_secret_test", 0, len(key))
        raise RuntimeError(CANARY)

    monkeypatch.setattr(scanner_module, "find_stripe_keys", failing)
    scanner = SecretScanner(stripe_keys=True, action=Action.REDACT)
    direct = scanner.scan(key, stage=Stage.INPUT)
    assert_error(direct, "scanner_error")
    result = configured(scanner).scan(key)
    assert result.action == Action.ERROR and result.text is None
    assert findings(result) == [("scanner_error", None, None)]
    with pytest.raises(Rejected) as caught:
        result.require_text()
    surface = (
        repr(direct)
        + repr(result)
        + json.dumps(result.diagnostics())
        + str(caught.value)
        + caplog.text
    )
    assert key not in surface and CANARY not in surface and "Q" * 24 not in surface


@pytest.mark.parametrize("exception", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("interface", ["direct", "guard"])
def test_helper_base_exceptions_are_not_swallowed(monkeypatch, exception, interface):
    def interrupted(_text):
        raise exception

    monkeypatch.setattr(scanner_module, "find_stripe_keys", interrupted)
    scanner = SecretScanner(stripe_keys=True)
    with pytest.raises(exception):
        scanner.scan(token(), stage=Stage.INPUT) if interface == "direct" else configured(
            scanner
        ).scan(token())


def test_overlapping_pem_and_stripe_findings_merge_only_redaction_edits():
    key = token("rk_live_")
    envelope = "-----BEGIN PRIVATE KEY-----\n" + key + "\n-----END PRIVATE KEY-----"
    text = "before " + envelope + " after"
    result = configured(SecretScanner(stripe_keys=True, action=Action.REDACT)).scan(text)
    assert len(result.findings) == 2
    assert {item.code for item in result.findings} == {
        "secret_private_key",
        "secret_stripe_restricted_live",
    }
    assert result.require_text() == "before [SECRET] after"
    check = SecretScanner(stripe_keys=True, action=Action.REDACT).scan(text, stage=Stage.INPUT)
    assert len(check.edits) == 1 and (check.edits[0].start, check.edits[0].end) == (
        7,
        7 + len(envelope),
    )


def test_uri_and_stripe_overlap_remain_individual_blocking_findings():
    key = token()
    uri = "postgresql://db.example.invalid/demo?password=" + key + "&public=ok"
    check = SecretScanner(connection_strings=True, stripe_keys=True).scan(uri, stage=Stage.INPUT)
    assert len(check.findings) == 2 and check.edits == ()
    assert {item.code for item in check.findings} == {
        "secret_postgresql_uri",
        "secret_stripe_secret_test",
    }


@pytest.mark.parametrize("prefix", ["pk_test_", "pk_live_"])
def test_publishable_values_do_not_exempt_independent_legacy_secrets(prefix):
    text = prefix + "P" * 24 + " ; " + LEGACY
    check = SecretScanner(stripe_keys=True).scan(text, stage=Stage.INPUT)
    assert check.action == Action.BLOCK and [f.code for f in check.findings] == [
        "secret_github_classic"
    ]


@pytest.mark.parametrize("action", ACTIONS)
def test_prior_pii_redaction_uses_current_secret_scanner_revision(action):
    email = "unit@example.invalid"
    key = token()
    text = "Contact " + email + " ; key " + key
    revised = "Contact [PII] ; key " + key
    result = Guard(
        input_scanners=[PIIScanner(), SecretScanner(stripe_keys=True, action=action)]
    ).scan(text)
    assert len(result.findings) == 2
    pii, secret = result.findings
    assert (pii.code, pii.start, pii.end, pii.revision) == ("pii_email", 8, 8 + len(email), 0)
    assert (secret.code, secret.start, secret.end, secret.revision, secret.scanner_index) == (
        "secret_stripe_secret_test",
        len("Contact [PII] ; key "),
        len(revised),
        1,
        1,
    )
    if action == Action.BLOCK:
        assert result.text is None
    else:
        assert result.require_text() == (
            "Contact [PII] ; key [SECRET]" if action == Action.REDACT else revised
        )


def test_prior_pii_history_remains_when_later_stripe_check_errors_atomically():
    text = "unit@example.invalid ; " + token(length=248)
    scanner = SecretScanner(stripe_keys=True)
    assert_error(scanner.scan(token(length=248), stage=Stage.INPUT), "stripe_key_limit_exceeded")
    result = Guard(input_scanners=[PIIScanner(), scanner]).scan(text)
    assert result.action == Action.ERROR and result.text is None
    assert [(f.code, f.revision, f.scanner_index) for f in result.findings] == [
        ("pii_email", 0, 0),
        ("stripe_key_limit_exceeded", 1, 1),
    ]
    assert (result.findings[-1].start, result.findings[-1].end) == (None, None)
    assert [(t.revision_before, t.revision_after) for t in result.trace] == [(0, 1), (1, 1)]
    with pytest.raises(Rejected):
        result.require_text()


def test_scanner_finding_cap_is_not_replaced_by_a_new_guard_wide_cap():
    text = " ".join(["unit@example.invalid"] * 200 + [token()] * 200)
    result = Guard(input_scanners=[PIIScanner(), SecretScanner(stripe_keys=True)]).scan(text)
    assert result.action == Action.BLOCK and len(result.findings) == 400


@pytest.mark.parametrize("action", ACTIONS)
def test_input_policy_controls_what_reaches_the_model(action):
    key = token()
    callback = Mock(return_value="public response")
    result = Guard(input_scanners=[SecretScanner(stripe_keys=True, action=action)]).run(
        key, callback
    )
    if action == Action.BLOCK:
        callback.assert_not_called()
        with pytest.raises(Rejected):
            result.require_text()
    else:
        callback.assert_called_once_with("[SECRET]" if action == Action.REDACT else key)
        assert result.require_text() == "public response"


@pytest.mark.parametrize("length,expected", [(24, Action.BLOCK), (248, Action.ERROR)])
def test_output_rejection_withholds_result_after_callback_already_ran(length, expected):
    callback = Mock(return_value=token(length=length))
    result = Guard(output_scanners=[SecretScanner(stripe_keys=True)]).run(
        "public request", callback
    )
    callback.assert_called_once_with("public request")
    assert result.action == expected and result.text is None
    with pytest.raises(Rejected):
        result.require_text()


def test_enabled_checks_and_rejection_diagnostics_never_expose_key_or_suffix(caplog):
    key = token("rk_test_")
    result = configured(SecretScanner(stripe_keys=True)).scan(key)
    with pytest.raises(Rejected) as caught:
        result.require_text()
    surface = repr(result) + json.dumps(result.diagnostics()) + str(caught.value) + caplog.text
    assert key not in surface and "Q" * 24 not in surface
