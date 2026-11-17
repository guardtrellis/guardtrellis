"""The optional recipe observes scans without changing checked delivery or exporting text."""

import json
import logging
import math
import socket
import traceback

import pytest

from examples import tool_result_handoff as original
from examples import tool_result_metrics as demo
from guardtrellis import Action, Check, Edit, Finding, Guard, Rejected, Result, Stage

CANARY = "PRIVATE_OBSERVABILITY_CANARY"
RAW = "raw " + CANARY
CHECKED = "checked " + CANARY
ATTRIBUTES = {"stage": "retrieval", "outcome": "allow"}
ACTIONS = tuple(Action)


class Scan:
    def __init__(self, events, action=Action.ALLOW, *, error=None, checked=CHECKED):
        self.events = events
        self.error = error
        self.result = Result(action, Stage.RETRIEVAL, checked)

    def scan(self, text, *, stage):
        self.events.append(("scan", text, stage))
        if self.error is not None:
            raise self.error
        return self.result


class Instrument:
    def __init__(self, events, name, *, error=None):
        self.events = events
        self.name = name
        self.error = error
        self.calls = []

    def write(self, value, attributes):
        self.events.append((self.name, value, dict(attributes)))
        self.calls.append((value, dict(attributes)))
        if self.error is not None:
            raise self.error

    def add(self, amount, *, attributes):
        self.write(amount, attributes)

    def record(self, amount, *, attributes):
        self.write(amount, attributes)


class Clock:
    def __init__(self, events, *values):
        self.events = events
        self.values = iter(values)

    def __call__(self):
        self.events.append(("clock",))
        value = next(self.values)
        if isinstance(value, BaseException):
            raise value
        return value


def instruments(events, *, counter_error=None, histogram_error=None):
    counter = Instrument(events, "counter", error=counter_error)
    histogram = Instrument(events, "histogram", error=histogram_error)
    return demo.Metrics(counter, histogram)


def consumer(events, state):
    def consume(text):
        events.append(("consume", text))
        state.append(text)

    return consume


def scan_events(events):
    return [event for event in events if event[0] == "scan"]


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("enabled", [False, True])
def test_checked_delivery_is_identical_with_metrics_disabled_or_enabled(action, enabled):
    events, state = [], []
    metrics = instruments(events) if enabled else None
    scan = Scan(events, action)
    clock = Clock(events, 10.0, 10.25)
    if action in (Action.BLOCK, Action.ERROR):
        with pytest.raises(Rejected, match=action.value):
            demo.scan_and_consume(
                RAW, consumer(events, state), result_guard=scan, instruments=metrics, clock=clock
            )
        assert state == []
    else:
        checked = demo.scan_and_consume(
            RAW, consumer(events, state), result_guard=scan, instruments=metrics, clock=clock
        )
        assert checked == CHECKED and state == [CHECKED]
    assert scan_events(events) == [("scan", RAW, Stage.RETRIEVAL)]
    if enabled:
        attributes = {"stage": "retrieval", "outcome": action.value}
        assert metrics.checks.calls == [(1, attributes)]
        assert metrics.duration.calls == [(0.25, attributes)]
    else:
        assert not [event for event in events if event[0] == "clock"]


def test_disabled_path_never_times_or_configures_metrics(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Disabled telemetry was entered")

    monkeypatch.setattr(demo, "create_demo_metrics", forbidden)
    state = []
    assert demo.scan_and_consume("Public guide", state.append, clock=forbidden) == "Public guide"
    assert state == ["Public guide"]


def test_timing_stops_before_metric_writes_require_text_and_consumption(monkeypatch):
    events, state = [], []
    metrics = instruments(events)
    require_text = Result.require_text

    def checked(result):
        events.append(("require_text",))
        return require_text(result)

    monkeypatch.setattr(Result, "require_text", checked)
    demo.scan_and_consume(
        RAW,
        consumer(events, state),
        result_guard=Scan(events),
        instruments=metrics,
        clock=Clock(events, 100.0, 100.125),
    )
    assert [event[0] for event in events] == [
        "clock",
        "scan",
        "clock",
        "counter",
        "histogram",
        "require_text",
        "consume",
    ]
    assert metrics.duration.calls == [(0.125, ATTRIBUTES)]


@pytest.mark.parametrize(
    "raw",
    [
        "Public guide",
        "Contact demo@example.org",
        "ghp_" + "A" * 36,
        "internal-only@example.org",
        "x" * 2_000,
        "x" * 2_001,
        None,
        b"Public guide",
    ],
)
def test_original_policy_is_preserved(raw):
    expected = original.RETURN_POLICY.scan(raw, stage=Stage.RETRIEVAL)
    actual = demo.RETURN_POLICY.scan(raw, stage=Stage.RETRIEVAL)
    assert actual == expected


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_initial_clock_interruption_runs_no_scan_consumer_or_metric(interruption):
    events, state = [], []
    error = interruption(CANARY)
    metrics = instruments(events)
    with pytest.raises(interruption) as caught:
        demo.scan_and_consume(
            RAW,
            consumer(events, state),
            result_guard=Scan(events),
            instruments=metrics,
            clock=Clock(events, error),
        )
    assert caught.value is error
    assert events == [("clock",)] and state == []
    assert metrics.checks.calls == metrics.duration.calls == []


@pytest.mark.parametrize("action", ACTIONS)
def test_initial_clock_exception_preserves_one_scan_and_checked_decision(action):
    events, state = [], []
    metrics = instruments(events)
    arguments = dict(
        result_guard=Scan(events, action),
        instruments=metrics,
        clock=Clock(events, RuntimeError(CANARY)),
    )
    if action in (Action.BLOCK, Action.ERROR):
        with pytest.raises(Rejected, match=action.value):
            demo.scan_and_consume(RAW, consumer(events, state), **arguments)
        assert state == []
    else:
        assert demo.scan_and_consume(RAW, consumer(events, state), **arguments) == CHECKED
        assert state == [CHECKED]
    assert len(scan_events(events)) == 1
    assert metrics.duration.calls == []
    assert len(metrics.checks.calls) <= 1


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_initial_clock_exception_cannot_replace_an_escaping_scan_exception(error_type):
    events, state = [], []
    metrics = instruments(events)
    primary = error_type(CANARY)
    with pytest.raises(error_type) as caught:
        demo.scan_and_consume(
            RAW,
            state.append,
            result_guard=Scan(events, error=primary),
            instruments=metrics,
            clock=Clock(events, RuntimeError("timing " + CANARY)),
        )
    assert caught.value is primary and state == []
    assert len(scan_events(events)) == 1
    assert metrics.duration.calls == []
    assert len(metrics.checks.calls) <= 1


@pytest.mark.parametrize(
    "error_type,outcome",
    [(RuntimeError, "raised"), (KeyboardInterrupt, "interrupted"), (SystemExit, "interrupted")],
)
def test_exception_escaping_scan_retains_identity_and_static_outcome(error_type, outcome):
    events, state = [], []
    error = error_type(CANARY)
    metrics = instruments(events)
    with pytest.raises(error_type) as caught:
        demo.scan_and_consume(
            RAW,
            consumer(events, state),
            result_guard=Scan(events, error=error),
            instruments=metrics,
            clock=Clock(events, 1.0, 1.5),
        )
    assert caught.value is error and state == []
    assert len(scan_events(events)) == 1
    attributes = {"stage": "retrieval", "outcome": outcome}
    assert metrics.checks.calls == [(1, attributes)]
    assert metrics.duration.calls == [(0.5, attributes)]


def test_scanner_exception_is_returned_error_not_escaping_scan_exception():
    class Broken:
        name = "broken"

        def scan(self, text, *, stage):
            raise RuntimeError(CANARY)

    events, state = [], []
    metrics = instruments(events)
    with pytest.raises(Rejected, match="error"):
        demo.scan_and_consume(
            RAW,
            state.append,
            result_guard=Guard(retrieval_scanners=[Broken()]),
            instruments=metrics,
            clock=Clock(events, 0.0, 0.5),
        )
    assert metrics.checks.calls == [(1, {"stage": "retrieval", "outcome": "error"})]
    assert state == []


@pytest.mark.parametrize("pending_type", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("secondary_type", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("location", ["clock", "counter", "histogram"])
def test_pending_scan_exception_survives_every_telemetry_failure(
    pending_type, secondary_type, location, caplog
):
    events, state = [], []
    primary, secondary = pending_type("scan " + CANARY), secondary_type("metric " + CANARY)
    metrics = instruments(
        events,
        counter_error=secondary if location == "counter" else None,
        histogram_error=secondary if location == "histogram" else None,
    )
    with pytest.raises(pending_type) as caught:
        demo.scan_and_consume(
            RAW,
            consumer(events, state),
            result_guard=Scan(events, error=primary),
            instruments=metrics,
            clock=Clock(events, 0.0, secondary if location == "clock" else 0.25),
        )
    assert caught.value is primary and state == []
    assert len(scan_events(events)) == 1
    assert len(metrics.checks.calls) <= 1 and len(metrics.duration.calls) <= 1
    assert CANARY not in caplog.text


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("location", ["clock", "counter", "histogram"])
def test_ordinary_post_scan_telemetry_error_preserves_checked_delivery(action, location, caplog):
    events, state = [], []
    error = RuntimeError(CANARY)
    metrics = instruments(
        events,
        counter_error=error if location == "counter" else None,
        histogram_error=error if location == "histogram" else None,
    )
    arguments = dict(
        result_guard=Scan(events, action),
        instruments=metrics,
        clock=Clock(events, 2.0, error if location == "clock" else 2.5),
    )
    if action in (Action.BLOCK, Action.ERROR):
        with pytest.raises(Rejected, match=action.value):
            demo.scan_and_consume(RAW, consumer(events, state), **arguments)
        assert state == []
    else:
        assert demo.scan_and_consume(RAW, consumer(events, state), **arguments) == CHECKED
        assert state == [CHECKED]
    assert len(scan_events(events)) == 1
    assert len(metrics.checks.calls) <= 1 and len(metrics.duration.calls) <= 1
    assert CANARY not in caplog.text


@pytest.mark.parametrize("action", [Action.ALLOW, Action.BLOCK])
@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("location", ["clock", "counter", "histogram"])
def test_post_scan_interruption_without_pending_exception_stops_consumption(
    action, interruption, location
):
    events, state = [], []
    error = interruption(CANARY)
    metrics = instruments(
        events,
        counter_error=error if location == "counter" else None,
        histogram_error=error if location == "histogram" else None,
    )
    with pytest.raises(interruption) as caught:
        demo.scan_and_consume(
            RAW,
            consumer(events, state),
            result_guard=Scan(events, action),
            instruments=metrics,
            clock=Clock(events, 3.0, error if location == "clock" else 3.25),
        )
    assert caught.value is error and state == []
    assert len(scan_events(events)) == 1
    assert len(metrics.checks.calls) <= 1 and len(metrics.duration.calls) <= 1


@pytest.mark.parametrize(
    "start,stop",
    [
        (math.nan, 1.0),
        (math.inf, 1.0),
        (-math.inf, 1.0),
        (True, 1.0),
        ("0", 1.0),
        (None, 1.0),
        (0.0, math.nan),
        (0.0, math.inf),
        (0.0, -math.inf),
        (0.0, False),
        (0.0, "1"),
        (0.0, None),
        (5.0, 4.0),
        (-1e308, 1e308),
        (10**1_000, 1.0),
    ],
)
def test_invalid_clock_samples_never_fabricate_duration(start, stop):
    events, state = [], []
    metrics = instruments(events)
    assert (
        demo.scan_and_consume(
            RAW,
            state.append,
            result_guard=Scan(events),
            instruments=metrics,
            clock=Clock(events, start, stop),
        )
        == CHECKED
    )
    assert state == [CHECKED] and len(scan_events(events)) == 1
    assert metrics.duration.calls == []
    assert len(metrics.checks.calls) <= 1


@pytest.mark.parametrize("start,stop,duration", [(0, 0, 0.0), (-5.0, -4.5, 0.5)])
def test_zero_and_negative_origin_monotonic_readings_are_valid(start, stop, duration):
    events, state = [], []
    metrics = instruments(events)
    demo.scan_and_consume(
        RAW,
        state.append,
        result_guard=Scan(events),
        instruments=metrics,
        clock=Clock(events, start, stop),
    )
    assert metrics.duration.calls == [(duration, ATTRIBUTES)]


def test_consumer_failure_is_outside_scan_measurement_and_outcome():
    events = []
    metrics = instruments(events)
    error = RuntimeError(CANARY)

    def fail(text):
        events.append(("consume", text))
        raise error

    with pytest.raises(RuntimeError) as caught:
        demo.scan_and_consume(
            RAW,
            fail,
            result_guard=Scan(events),
            instruments=metrics,
            clock=Clock(events, 0.0, 1.0),
        )
    assert caught.value is error and len(scan_events(events)) == 1
    assert metrics.checks.calls == [(1, ATTRIBUTES)]
    assert metrics.duration.calls == [(1.0, ATTRIBUTES)]


@pytest.fixture
def sdk_demo():
    pytest.importorskip("opentelemetry.sdk.metrics")
    instance = demo.create_demo_metrics()
    try:
        yield instance
    finally:
        instance.provider.shutdown()


def empty_url(value):
    assert value is None or value == ""


def empty_attributes(value):
    assert value is None or value == {}


def finite_number(value):
    assert type(value) in (int, float) and math.isfinite(value)


def assert_exported_envelope(data, counts, durations):
    """Reject unknown metadata and empty healthy exports; validate structural fields separately."""
    assert data is not None
    payload = json.loads(data.to_json())
    assert set(payload) == {"resource_metrics"}
    assert len(payload["resource_metrics"]) == 1
    resource = payload["resource_metrics"][0]
    assert set(resource) - {"schema_url"} == {"resource", "scope_metrics"}
    assert set(resource["resource"]) <= {"attributes", "schema_url"}
    assert resource["resource"]["attributes"] == {"service.name": "guardtrellis-observability-demo"}
    empty_url(resource["resource"].get("schema_url"))
    empty_url(resource.get("schema_url"))
    assert len(resource["scope_metrics"]) == 1
    scoped = resource["scope_metrics"][0]
    assert set(scoped) - {"schema_url"} == {"scope", "metrics"}
    empty_url(scoped.get("schema_url"))
    scope = scoped["scope"]
    assert set(scope) <= {"name", "version", "schema_url", "attributes"}
    assert scope["name"] == "guardtrellis.examples.tool_result_metrics"
    assert scope["version"] == "1"
    empty_url(scope.get("schema_url"))
    empty_attributes(scope.get("attributes"))
    metrics = scoped["metrics"]
    expected_names = set()
    if counts:
        expected_names.add("guardtrellis.checks")
    if durations:
        expected_names.add("guardtrellis.check.duration")
    assert {metric["name"] for metric in metrics} == expected_names
    assert len(metrics) == len(expected_names)
    for metric in metrics:
        assert set(metric) == {"name", "unit", "description", "data"}
        histogram = metric["name"] == "guardtrellis.check.duration"
        assert metric["unit"] == ("s" if histogram else "{check}")
        assert metric["description"] == (
            "Elapsed time of a retrieval scan attempt in seconds."
            if histogram
            else "Number of retrieval scan attempts that completed or raised."
        )
        measurement = metric["data"]
        assert set(measurement) == (
            {"data_points", "aggregation_temporality"}
            if histogram
            else {"data_points", "aggregation_temporality", "is_monotonic"}
        )
        assert type(measurement["aggregation_temporality"]) is int
        assert measurement["aggregation_temporality"] in (1, 2)
        if not histogram:
            assert measurement["is_monotonic"] is True
        points = measurement["data_points"]
        expected = durations if histogram else counts
        assert len(points) == len(expected)
        assert {point["attributes"]["outcome"] for point in points} == set(expected)
        for point in points:
            attributes = point["attributes"]
            assert set(attributes) == {"stage", "outcome"}
            assert attributes["stage"] == "retrieval"
            assert attributes["outcome"] in {
                "allow",
                "warn",
                "redact",
                "block",
                "error",
                "raised",
                "interrupted",
            }
            common = {"attributes", "start_time_unix_nano", "time_unix_nano", "exemplars"}
            assert set(point) == common | (
                {"count", "sum", "bucket_counts", "explicit_bounds", "min", "max"}
                if histogram
                else {"value"}
            )
            assert type(point["start_time_unix_nano"]) is int
            assert type(point["time_unix_nano"]) is int
            assert 0 < point["start_time_unix_nano"] <= point["time_unix_nano"]
            assert point["exemplars"] == []
            outcome = attributes["outcome"]
            if not histogram:
                assert type(point["value"]) is int and point["value"] == counts[outcome]
                continue
            values = durations[outcome]
            assert type(point["count"]) is int and point["count"] == len(values)
            for key in ("sum", "min", "max"):
                finite_number(point[key])
            assert point["sum"] == pytest.approx(sum(values))
            assert point["min"] == pytest.approx(min(values))
            assert point["max"] == pytest.approx(max(values))
            assert 0 <= point["min"] <= point["max"]
            bounds, buckets = point["explicit_bounds"], point["bucket_counts"]
            assert all(type(value) in (int, float) and math.isfinite(value) for value in bounds)
            assert all(left < right for left, right in zip(bounds, bounds[1:], strict=False))
            assert len(buckets) == len(bounds) + 1
            assert all(type(count) is int and count >= 0 for count in buckets)
            assert sum(buckets) == point["count"]
    return payload


def test_real_exports_have_both_instruments_and_all_finite_outcomes(sdk_demo):
    expected = {}
    for action in ACTIONS:
        events, state = [], []
        arguments = dict(
            result_guard=Scan(events, action),
            instruments=sdk_demo.instruments,
            clock=Clock(events, 0.0, 0.25),
        )
        if action in (Action.BLOCK, Action.ERROR):
            with pytest.raises(Rejected):
                demo.scan_and_consume(RAW, state.append, **arguments)
        else:
            demo.scan_and_consume(RAW, state.append, **arguments)
        expected[action.value] = 1
    for error_type, outcome in ((RuntimeError, "raised"), (KeyboardInterrupt, "interrupted")):
        events, state = [], []
        with pytest.raises(error_type):
            demo.scan_and_consume(
                RAW,
                state.append,
                result_guard=Scan(events, error=error_type(CANARY)),
                instruments=sdk_demo.instruments,
                clock=Clock(events, 1.0, 1.25),
            )
        assert state == []
        expected[outcome] = 1
    assert_exported_envelope(
        sdk_demo.reader.get_metrics_data(), expected, {key: [0.25] for key in expected}
    )


def test_real_counter_only_export_after_invalid_timing_has_no_fabricated_duration(sdk_demo):
    state = []
    demo.scan_and_consume(
        RAW,
        state.append,
        result_guard=Scan([]),
        instruments=sdk_demo.instruments,
        clock=Clock([], math.nan),
    )
    assert_exported_envelope(sdk_demo.reader.get_metrics_data(), {"allow": 1}, {})


@pytest.mark.parametrize("location", ["counter", "histogram"])
@pytest.mark.parametrize("write_first", [False, True])
def test_real_export_remains_allowlisted_when_instrument_writes_partly_fail(
    sdk_demo, location, write_first, caplog
):
    class Fails:
        def write(self, value, attributes):
            if write_first:
                instrument = (
                    sdk_demo.instruments.checks
                    if location == "counter"
                    else sdk_demo.instruments.duration
                )
                method = instrument.add if location == "counter" else instrument.record
                method(value, attributes=attributes)
            raise RuntimeError(CANARY)

        def add(self, value, *, attributes):
            self.write(value, attributes)

        def record(self, value, *, attributes):
            self.write(value, attributes)

    metrics = demo.Metrics(
        Fails() if location == "counter" else sdk_demo.instruments.checks,
        Fails() if location == "histogram" else sdk_demo.instruments.duration,
    )
    state = []
    demo.scan_and_consume(
        RAW,
        state.append,
        result_guard=Scan([]),
        instruments=metrics,
        clock=Clock([], 0.0, 0.25),
    )
    assert state == [CHECKED]
    counts = {} if location == "counter" and not write_first else {"allow": 1}
    durations = {} if location == "histogram" and not write_first else {"allow": [0.25]}
    payload = assert_exported_envelope(sdk_demo.reader.get_metrics_data(), counts, durations)
    assert CANARY not in json.dumps(payload) + caplog.text


def test_real_counter_write_can_precede_interruption_without_any_consumption(sdk_demo):
    error = KeyboardInterrupt(CANARY)

    class InterruptedCounter:
        def add(self, value, *, attributes):
            sdk_demo.instruments.checks.add(value, attributes=attributes)
            raise error

    state = []
    with pytest.raises(KeyboardInterrupt) as caught:
        demo.scan_and_consume(
            RAW,
            state.append,
            result_guard=Scan([]),
            instruments=demo.Metrics(InterruptedCounter(), sdk_demo.instruments.duration),
            clock=Clock([], 0.0, 0.25),
        )
    assert caught.value is error and state == []
    assert_exported_envelope(sdk_demo.reader.get_metrics_data(), {"allow": 1}, {})


def test_canaries_custom_metadata_and_active_trace_context_never_enter_exports_or_logs(
    sdk_demo, monkeypatch, caplog
):
    from opentelemetry import baggage, context, trace

    class Replace:
        name = "private_scanner_canary"

        def scan(self, text, *, stage):
            return Check(
                Action.REDACT,
                (Finding("private_finding_canary", 0, len(text)),),
                (Edit(0, len(text), CHECKED),),
            )

    def forbidden(*args, **kwargs):
        raise AssertionError("Diagnostics are not a metric schema")

    monkeypatch.setattr(Result, "diagnostics", forbidden)
    caplog.set_level(logging.DEBUG)
    span = trace.NonRecordingSpan(
        trace.SpanContext(
            trace_id=int("a" * 32, 16),
            span_id=int("b" * 16, 16),
            is_remote=False,
            trace_flags=trace.TraceFlags.SAMPLED,
        )
    )
    active = baggage.set_baggage("private_baggage_canary", CANARY, trace.set_span_in_context(span))
    token = context.attach(active)
    try:
        state = []
        demo.scan_and_consume(
            RAW,
            state.append,
            result_guard=Guard(retrieval_scanners=[Replace()]),
            instruments=sdk_demo.instruments,
            clock=Clock([], 0.0, 0.5),
        )
        assert state == [CHECKED]
        for error_type in (RuntimeError, KeyboardInterrupt, SystemExit):
            with pytest.raises(error_type):
                demo.scan_and_consume(
                    RAW,
                    state.append,
                    result_guard=Scan([], error=error_type(CANARY)),
                    instruments=sdk_demo.instruments,
                    clock=Clock([], 1.0, 1.25),
                )
        assert state == [CHECKED]
    finally:
        context.detach(token)
    payload = assert_exported_envelope(
        sdk_demo.reader.get_metrics_data(),
        {"redact": 1, "raised": 1, "interrupted": 2},
        {"redact": [0.5], "raised": [0.25], "interrupted": [0.25, 0.25]},
    )
    displayed = json.dumps(payload) + caplog.text
    for value in (
        CANARY,
        RAW,
        CHECKED,
        "private_scanner_canary",
        "private_finding_canary",
        "private_baggage_canary",
        "a" * 32,
        "b" * 16,
    ):
        assert value not in displayed


def test_demo_setup_has_no_detectors_default_merge_global_provider_or_network(monkeypatch, caplog):
    pytest.importorskip("opentelemetry.sdk.metrics")
    from opentelemetry import metrics
    from opentelemetry.sdk import resources

    def forbidden(*args, **kwargs):
        raise AssertionError("Ambient setup or network entered")

    monkeypatch.setattr(resources.Resource, "create", forbidden)
    monkeypatch.setattr(resources.Resource, "merge", forbidden)
    monkeypatch.setattr(resources, "_build_resource_detectors", forbidden)
    monkeypatch.setattr(metrics, "set_meter_provider", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    instance = demo.create_demo_metrics()
    try:
        state = []
        demo.scan_and_consume(
            RAW,
            state.append,
            result_guard=Scan([]),
            instruments=instance.instruments,
            clock=Clock([], 0.0, 0.5),
        )
        assert_exported_envelope(instance.reader.get_metrics_data(), {"allow": 1}, {"allow": [0.5]})
        assert CANARY not in caplog.text
    finally:
        instance.provider.shutdown()


def test_handoff_owns_no_collection_flush_shutdown_or_export(sdk_demo, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Lifecycle entered the handoff")

    with monkeypatch.context() as patch:
        patch.setattr(sdk_demo.provider, "force_flush", forbidden)
        patch.setattr(sdk_demo.provider, "shutdown", forbidden)
        patch.setattr(sdk_demo.reader, "collect", forbidden)
        patch.setattr(sdk_demo.reader, "get_metrics_data", forbidden)
        state = []
        demo.scan_and_consume(
            RAW,
            state.append,
            result_guard=Scan([]),
            instruments=sdk_demo.instruments,
            clock=Clock([], 0.0, 0.25),
        )
        assert state == [CHECKED]
    assert_exported_envelope(sdk_demo.reader.get_metrics_data(), {"allow": 1}, {"allow": [0.25]})


def test_enabled_setup_errors_have_static_messages_and_no_payload_logging(monkeypatch, caplog):
    sdk = pytest.importorskip("opentelemetry.sdk.metrics")

    def broken(*args, **kwargs):
        raise RuntimeError(CANARY)

    monkeypatch.setattr(sdk, "MeterProvider", broken)
    with pytest.raises(RuntimeError, match="^Metrics demonstration setup failed$") as caught:
        demo.create_demo_metrics()
    displayed = "".join(traceback.format_exception(caught.value)) + caplog.text
    assert CANARY not in displayed


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_enabled_setup_interruption_retains_identity(monkeypatch, interruption):
    sdk = pytest.importorskip("opentelemetry.sdk.metrics")
    error = interruption(CANARY)

    def broken(*args, **kwargs):
        raise error

    monkeypatch.setattr(sdk, "MeterProvider", broken)
    with pytest.raises(interruption) as caught:
        demo.create_demo_metrics()
    assert caught.value is error
