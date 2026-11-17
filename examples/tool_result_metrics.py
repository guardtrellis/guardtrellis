"""Run this source recipe with optional ``--metrics``; no network or credentials."""

from __future__ import annotations

import argparse
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from time import perf_counter
from typing import TYPE_CHECKING, Protocol

from guardtrellis import Action, Guard, LiteralScanner, PIIScanner, Result, SecretScanner, Stage

if TYPE_CHECKING:
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader

# Preserve the original tool-result handoff policy; only the observation is optional.
RETURN_POLICY = Guard(
    retrieval_scanners=[
        SecretScanner(),
        LiteralScanner(["internal-only"], action=Action.BLOCK),
        PIIScanner(),
    ],
    max_chars=2_000,
)

COUNTER_NAME = "guardtrellis.checks"
COUNTER_UNIT = "{check}"
COUNTER_DESCRIPTION = "Number of retrieval scan attempts that completed or raised."
HISTOGRAM_NAME = "guardtrellis.check.duration"
HISTOGRAM_UNIT = "s"
HISTOGRAM_DESCRIPTION = "Elapsed time of a retrieval scan attempt in seconds."
SCOPE_NAME = "guardtrellis.examples.tool_result_metrics"
SCOPE_VERSION = "1"


class CheckCounter(Protocol):
    def add(self, amount: int, *, attributes: Mapping[str, str]) -> None: ...


class DurationHistogram(Protocol):
    def record(self, amount: float, *, attributes: Mapping[str, str]) -> None: ...


@dataclass(frozen=True)
class Metrics:
    """Explicit caller-owned instruments; this recipe owns no exporter or lifecycle."""

    checks: CheckCounter
    duration: DurationHistogram


@dataclass(frozen=True)
class DemoMetrics:
    """Local demonstration resources; collect and shut down outside the handoff."""

    provider: MeterProvider
    reader: InMemoryMetricReader
    instruments: Metrics


def _read_clock(clock: Callable[[], float]) -> float | None:
    try:
        value = clock()
        # Do not coerce arbitrary objects, bools, NaN or infinite readings into samples.
        if type(value) not in (int, float) or not math.isfinite(value):
            return None
        return float(value)
    except Exception:
        return None


def _elapsed(start: float | None, clock: Callable[[], float]) -> float | None:
    if start is None:
        return None
    stop = _read_clock(clock)
    if stop is None:
        return None
    duration = stop - start
    return duration if math.isfinite(duration) and duration >= 0 else None


def _outcome(result: Result) -> str:
    # StrEnum-compatible strings or arbitrary objects are not telemetry labels.
    action = result.action
    if not isinstance(action, Action):
        return "error"
    return {
        Action.ALLOW: "allow",
        Action.WARN: "warn",
        Action.REDACT: "redact",
        Action.BLOCK: "block",
        Action.ERROR: "error",
    }[action]


def _record(metrics: Metrics, outcome: str, duration: float | None) -> None:
    try:
        metrics.checks.add(1, attributes={"stage": "retrieval", "outcome": outcome})
    except Exception:
        pass
    if duration is not None:
        try:
            metrics.duration.record(duration, attributes={"stage": "retrieval", "outcome": outcome})
        except Exception:
            pass


def scan_and_consume(
    raw_return: str,
    consume: Callable[[str], None],
    *,
    result_guard: Guard = RETURN_POLICY,
    instruments: Metrics | None = None,
    clock: Callable[[], float] = perf_counter,
) -> str:
    """Observe only the synchronous retrieval scan, then deliver its checked text.

    Instruments are trusted application code and may block or export according to
    host configuration. This helper never collects, flushes, shuts down or exports.
    """
    if instruments is None:
        result = result_guard.scan(raw_return, stage=Stage.RETRIEVAL)
    else:
        # An initial interruption propagates before a scan or metric write can occur.
        start = _read_clock(clock)
        try:
            result = result_guard.scan(raw_return, stage=Stage.RETRIEVAL)
        except BaseException as error:
            # A secondary telemetry failure, including interruption, cannot replace
            # the exception already escaping the one scan attempt.
            try:
                duration = _elapsed(start, clock)
                outcome = (
                    "interrupted"
                    if isinstance(error, (KeyboardInterrupt, SystemExit))
                    else "raised"
                )
                _record(instruments, outcome, duration)
            except BaseException:
                pass
            raise
        duration = _elapsed(start, clock)
        _record(instruments, _outcome(result), duration)

    checked_text = result.require_text()
    consume(checked_text)
    return checked_text


def create_demo_metrics() -> DemoMetrics:
    """Explicit opt-in setup for the fixed, in-memory demonstration only."""
    provider = None
    try:
        from opentelemetry.sdk.metrics import AlwaysOffExemplarFilter, MeterProvider
        from opentelemetry.sdk.metrics.export import InMemoryMetricReader
        from opentelemetry.sdk.resources import Resource

        reader = InMemoryMetricReader()
        provider = MeterProvider(
            metric_readers=[reader],
            resource=Resource({"service.name": "guardtrellis-observability-demo"}, schema_url=""),
            exemplar_filter=AlwaysOffExemplarFilter(),
            shutdown_on_exit=False,
        )
        meter = provider.get_meter(SCOPE_NAME, version=SCOPE_VERSION, schema_url="", attributes={})
        instruments = Metrics(
            meter.create_counter(COUNTER_NAME, unit=COUNTER_UNIT, description=COUNTER_DESCRIPTION),
            meter.create_histogram(
                HISTOGRAM_NAME, unit=HISTOGRAM_UNIT, description=HISTOGRAM_DESCRIPTION
            ),
        )
        return DemoMetrics(provider, reader, instruments)
    except BaseException as error:
        if provider is not None:
            try:
                provider.shutdown()
            except BaseException:
                pass
        if isinstance(error, Exception):
            raise RuntimeError("Metrics demonstration setup failed") from None
        raise


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", action="store_true", help="Enable fixed in-memory metrics")
    args = parser.parse_args(argv)
    state: list[str] = []
    if not args.metrics:
        checked = scan_and_consume("Contact demo@example.org", state.append)
        assert state == [checked] == ["Contact [PII]"]
        print("Checked handoff completed (metrics disabled).")
        return

    demo = create_demo_metrics()
    try:
        checked = scan_and_consume(
            "Contact demo@example.org", state.append, instruments=demo.instruments
        )
        assert state == [checked] == ["Contact [PII]"]
        # Collection and lifecycle belong to this caller, after checked delivery.
        data = demo.reader.get_metrics_data()
        if data is None:
            raise RuntimeError("Metrics demonstration produced no measurements")
        print(data.to_json())
    finally:
        demo.provider.shutdown()


if __name__ == "__main__":
    main()
