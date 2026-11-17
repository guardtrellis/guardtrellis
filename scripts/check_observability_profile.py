"""Prove disabled/no-OpenTelemetry and opted-in minimum/locked source-recipe profiles."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from observability_profiles import (
    PROFILES,
    assert_recipe_profile,
    fresh_environment,
    install_profile,
    run_regressions,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--regressions", action="store_true")
    args = parser.parse_args()
    if args.profile == "disabled" and args.regressions:
        parser.error("The disabled consumer profile deliberately installs no test tooling")
    with tempfile.TemporaryDirectory(
        prefix=f"guardtrellis-observability-{args.profile}-"
    ) as directory:
        work = Path(directory)
        python = fresh_environment(work)
        expected = install_profile(python, work, args.profile)
        assert_recipe_profile(python, work, expected)
        if args.regressions:
            run_regressions(python, work, expected)


if __name__ == "__main__":
    main()
