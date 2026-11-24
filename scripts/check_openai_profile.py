"""Check fresh OpenAI/Azure minimum or locked dependencies, without provider calls."""

from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path

from openai_profiles import (
    PREPARATION_TIMEOUT,
    PROFILES,
    ROOT,
    assert_openai_profile,
    build_options,
    fresh_environment,
    print_evidence,
    profile_constraints,
    run_mocked_examples,
    run_regressions,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--regressions", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix=f"guardtrellis-openai-{args.profile}-") as directory:
        work = Path(directory)
        python = fresh_environment(work)
        constraints, expected = profile_constraints(work, args.profile)
        options = build_options(python, work, ROOT)
        subprocess.run(
            [
                "uv",
                "pip",
                "install",
                "--python",
                str(python),
                "--index-url",
                "https://pypi.org/simple",
                "--constraint",
                str(constraints),
                *options,
                f"{ROOT}[openai]",
            ],
            cwd=work,
            check=True,
            timeout=PREPARATION_TIMEOUT,
        )
        subprocess.run(
            ["uv", "pip", "check", "--python", str(python)], check=True, timeout=PREPARATION_TIMEOUT
        )
        print_evidence(python, work, args.profile, expected)
        assert_openai_profile(python, work, expected)
        run_mocked_examples(python, work, expected)
        if args.regressions:
            run_regressions(python, work, expected)


if __name__ == "__main__":
    main()
