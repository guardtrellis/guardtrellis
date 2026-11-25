"""Bounded disclosure-shape detection for selected Stripe account keys."""

from __future__ import annotations

import re
from collections.abc import Iterator

from .models import Finding

# Private work budgets, independent of a caller's Guard configuration.
MAX_TEXT_CHARS = 100_000
MAX_CANDIDATE_CHARS = 255
MAX_CANDIDATES = 256

DELIMITERS = frozenset("\t\n\v\f\r \"'`()[]{}<>,;:=.!?&")
_START = re.compile(r"(?:sk|rk)_(?:test|live)_", re.ASCII)
_CODES = {
    "sk_test_": "secret_stripe_secret_test",
    "sk_live_": "secret_stripe_secret_live",
    "rk_test_": "secret_stripe_restricted_test",
    "rk_live_": "secret_stripe_restricted_live",
}


class StripeKeyLimitError(Exception):
    """Internal control flow without input, token fragments or exception payloads."""


def find_stripe_keys(text: str) -> Iterator[Finding]:
    """Read complete bounded candidates; never normalize or accept a shorter match."""
    size = len(text)
    if size > MAX_TEXT_CHARS:
        raise StripeKeyLimitError
    cursor, attempts = 0, 0
    while match := _START.search(text, cursor):
        start = match.start()
        if start and text[start - 1] not in DELIMITERS:
            cursor = match.end()
            continue
        attempts += 1
        if attempts > MAX_CANDIDATES:
            raise StripeKeyLimitError
        end, valid = match.end(), True
        while end < size and text[end] not in DELIMITERS:
            # Test before consuming the 256th nondelimiter, including malformed ones.
            if end - start >= MAX_CANDIDATE_CHARS:
                raise StripeKeyLimitError
            char = text[end]
            valid &= "A" <= char <= "Z" or "a" <= char <= "z" or "0" <= char <= "9"
            end += 1
        if valid and 10 <= end - match.end() <= 247:
            yield Finding(_CODES[match.group()], start, end)
        # The whole candidate is consumed, including any nested sensitive prefix.
        cursor = end
