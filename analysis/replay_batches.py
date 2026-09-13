"""Bounded batch replay helpers for offline OpenCode history analysis."""

from collections.abc import Callable, Sequence
from subprocess import TimeoutExpired
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")


def isolate_timed_out_items(
    items: Sequence[T],
    replay: Callable[[Sequence[T]], Sequence[R]],
) -> tuple[list[tuple[T, R]], list[T]]:
    """Replay a batch, bisecting timeouts until individual items are isolated."""
    if not items:
        return [], []
    try:
        results = replay(items)
    except TimeoutExpired:
        if len(items) == 1:
            return [], [items[0]]
        midpoint = len(items) // 2
        left_resolved, left_timed_out = isolate_timed_out_items(items[:midpoint], replay)
        right_resolved, right_timed_out = isolate_timed_out_items(items[midpoint:], replay)
        return left_resolved + right_resolved, left_timed_out + right_timed_out

    if len(results) != len(items):
        raise ValueError("Replay result count does not match its input batch")
    return list(zip(items, results)), []
