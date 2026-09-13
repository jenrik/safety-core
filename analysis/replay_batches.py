"""Bounded batch replay helpers for offline OpenCode history analysis."""

from collections.abc import Callable, Sequence
from subprocess import TimeoutExpired
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")


def isolate_timed_out_items(
    items: Sequence[T],
    replay: Callable[[Sequence[T], float], Sequence[R]],
    *,
    batch_timeout: float = 30,
    item_timeout: float = 5,
) -> tuple[list[tuple[T, R]], list[T]]:
    """Replay a batch, then retry every item once with a shorter timeout."""
    if not items:
        return [], []
    try:
        results = replay(items, batch_timeout)
    except TimeoutExpired:
        resolved: list[tuple[T, R]] = []
        timed_out: list[T] = []
        for item in items:
            try:
                result = replay([item], item_timeout)
            except TimeoutExpired:
                timed_out.append(item)
                continue
            if len(result) != 1:
                raise ValueError("Singleton replay result count does not match its input")
            resolved.append((item, result[0]))
        return resolved, timed_out

    if len(results) != len(items):
        raise ValueError("Replay result count does not match its input batch")
    return list(zip(items, results)), []
