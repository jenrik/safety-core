import unittest
from subprocess import TimeoutExpired

from analysis.replay_batches import isolate_timed_out_items


class ReplayBatchFallbackTests(unittest.TestCase):
    def test_retries_every_item_once_and_preserves_successful_order(self):
        problematic = {2, 5}
        calls = []

        def replay(items, timeout):
            calls.append((list(items), timeout))
            if any(item in problematic for item in items):
                raise TimeoutExpired(["replay"], timeout)
            return [item * 10 for item in items]

        resolved, timed_out = isolate_timed_out_items(list(range(8)), replay)

        self.assertEqual(resolved, [(0, 0), (1, 10), (3, 30), (4, 40), (6, 60), (7, 70)])
        self.assertEqual(timed_out, [2, 5])
        self.assertEqual(calls[0], (list(range(8)), 30))
        self.assertEqual(calls[1:], [([item], 5) for item in range(8)])

    def test_returns_a_successful_batch_without_singleton_replays(self):
        calls = []

        def replay(items, timeout):
            calls.append((list(items), timeout))
            return [item * 10 for item in items]

        resolved, timed_out = isolate_timed_out_items([1, 2, 3], replay)

        self.assertEqual(resolved, [(1, 10), (2, 20), (3, 30)])
        self.assertEqual(timed_out, [])
        self.assertEqual(calls, [([1, 2, 3], 30)])

    def test_rejects_result_count_mismatches(self):
        with self.assertRaisesRegex(ValueError, "input batch"):
            isolate_timed_out_items([1, 2], lambda _items, _timeout: [10])

        def mismatched_singleton(items, timeout):
            if len(items) > 1:
                raise TimeoutExpired(["replay"], timeout)
            return []

        with self.assertRaisesRegex(ValueError, "Singleton"):
            isolate_timed_out_items([1, 2], mismatched_singleton)

    def test_propagates_non_timeout_failures_without_fallback(self):
        calls = []

        def replay(items, timeout):
            calls.append((list(items), timeout))
            raise RuntimeError("replay failed")

        with self.assertRaisesRegex(RuntimeError, "replay failed"):
            isolate_timed_out_items([1, 2], replay)
        self.assertEqual(calls, [([1, 2], 30)])

    def test_property_singleton_fallback_identifies_every_generated_problematic_item(self):
        for size in range(1, 65):
            items = list(range(size))
            problematic = {item for item in items if (item * 17 + size) % 11 == 0}
            calls = []

            def replay(batch, timeout):
                calls.append((list(batch), timeout))
                if any(item in problematic for item in batch):
                    raise TimeoutExpired(["replay"], timeout)
                return [f"result-{item}" for item in batch]

            resolved, timed_out = isolate_timed_out_items(items, replay)

            self.assertEqual(timed_out, sorted(problematic))
            self.assertEqual(resolved, [(item, f"result-{item}") for item in items if item not in problematic])
            expected_calls = 1 if not problematic else size + 1
            self.assertEqual(len(calls), expected_calls)
            self.assertEqual(calls[0], (items, 30))
            if problematic:
                self.assertEqual(calls[1:], [([item], 5) for item in items])


if __name__ == "__main__":
    unittest.main()
