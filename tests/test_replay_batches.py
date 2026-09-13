import unittest
from subprocess import TimeoutExpired

from analysis.replay_batches import isolate_timed_out_items


class ReplayBatchBisectionTests(unittest.TestCase):
    def test_bisects_each_timed_out_item_and_preserves_successful_order(self):
        problematic = {2, 5}

        def replay(items):
            if any(item in problematic for item in items):
                raise TimeoutExpired(["replay"], 30)
            return [item * 10 for item in items]

        resolved, timed_out = isolate_timed_out_items(list(range(8)), replay)

        self.assertEqual(resolved, [(0, 0), (1, 10), (3, 30), (4, 40), (6, 60), (7, 70)])
        self.assertEqual(timed_out, [2, 5])

    def test_property_bisection_identifies_every_generated_problematic_item(self):
        for size in range(1, 65):
            items = list(range(size))
            problematic = {item for item in items if (item * 17 + size) % 11 == 0}

            def replay(batch):
                if any(item in problematic for item in batch):
                    raise TimeoutExpired(["replay"], 30)
                return [f"result-{item}" for item in batch]

            resolved, timed_out = isolate_timed_out_items(items, replay)

            self.assertEqual(timed_out, sorted(problematic))
            self.assertEqual(resolved, [(item, f"result-{item}") for item in items if item not in problematic])


if __name__ == "__main__":
    unittest.main()
