import unittest

from tools.sbox_search import evaluate_sbox, search_sbox


class SBoxSearchTests(unittest.TestCase):
    def test_metrics_reject_non_permutations(self):
        with self.assertRaises(ValueError):
            evaluate_sbox([0] * 256)

    def test_search_is_reproducible_and_bijective(self):
        first, first_metrics = search_sbox(
            seed=12345, population_size=5, generations=1, sa_steps=2
        )
        second, second_metrics = search_sbox(
            seed=12345, population_size=5, generations=1, sa_steps=2
        )
        self.assertEqual(first, second)
        self.assertEqual(first_metrics, second_metrics)
        self.assertEqual(sorted(first), list(range(256)))


if __name__ == "__main__":
    unittest.main()
