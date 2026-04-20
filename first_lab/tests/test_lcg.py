import unittest
import math
from first_lab.lcg import RandomNumberGenerator


class TestLCG(unittest.TestCase):
    def test_pi_approximation_cesaro(self):
        modulus = 2 ** 31 - 1
        multiplier = 16807
        increment = 0
        seed = 12345
        size = 100000

        lcg = RandomNumberGenerator(modulus, multiplier, increment, seed)
        sequence = lcg.generate_sequence(size)

        estimated_pi = lcg.test_sequence(sequence)
        actual_pi = math.pi

        tolerance = 0.01

        error_msg = f"Estimated pi ({estimated_pi:.5f}) deviated from math.pi ({actual_pi:.5f}) by more than {tolerance}"

        self.assertTrue(abs(estimated_pi - actual_pi) < tolerance, error_msg)

    def test_invalid_parameters_raise_error(self):
        with self.assertRaises(ValueError):
            RandomNumberGenerator(modulus=10, multiplier=10, increment=1, seed=1)

        with self.assertRaises(ValueError):
            RandomNumberGenerator(modulus=10, multiplier=3, increment=1, seed=-5)

    def test_full_period_hull_dobell(self):
        lcg = RandomNumberGenerator(modulus=8, multiplier=5, increment=1, seed=0)
        self.assertEqual(lcg.find_period(), 8)

if __name__ == '__main__':
    unittest.main()