from math import sqrt
from typing import List

class RandomNumberGenerator:
    def __init__(self, modulus: int, multiplier: int, increment: int, seed: int):
        self.modulus = modulus
        self.multiplier = multiplier
        self.increment = increment
        self.seed = seed
        if not self._check_conditions():
            raise ValueError("Parameters don't meet conditions")

    def _check_conditions(self) -> bool:
        return all([
            self.modulus > 0,
            0 <= self.multiplier < self.modulus,
            0 <= self.increment < self.modulus,
            0 <= self.seed < self.modulus
        ])

    def _get_next_number(self, x) -> int:
        return (self.multiplier * x + self.increment) % self.modulus

    def generate_sequence(self, size: int) -> List[int]:
        if size <= 0:
            return []

        output = [self.seed]

        for i in range(1, size):
            output.append(self._get_next_number(output[i - 1]))

        return output

    def find_period(self) -> int:
        count = 1
        current = self._get_next_number(self.seed)

        while current != self.seed and count < self.modulus:
            current = self._get_next_number(current)
            count += 1
        return count

    @staticmethod
    def gcd(a: int, b: int) -> int:
        if a < b:
            a, b = b, a
        while b > 0:
            a, b = b, a % b
        return a

    def test_sequence(self, sequence: List[int]) -> float:
        pairs = [(sequence[i], sequence[i+1]) for i in range(0, len(sequence)-1, 2)
                 if sequence[i] != 0 and sequence[i+1] != 0]

        if not pairs:
            return 0.0

        gcd_results = [self.gcd(a, b) for a, b in pairs]

        numerator = sum(1 for g in gcd_results if g == 1)
        denominator = len(gcd_results)

        if numerator == 0:
            return 0.0

        return sqrt(6 * denominator / numerator)