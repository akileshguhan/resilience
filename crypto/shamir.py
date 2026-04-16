# crypto/shamir.py
# Shamir's Secret Sharing implementation.
# Identical mathematics to the notebook — split and reconstruct
# over the secp256k1 prime finite field.

import secrets
from config import SHAMIR_PRIME, SHAMIR_TOTAL_SHARES, SHAMIR_THRESHOLD

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def split_secret(secret: int, n: int = SHAMIR_TOTAL_SHARES,
                 k: int = SHAMIR_THRESHOLD) -> list:
    """
    Split a secret integer into n shares with a k-of-n threshold.
    Returns a list of (x, y) tuples.
    """
    assert 0 < k <= n, "Threshold k must be between 1 and n."
    assert secret < SHAMIR_PRIME, "Secret must be smaller than the field prime."

    coefficients = [secret] + [
        secrets.randbelow(SHAMIR_PRIME) for _ in range(k - 1)
    ]

    def evaluate(x):
        result = 0
        for coeff in reversed(coefficients):
            result = (result * x + coeff) % SHAMIR_PRIME
        return result

    return [(i, evaluate(i)) for i in range(1, n + 1)]


def reconstruct_secret(shares: list) -> int:
    """
    Reconstruct the secret from k or more (x, y) share tuples
    using Lagrange interpolation over the finite field.
    """
    def mod_inv(a, m):
        return pow(a, -1, m)

    total = 0
    for i, (xi, yi) in enumerate(shares):
        num = den = 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * (0 - xj)) % SHAMIR_PRIME
            den = (den * (xi - xj)) % SHAMIR_PRIME
        total = (total + yi * num * mod_inv(den, SHAMIR_PRIME)) % SHAMIR_PRIME
    return total


def shares_to_json(shares: list) -> list:
    """Convert shares to JSON-serializable format."""
    return [[x, y] for x, y in shares]


def shares_from_json(data: list) -> list:
    """Reconstruct shares from JSON-deserialized format."""
    return [(int(x), int(y)) for x, y in data]


if __name__ == "__main__":
    # Quick self-test
    print("Testing Shamir's Secret Sharing...")
    secret = 123456789
    shares = split_secret(secret, n=3, k=2)
    assert reconstruct_secret(shares[:2]) == secret, "Reconstruction failed."
    assert reconstruct_secret([shares[0], shares[2]]) == secret
    assert reconstruct_secret([shares[1], shares[2]]) == secret
    print("  All combinations reconstruct correctly.")

    single = reconstruct_secret([shares[0]])
    assert single != secret, "Single share should not reconstruct."
    print("  Single share does not reconstruct.")
    print("  shamir.py OK.")