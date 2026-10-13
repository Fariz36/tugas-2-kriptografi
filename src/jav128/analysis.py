"""Byte statistics on plaintext and authenticated ciphertext payloads."""
from collections import Counter
import math


def byte_statistics(data: bytes) -> dict:
    counts = Counter(data)
    size = len(data)
    entropy = -sum((count / size) * math.log2(count / size) for count in counts.values()) if size else None
    return {"size_bytes": size, "entropy_bits_per_byte": entropy,
            "histogram": [counts[value] for value in range(256)]}


def bit_distance(left: bytes, right: bytes) -> int:
    if len(left) != len(right):
        raise ValueError("bit distance requires equal-length inputs")
    return sum((a ^ b).bit_count() for a, b in zip(left, right, strict=True))
