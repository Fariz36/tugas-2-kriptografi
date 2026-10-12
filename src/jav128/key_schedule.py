from collections.abc import Sequence

from .constants import BLOCK_SIZE, ROUND_KEY_COUNT, WORD_MASK
from .core import _rotl32
from .sbox import SBOX


def expand_round_keys(master_key: bytes) -> Sequence[bytes]:
    if not isinstance(master_key, bytes) or len(master_key) != BLOCK_SIZE:
        raise ValueError("master key must be exactly 16 bytes")

    words = [
        int.from_bytes(master_key[offset : offset + 4], "little")
        for offset in range(0, BLOCK_SIZE, 4)
    ]
    round_keys = [master_key]
    for round_number in range(1, ROUND_KEY_COUNT):
        previous = words[-1]
        mixed = previous ^ (round_number * 0x9E3779B9)
        mixed = _rotl32(mixed, round_number & 31)
        words = [
            (words[index] ^ _rotl32(mixed, 7 * index + 3) ^ SBOX[(mixed >> (8 * index)) & 0xFF])
            & WORD_MASK
            for index in range(4)
        ]
        round_keys.append(b"".join(word.to_bytes(4, "little") for word in words))
    return round_keys
