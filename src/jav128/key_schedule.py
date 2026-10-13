from collections.abc import Sequence

from .constants import BLOCK_SIZE, ROUND_KEY_COUNT, WORD_MASK
from .core import _rotl32
from .sbox import SBOX


def expand_round_keys(master_key: bytes) -> Sequence[bytes]:
    """Expand w1..w4 with revision-2 bijective SubWord mixing."""
    if not isinstance(master_key, bytes) or len(master_key) != BLOCK_SIZE:
        raise ValueError("master key must be exactly 16 bytes")
    words = [int.from_bytes(master_key[offset:offset + 4], "little")
             for offset in range(0, BLOCK_SIZE, 4)]
    for i in range(1, 4 * ROUND_KEY_COUNT - 3):
        q = (0x3C6EF372 + i * 0x9E3779B9) & WORD_MASK
        x = words[i - 1]
        t = (x + q) & WORD_MASK
        substituted = sum(SBOX[(t >> (8 * j)) & 0xFF] << (8 * j) for j in range(4))
        g = _rotl32(substituted, (7 * i + 3) % 32) ^ q
        words.append(words[-1] ^ g)
    return [b"".join(word.to_bytes(4, "little") for word in words[offset:offset + 4])
            for offset in range(0, len(words), 4)]
