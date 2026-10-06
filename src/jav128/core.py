from collections.abc import Sequence

from .constants import BLOCK_SIZE, ROUND_KEY_COUNT, WORD_MASK
from .sbox import SBOX


def _rotl32(value: int, count: int) -> int:
    count &= 31
    value &= WORD_MASK
    return ((value << count) | (value >> ((32 - count) & 31))) & WORD_MASK


def _rotr32(value: int, count: int) -> int:
    count &= 31
    value &= WORD_MASK
    return ((value >> count) | (value << ((32 - count) & 31))) & WORD_MASK


def _xor_block(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _permute_bytes(state: bytes) -> bytes:
    result = bytearray(BLOCK_SIZE)
    for source_index, value in enumerate(state):
        result[(5 * source_index + 3) % BLOCK_SIZE] = value
    return bytes(result)


def _words_from_block(block: bytes) -> tuple[int, int, int, int]:
    words = tuple(
        int.from_bytes(block[offset : offset + 4], "little")
        for offset in range(0, BLOCK_SIZE, 4)
    )
    return words[0], words[1], words[2], words[3]


def _block_from_words(words: tuple[int, int, int, int]) -> bytes:
    return b"".join((word & WORD_MASK).to_bytes(4, "little") for word in words)


def _round_constant(round_number: int) -> bytes:
    c = (0xA5A5A5A5 + round_number * 0x7F4A7C15) & WORD_MASK
    words = (
        c,
        _rotl32(c, 7),
        _rotl32(c, 13),
        _rotl32(c, 21),
    )
    return _block_from_words(words)


def _validate_round_keys(round_keys: Sequence[bytes]) -> None:
    if len(round_keys) != ROUND_KEY_COUNT:
        raise ValueError(f"JAV-128 requires exactly {ROUND_KEY_COUNT} round keys")
    if any(not isinstance(key, bytes) or len(key) != BLOCK_SIZE for key in round_keys):
        raise ValueError("each round key must be exactly 16 bytes")


def encrypt_block(block: bytes, round_keys: Sequence[bytes]) -> bytes:
    if not isinstance(block, bytes) or len(block) != BLOCK_SIZE:
        raise ValueError("JAV-128 block input must be exactly 16 bytes")
    _validate_round_keys(round_keys)

    state = block
    for round_index in range(16):
        round_number = round_index + 1
        state = _xor_block(state, round_keys[round_index])
        state = bytes(SBOX[value] for value in state)
        state = _permute_bytes(state)

        a, b, c, d = _words_from_block(state)
        a_rot = _rotl32(a, (b ^ d) & 31)
        c_rot = _rotr32(c, (a_rot ^ b) & 31)

        a_next = (a_rot + _rotl32(b, 5)) & WORD_MASK
        b_next = b ^ _rotl32(c_rot, 11)
        c_next = (c_rot + _rotl32(d, 17)) & WORD_MASK
        d_next = d ^ _rotl32(a_next, 23)
        state = _block_from_words((a_next, b_next, c_next, d_next))
        state = _xor_block(state, _round_constant(round_number))

    return _xor_block(state, round_keys[16])
