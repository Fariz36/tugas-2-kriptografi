from collections.abc import Callable, Sequence
import secrets

from .constants import BLOCK_SIZE, MODE_IDS

BlockEncryptor = Callable[[bytes, Sequence[bytes]], bytes]


def encrypt_mode(
    padded_plaintext: bytes,
    round_keys: Sequence[bytes],
    mode: str,
    nonce: bytes | None = None,
    *,
    block_encryptor: BlockEncryptor,
) -> tuple[bytes, bytes | None]:
    normalized_mode = mode.upper()
    if normalized_mode not in MODE_IDS:
        raise ValueError("mode must be one of ECB, CBC, CFB, OFB, CTR")
    if not padded_plaintext or len(padded_plaintext) % BLOCK_SIZE:
        raise ValueError("mode input must be a non-empty multiple of 16 bytes")

    if normalized_mode == "ECB":
        if nonce is not None:
            raise ValueError("ECB must not use an IV or counter")
        return _encrypt_ecb(padded_plaintext, round_keys, block_encryptor), None

    if nonce is None:
        nonce = secrets.token_bytes(BLOCK_SIZE)
    if len(nonce) != BLOCK_SIZE:
        raise ValueError("IV/counter must be exactly 16 bytes")

    if normalized_mode == "CBC":
        ciphertext = _encrypt_cbc(padded_plaintext, round_keys, nonce, block_encryptor)
    elif normalized_mode == "CFB":
        ciphertext = _encrypt_cfb(padded_plaintext, round_keys, nonce, block_encryptor)
    elif normalized_mode == "OFB":
        ciphertext = _encrypt_ofb(padded_plaintext, round_keys, nonce, block_encryptor)
    else:
        ciphertext = _encrypt_ctr(padded_plaintext, round_keys, nonce, block_encryptor)
    return ciphertext, nonce


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _blocks(data: bytes):
    for offset in range(0, len(data), BLOCK_SIZE):
        yield data[offset : offset + BLOCK_SIZE]


def _encrypt_ecb(data, keys, encrypt_block):
    return b"".join(encrypt_block(block, keys) for block in _blocks(data))


def _encrypt_cbc(data, keys, iv, encrypt_block):
    feedback = iv
    output = bytearray()
    for block in _blocks(data):
        feedback = encrypt_block(_xor(block, feedback), keys)
        output.extend(feedback)
    return bytes(output)


def _encrypt_cfb(data, keys, iv, encrypt_block):
    feedback = iv
    output = bytearray()
    for block in _blocks(data):
        ciphertext = _xor(block, encrypt_block(feedback, keys))
        output.extend(ciphertext)
        feedback = ciphertext
    return bytes(output)


def _encrypt_ofb(data, keys, iv, encrypt_block):
    feedback = iv
    output = bytearray()
    for block in _blocks(data):
        feedback = encrypt_block(feedback, keys)
        output.extend(_xor(block, feedback))
    return bytes(output)


def _encrypt_ctr(data, keys, initial_counter, encrypt_block):
    counter = int.from_bytes(initial_counter, "big")
    max_counter = (1 << 128) - 1
    blocks = list(_blocks(data))
    output = bytearray()
    for index, block in enumerate(blocks):
        stream_block = encrypt_block(counter.to_bytes(BLOCK_SIZE, "big"), keys)
        output.extend(_xor(block, stream_block))
        if index + 1 < len(blocks):
            if counter == max_counter:
                raise OverflowError("CTR counter would wrap past 128 bits")
            counter += 1
    return bytes(output)
