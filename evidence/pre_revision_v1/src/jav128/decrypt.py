import hashlib
import hmac
from collections.abc import Sequence
from pathlib import Path

from .constants import (
    BLOCK_SIZE,
    FORMAT_VERSION,
    ID_MODES,
    MAGIC,
    ROUND_KEY_COUNT,
    TAG_SIZE,
)
from .container import derive_mac_key
from .core import decrypt_block, encrypt_block
from .modes import decrypt_mode
from .padding import unpad_pkcs7


def parse_container(data: bytes, master_key: bytes) -> tuple[str, int, bytes | None, bytes]:
    if len(data) < 15 + TAG_SIZE:
        raise ValueError("container is truncated")
    if data[:4] != MAGIC or data[4] != FORMAT_VERSION:
        raise ValueError("invalid container header")

    mode = ID_MODES.get(data[5])
    if mode is None:
        raise ValueError("unknown mode ID")
    nonce_length = data[6]
    if nonce_length != (0 if mode == "ECB" else BLOCK_SIZE):
        raise ValueError("invalid IV/counter length")

    header_length = 15 + nonce_length
    if len(data) < header_length + BLOCK_SIZE + TAG_SIZE:
        raise ValueError("container is truncated")

    original_length = int.from_bytes(data[7:15], "big")
    ciphertext = data[header_length:-TAG_SIZE]
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("invalid ciphertext length")
    if len(ciphertext) != (original_length // BLOCK_SIZE + 1) * BLOCK_SIZE:
        raise ValueError("ciphertext length does not match plaintext length")

    expected_tag = hmac.new(derive_mac_key(master_key), data[:-TAG_SIZE], hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, data[-TAG_SIZE:]):
        raise ValueError("authentication failed")
    nonce = data[15:header_length] if nonce_length else None
    return mode, original_length, nonce, ciphertext


def decrypt_bytes(
    container: bytes,
    master_key: bytes,
    round_keys: Sequence[bytes],
) -> bytes:
    if len(round_keys) != ROUND_KEY_COUNT:
        raise ValueError(f"key schedule must provide exactly {ROUND_KEY_COUNT} round keys")
    mode, original_length, nonce, ciphertext = parse_container(container, master_key)
    padded = decrypt_mode(
        ciphertext,
        round_keys,
        mode,
        nonce,
        block_encryptor=encrypt_block,
        block_decryptor=decrypt_block,
    )
    plaintext = unpad_pkcs7(padded)
    if len(plaintext) != original_length:
        raise ValueError("decrypted plaintext length does not match container")
    return plaintext


def decrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    master_key: bytes,
    round_keys: Sequence[bytes],
) -> None:
    source = Path(input_path)
    destination = Path(output_path)
    plaintext = decrypt_bytes(source.read_bytes(), master_key, round_keys)
    destination.write_bytes(plaintext)
