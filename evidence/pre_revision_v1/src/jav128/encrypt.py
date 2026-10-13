from collections.abc import Sequence
from pathlib import Path

from .constants import BLOCK_SIZE, ROUND_KEY_COUNT
from .container import build_container
from .core import encrypt_block
from .modes import encrypt_mode
from .padding import pad_pkcs7


def encrypt_bytes(
    plaintext: bytes,
    master_key: bytes,
    round_keys: Sequence[bytes],
    mode: str,
    nonce: bytes | None = None,
) -> bytes:
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if not isinstance(master_key, bytes) or len(master_key) != BLOCK_SIZE:
        raise ValueError("master key must be exactly 16 bytes")
    if len(round_keys) != ROUND_KEY_COUNT:
        raise ValueError(f"key schedule must provide exactly {ROUND_KEY_COUNT} round keys")

    padded = pad_pkcs7(plaintext)
    ciphertext, used_nonce = encrypt_mode(
        padded,
        round_keys,
        mode,
        nonce,
        block_encryptor=encrypt_block,
    )
    return build_container(master_key, mode, len(plaintext), used_nonce, ciphertext)


def encrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    master_key: bytes,
    round_keys: Sequence[bytes],
    mode: str,
    nonce: bytes | None = None,
) -> None:
    source = Path(input_path)
    destination = Path(output_path)
    encrypted = encrypt_bytes(source.read_bytes(), master_key, round_keys, mode, nonce)
    destination.write_bytes(encrypted)
