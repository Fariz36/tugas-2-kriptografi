import hashlib
import hmac

from .constants import (
    BLOCK_SIZE,
    FORMAT_VERSION,
    MAGIC,
    MAC_DOMAIN,
    MODE_IDS,
    TAG_SIZE,
)


def derive_mac_key(master_key: bytes) -> bytes:
    _validate_master_key(master_key)
    return hmac.new(master_key, MAC_DOMAIN, hashlib.sha256).digest()


def build_header(mode: str, original_length: int, nonce: bytes | None) -> bytes:
    normalized_mode = mode.upper()
    if normalized_mode not in MODE_IDS:
        raise ValueError("mode must be one of ECB, CBC, CFB, OFB, CTR")
    if not 0 <= original_length < (1 << 64):
        raise ValueError("plaintext length does not fit in an unsigned 64-bit field")

    if normalized_mode == "ECB":
        if nonce is not None:
            raise ValueError("ECB must not contain an IV or counter")
        encoded_nonce = b""
    else:
        if nonce is None or len(nonce) != BLOCK_SIZE:
            raise ValueError("non-ECB mode requires a 16-byte IV/counter")
        encoded_nonce = nonce

    return (
        MAGIC
        + bytes((FORMAT_VERSION, MODE_IDS[normalized_mode], len(encoded_nonce)))
        + original_length.to_bytes(8, "big")
        + encoded_nonce
    )


def build_container(
    master_key: bytes,
    mode: str,
    original_length: int,
    nonce: bytes | None,
    ciphertext: bytes,
) -> bytes:
    _validate_master_key(master_key)
    if not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("ciphertext must be a non-empty multiple of 16 bytes")
    expected_length = (original_length // BLOCK_SIZE + 1) * BLOCK_SIZE
    if len(ciphertext) != expected_length:
        raise ValueError("ciphertext length does not match PKCS#7 padded plaintext length")
    header = build_header(mode, original_length, nonce)
    tag = hmac.new(derive_mac_key(master_key), header + ciphertext, hashlib.sha256).digest()
    if len(tag) != TAG_SIZE:
        raise AssertionError("unexpected HMAC-SHA-256 tag length")
    return header + ciphertext + tag


def _validate_master_key(master_key: bytes) -> None:
    if not isinstance(master_key, bytes) or len(master_key) != BLOCK_SIZE:
        raise ValueError("master key must be exactly 16 bytes")
