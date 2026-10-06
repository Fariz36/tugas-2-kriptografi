from .constants import BLOCK_SIZE


def pad_pkcs7(data: bytes) -> bytes:
    amount = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([amount]) * amount


def unpad_pkcs7(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("padded data must be a non-empty multiple of 16 bytes")
    amount = data[-1]
    if amount < 1 or amount > BLOCK_SIZE or data[-amount:] != bytes([amount]) * amount:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-amount]
