from .constants import BLOCK_SIZE


def pad_pkcs7(data: bytes) -> bytes:
    """Tambahkan padding PKCS#7 untuk ukuran blok 16 byte.

    :param data: Data berupa ``bytes``, termasuk data kosong.
    :returns: Data dengan 1 sampai 16 byte padding. Data yang sudah sejajar
        dengan ukuran blok mendapat satu blok padding penuh."""
    amount = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([amount]) * amount


def unpad_pkcs7(data: bytes) -> bytes:
    """Periksa dan hapus padding PKCS#7 untuk ukuran blok 16 byte.

    :param data: Data berpadding berupa ``bytes``.
    :returns: Data asli tanpa padding.
    :raises ValueError: Data kosong, panjang bukan kelipatan 16, atau padding salah."""
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("padded data must be a non-empty multiple of 16 bytes")
    amount = data[-1]
    if amount < 1 or amount > BLOCK_SIZE or data[-amount:] != bytes([amount]) * amount:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-amount]
