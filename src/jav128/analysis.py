"""Byte statistics on plaintext and authenticated ciphertext payloads."""
from collections import Counter
import math


def byte_statistics(data: bytes) -> dict:
    """Hitung histogram dan entropi Shannon dari distribusi byte.

    :param data: Data berupa ``bytes`` yang akan dianalisis.
    :returns: Dictionary dengan ``size_bytes``, ``entropy_bits_per_byte``, dan
        ``histogram`` berisi 256 frekuensi untuk nilai byte 0 sampai 255.
        Entropi data kosong bernilai ``None``.

    Entropi ini menggambarkan distribusi sampel, bukan bukti keamanan cipher."""
    counts = Counter(data)
    size = len(data)
    entropy = -sum((count / size) * math.log2(count / size) for count in counts.values()) if size else None
    return {"size_bytes": size, "entropy_bits_per_byte": entropy,
            "histogram": [counts[value] for value in range(256)]}


def bit_distance(left: bytes, right: bytes) -> int:
    """Hitung jumlah posisi bit yang berbeda pada dua data.

    :param left: Data pertama berupa ``bytes``.
    :param right: Data kedua berupa ``bytes`` dengan panjang yang sama.
    :returns: Jarak Hamming dalam bit; dua data kosong menghasilkan nol.
    :raises ValueError: Panjang kedua data berbeda."""
    if len(left) != len(right):
        raise ValueError("bit distance requires equal-length inputs")
    return sum((a ^ b).bit_count() for a, b in zip(left, right, strict=True))
