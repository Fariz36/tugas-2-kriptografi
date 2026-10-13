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
    """Enkripsi plainteks menjadi container yang diautentikasi.

    :param plaintext: Data berupa ``bytes``; data kosong juga diterima.
    :param master_key: Kunci sepanjang 16 byte untuk autentikasi container.
    :param round_keys: Hasil ekspansi master key yang sama, sebanyak 17 kunci.
    :param mode: ``ECB``, ``CBC``, ``CFB``, ``OFB``, atau ``CTR``;
        huruf besar dan kecil diterima. ``CFB`` berarti CFB-128.
    :param nonce: IV/counter sepanjang 16 byte. ``None`` membuat nilai acak
        untuk mode selain ECB; ECB harus memakai ``None``.
    :returns: Header, payload cipherteks dengan padding PKCS#7, dan tag HMAC.
    :raises TypeError: Plainteks bukan ``bytes``.
    :raises ValueError: Kunci, mode, atau IV/counter tidak valid.
    :raises OverflowError: Counter CTR melampaui rentang 128 bit.

    Kesesuaian master key dengan round keys tidak diperiksa. Gunakan
    :func:`jav128.key_schedule.expand_round_keys` untuk membentuk round keys.
    IV CBC/CFB harus tidak dapat diprediksi; IV OFB dan rentang counter CTR
    harus tidak berulang dengan kunci yang sama. Nilai tetap hanya untuk uji."""
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
    """Enkripsi seluruh berkas dan tulis container ke berkas keluaran.

    :param input_path: Lokasi berkas plainteks.
    :param output_path: Lokasi container keluaran; berkas yang ada akan ditimpa.
    :param master_key: Kunci sepanjang 16 byte.
    :param round_keys: 17 kunci putaran dari master key yang sama.
    :param mode: Nama mode seperti pada :func:`encrypt_bytes`.
    :param nonce: IV/counter seperti pada :func:`encrypt_bytes`.
    :returns: ``None`` setelah penulisan berhasil.
    :raises OSError: Pembacaan atau penulisan berkas gagal.
    :raises ValueError: Parameter enkripsi tidak valid.
    :raises OverflowError: Counter CTR melampaui rentang 128 bit.

    Seluruh berkas diproses di memori. Penulisan dimulai setelah enkripsi
    berhasil, tetapi tidak bersifat atomik jika terjadi kegagalan I/O."""
    source = Path(input_path)
    destination = Path(output_path)
    encrypted = encrypt_bytes(source.read_bytes(), master_key, round_keys, mode, nonce)
    destination.write_bytes(encrypted)
