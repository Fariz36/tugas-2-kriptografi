Panduan penggunaan
======================

Instalasi
-------------

Dari direktori repositori, pasang paket ke lingkungan virtual::

   python -m pip install -e .

Enkripsi dan dekripsi bytes
-------------------------------

Bentuk kunci putaran sekali dengan master key yang sama untuk enkripsi dan
dekripsi. API menerima master key dan kunci putaran secara terpisah;
kesesuaiannya tidak diperiksa otomatis. Kunci contoh berikut adalah kunci uji
publik.

.. doctest::

   >>> from jav128 import encrypt_bytes, decrypt_bytes
   >>> from jav128.key_schedule import expand_round_keys
   >>> key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
   >>> round_keys = expand_round_keys(key)
   >>> len(round_keys), len(round_keys[0])
   (17, 16)
   >>> plaintext = "Contoh pesan dalam bahasa Indonesia.".encode("utf-8")
   >>> container = encrypt_bytes(plaintext, key, round_keys, "CBC")
   >>> decrypt_bytes(container, key, round_keys) == plaintext
   True

``encrypt_bytes`` menambahkan padding PKCS#7 dan HMAC. ``decrypt_bytes``
membaca mode serta IV/counter dari header, memeriksa autentikasi, lalu
mendekripsi dan memeriksa padding serta panjang asli.

Mode dan IV/counter
-----------------------

Nilai ``mode`` adalah ``ECB``, ``CBC``, ``CFB``, ``OFB``, atau ``CTR``.
Nama tidak peka huruf besar; ``CFB`` berarti CFB-128.
Untuk ECB, ``nonce`` harus ``None``. Untuk mode lain, ``None`` membuat
IV/counter acak sepanjang 16 byte. Nilai eksplisit juga harus sepanjang 16 byte.

IV CBC dan CFB harus tidak dapat diprediksi. IV OFB serta rentang counter CTR
harus tidak berulang dengan kunci yang sama. Counter CTR menggunakan
urutan big-endian; overflow menimbulkan ``OverflowError``.

Contoh berikut memakai IV tetap hanya untuk pengujian yang dapat diulang.
Semua mode pada format berkas ini memakai padding, termasuk CFB, OFB, dan CTR.

.. doctest::

   >>> for mode in ("ECB", "CBC", "CFB", "OFB", "CTR"):
   ...     nonce = None if mode == "ECB" else bytes(range(16))
   ...     encrypted = encrypt_bytes(plaintext, key, round_keys, mode, nonce)
   ...     assert decrypt_bytes(encrypted, key, round_keys) == plaintext

Enkripsi dan dekripsi berkas
--------------------------------

.. doctest::

   >>> from pathlib import Path
   >>> from tempfile import TemporaryDirectory
   >>> from jav128 import encrypt_file, decrypt_file
   >>> with TemporaryDirectory() as directory:
   ...     root = Path(directory)
   ...     source = root / "pesan.txt"
   ...     encrypted = root / "pesan.jav"
   ...     recovered = root / "pulih.txt"
   ...     _ = source.write_bytes(plaintext)
   ...     encrypt_file(source, encrypted, key, round_keys, "CBC")
   ...     decrypt_file(encrypted, recovered, key, round_keys)
   ...     assert recovered.read_bytes() == plaintext

Berkas keluaran yang sudah ada akan ditimpa setelah proses berhasil.
Kegagalan autentikasi, padding, atau validasi panjang saat dekripsi tidak
mengubah berkas keluaran. Kegagalan I/O saat penulisan tetap dapat meninggalkan
berkas parsial karena penulisan belum atomik. Seluruh berkas diproses di memori.

Penanganan error
--------------------

Parameter atau container yang tidak valid umumnya menimbulkan ``ValueError``.
Kegagalan akses berkas menimbulkan ``OSError``. Contoh perubahan tag:

.. doctest::

   >>> corrupted = container[:-1] + bytes([container[-1] ^ 1])
   >>> try:
   ...     decrypt_bytes(corrupted, key, round_keys)
   ... except ValueError as error:
   ...     print(error)
   authentication failed

API blok dan mode
---------------------

``encrypt_block`` dan ``decrypt_block`` hanya memproses satu blok mentah
sepanjang 16 byte. Keduanya tidak menyediakan padding atau autentikasi.

.. doctest::

   >>> from jav128 import encrypt_block, decrypt_block
   >>> block = bytes(range(16))
   >>> decrypt_block(encrypt_block(block, round_keys), round_keys) == block
   True

Fungsi ``encrypt_mode`` dan ``decrypt_mode`` merupakan fungsi pendukung
untuk payload kelipatan 16 byte. Fungsi tersebut tidak mengemas container
atau memeriksa HMAC. Untuk berkas biasa, gunakan API container di atas.
