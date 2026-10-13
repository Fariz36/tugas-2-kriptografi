Referensi fungsi
====================

Enam fungsi enkripsi/dekripsi utama juga dapat diimpor dari ``jav128``.
Referensi berikut memakai lokasi modul asal agar setiap fungsi hanya muncul sekali.

Enkripsi bytes dan berkas
-----------------------------

.. automodule:: jav128.encrypt
   :members: encrypt_bytes, encrypt_file

Dekripsi dan pemeriksaan container
--------------------------------------

.. automodule:: jav128.decrypt
   :members: decrypt_bytes, decrypt_file, parse_container

Cipher blok
---------------

.. automodule:: jav128.core
   :members: encrypt_block, decrypt_block

Ekspansi kunci
------------------

.. automodule:: jav128.key_schedule
   :members: expand_round_keys

Mode operasi
----------------

.. automodule:: jav128.modes
   :members: encrypt_mode, decrypt_mode

Padding
-----------

.. automodule:: jav128.padding
   :members: pad_pkcs7, unpad_pkcs7

Pembuatan container
-----------------------

.. automodule:: jav128.container
   :members: derive_mac_key, build_header, build_container

Analisis data
-----------------

.. automodule:: jav128.analysis
   :members: byte_statistics, bit_distance
