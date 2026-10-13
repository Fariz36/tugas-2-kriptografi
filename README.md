# JAV-128

JAV-128 adalah cipher blok eksperimental untuk Tugas 2 IF4020 Kriptografi. Program menyediakan CLI untuk mengenkripsi, mendekripsi, dan menganalisis berkas teks maupun biner.

## Desain dan teknologi

- Python 3.11 atau lebih baru, dengan blok dan kunci 128 bit serta 16 putaran.
- S-box tetap dari pencarian GA–SA, permutasi byte, rotasi yang bergantung pada data, operasi ARX, dan ekspansi kunci berantai.
- Lima mode yang diimplementasikan sendiri: ECB, CBC, CFB-128, OFB, dan CTR.
- Padding PKCS#7 pada semua mode dan autentikasi berkas dengan HMAC-SHA-256 dari pustaka standar Python.

Setiap blok dibaca sebagai empat word 32-bit little-endian. Pada setiap putaran, state diproses melalui XOR dengan kunci putaran, substitusi S-box, permutasi byte, rotasi yang bergantung pada data, pencampuran ARX, dan XOR dengan konstanta putaran. Setelah 16 putaran, program menerapkan XOR dengan kunci terakhir. Dekripsi membalik operasi tersebut dalam urutan terbalik. Ekspansi kunci menghasilkan 17 kunci putaran melalui penjumlahan konstanta, substitusi byte, rotasi, dan XOR.

S-box dibentuk melalui pencarian Genetic Algorithm (GA) yang dilanjutkan dengan Simulated Annealing (SA). Kandidat dinilai berdasarkan differential uniformity, nonlinearity, dan penyimpangan Strict Avalanche Criterion (SAC). Tabel hasil pencarian ditetapkan sebelum pengujian cipher. Metodologi dan analisis lengkap dijelaskan dalam laporan.

## Instalasi

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Pada Windows PowerShell, aktifkan lingkungan dengan `.venv\Scripts\Activate.ps1`. Enkripsi dan dekripsi tidak memerlukan dependensi pihak ketiga. Untuk pengumpulan data, pencarian S-box, dan pembuatan grafik, pasang NumPy dan Matplotlib:

```bash
python -m pip install -e '.[analysis]'
```

## Penggunaan CLI

Contoh berikut menggunakan berkas masukan yang tersedia di repositori. Kunci pada contoh adalah kunci uji publik.

```bash
jav128 encrypt --input data/inputs/text_utf8.txt --output hasil.jav --key-hex 000102030405060708090a0b0c0d0e0f --mode CBC
jav128 decrypt --input hasil.jav --output pulih.txt --key-hex 000102030405060708090a0b0c0d0e0f
jav128 analyze --input hasil.jav --plaintext data/inputs/text_utf8.txt --key-hex 000102030405060708090a0b0c0d0e0f --output statistik.json
```

Kunci harus terdiri atas 32 digit heksadesimal. Pilihan `--mode` adalah `ECB`, `CBC`, `CFB`, `OFB`, atau `CTR`. Pada mode selain ECB, program membuat IV/counter acak sepanjang 16 byte. Untuk demonstrasi yang dapat diulang, gunakan `--nonce-hex` dengan 32 digit heksadesimal. Dekripsi membaca mode dan IV/counter dari berkas hasil enkripsi.

Berkas `.jav` merupakan container biner dengan magic `JAV1`. Autentikasi, padding, dan panjang data diperiksa sebelum hasil dekripsi ditulis. Perintah `analyze` memeriksa kecocokan plainteks, lalu menghitung entropi byte dan histogram payload cipherteks. Pemrosesan berkas berlangsung di memori, sehingga ukuran masukan dibatasi oleh RAM yang tersedia.

## Pengujian dan pengumpulan data

Jalankan dari direktori utama repositori setelah memasang dependensi analisis:

```bash
python -m unittest discover -s tests -v
python -m tools.collect_data
python -m tools.collect_design
python -m tools.verify_cli
python -m tools.plot_results
```

Pengumpulan data dapat menimpa hasil sebelumnya. Korpus, seed, dan jumlah sampel tetap digunakan agar pengujian dapat diulang. Grafik dibuat dari hasil yang tersimpan, dalam format PNG dan PDF, tanpa menjalankan ulang eksperimen. Waktu proses serta IV acak pada pemeriksaan CLI dapat berbeda pada setiap pengulangan; pengukuran waktu merupakan pengamatan satu kali yang mencakup akses berkas.

Pencarian S-box merupakan langkah terpisah. Perintah berikut dapat menimpa tabel S-box dan metadatanya, sehingga hanya perlu dijalankan untuk mengulang proses desain:

```bash
python -m tools.sbox_search --seed 0xC0DEC0DE --history data/results/sbox_history.json
```

## Susunan repositori dan hasil eksperimen

| Lokasi | Isi |
| --- | --- |
| `src/jav128/` | Cipher, ekspansi kunci, mode operasi, container, dan CLI |
| `tests/` | Uji unit dan regresi |
| `tools/` | Pencarian S-box, pengumpulan data, dan pembuatan grafik |
| `data/inputs/` | Korpus plainteks pengujian |
| `data/encrypted/`; `data/decrypted/` | Hasil enkripsi dan dekripsi pada kelima mode |
| `data/cli/` | Hasil pemeriksaan CLI; berkas `.txt` berisi plainteks yang dipulihkan |
| `data/results/` | Data numerik, catatan eksperimen, dan log pemeriksaan |
| `data/plots/` | Grafik yang dihasilkan oleh `tools.plot_results` |

Hasil pengujian mencakup 24 uji unit yang lulus, 50 pengujian enkripsi–dekripsi berkas, 160 pemeriksaan penolakan, 9.216 percobaan avalanche, 35 vektor blok, dan 4.096 perbandingan perubahan satu bit kunci. Data utama tersedia di berkas berikut:

| Berkas dalam `data/results/` | Isi |
| --- | --- |
| [manifest.json](data/results/manifest.json) | Lingkungan, seed, kunci/IV uji, serta hash masukan dan kode saat pengumpulan |
| [roundtrips.csv](data/results/roundtrips.csv); [integrity.csv](data/results/integrity.csv) | Keberhasilan enkripsi–dekripsi dan penolakan masukan tidak valid |
| [avalanche_raw.csv](data/results/avalanche_raw.csv); [avalanche_summary.csv](data/results/avalanche_summary.csv) | Pengamatan avalanche dan ringkasannya |
| [histograms.json](data/results/histograms.json) | Frekuensi byte plainteks dan cipherteks |
| [key_schedule_regression.csv](data/results/key_schedule_regression.csv); [related_key_regression.json](data/results/related_key_regression.json) | Pengujian regresi ekspansi kunci |
| [known_vectors.json](data/results/known_vectors.json) | Vektor blok, kunci putaran, dan jejak putaran |
| [artifact_hashes.json](data/results/artifact_hashes.json) | Hash SHA-256 artefak data yang tersimpan |

`manifest.json` adalah catatan eksperimen dan tidak diperlukan untuk mengenkripsi atau mendekripsi berkas. Hash membantu mengenali hasil yang tersimpan. JAV-128 merupakan proyek pendidikan dan belum memiliki bukti keamanan untuk penggunaan produksi.
