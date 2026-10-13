"""Reproduce the report evidence: python -m tools.collect_data."""
from __future__ import annotations
import argparse
import csv
import hashlib
import hmac
import json
import platform
import random
import statistics
import struct
import subprocess
import time
import zlib
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import numpy as np

from jav128.analysis import bit_distance, byte_statistics
from jav128.constants import FORMAT_VERSION, MODE_IDS
from jav128.container import build_container, derive_mac_key
from jav128.core import encrypt_block, decrypt_block
from jav128.decrypt import decrypt_bytes, decrypt_file, parse_container
from jav128.encrypt import encrypt_bytes, encrypt_file
from jav128.key_schedule import expand_round_keys
from tools.sbox_search import evaluate_sbox
from jav128.sbox import SBOX

SEED = 0x4A415631
KEY = bytes(range(16))
IV = bytes(range(16, 32))
MODES = list(MODE_IDS)


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def csv_write(path, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def flip(data, bit):
    result = bytearray(data)
    result[bit // 8] ^= 1 << (bit % 8)
    return bytes(result)


def png_image():
    # Valid RGB PNG: a controlled real binary format with repeated image regions.
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    pixels = b"".join(b"\0" + b"".join(bytes((255, 64, 0) if (x // 8 + y // 8) % 2 else (0, 64, 255)) for x in range(128)) for y in range(128))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 128, 128, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b"")


def corpus(root):
    rng = random.Random(SEED)
    files = {f"edge_{n}.bin": bytes(i % 256 for i in range(n)) for n in (0, 1, 15, 16, 17)}
    files.update({"text_utf8.txt": ("JAV-128: pengujian kriptografi, integritas, dan difusi.\nTeks UTF-8: café, 漢字.\n" * 256).encode(),
                  "image_checker.png": png_image(),
                  "repeated_64k.bin": b"JAV128-pattern!!" * 4096,
                  "random_64k.bin": rng.randbytes(65536),
                  "random_256k.bin": rng.randbytes(262144)})
    for name, data in files.items():
        (root / name).write_bytes(data)
    return files


def roundtrips(out, files):
    rows, histograms = [], []
    keys = expand_round_keys(KEY)
    for name, plain in files.items():
        for mode in MODES:
            nonce = None if mode == "ECB" else IV
            dest = out / "encrypted" / f"{name}.{mode}.jav"
            recovered = out / "decrypted" / f"{name}.{mode}.plain"
            start = time.perf_counter()
            encrypt_file(out / "inputs" / name, dest, KEY, keys, mode, nonce)
            encrypt_s = time.perf_counter() - start
            start = time.perf_counter()
            decrypt_file(dest, recovered, KEY, keys)
            decrypt_s = time.perf_counter() - start
            container = dest.read_bytes()
            _, _, _, payload = parse_container(container, KEY)
            restored = recovered.read_bytes()
            assert restored == plain
            ps, cs = byte_statistics(plain), byte_statistics(payload)
            rows.append({"file": name, "mode": mode, "plaintext_bytes": len(plain),
                         "padded_bytes": len(payload), "container_bytes": len(container),
                         "padding_bytes": len(payload) - len(plain),
                         "original_sha256": digest(plain), "decrypted_sha256": digest(restored),
                         "roundtrip_pass": True, "plaintext_entropy": ps["entropy_bits_per_byte"],
                         "ciphertext_entropy": cs["entropy_bits_per_byte"],
                         "encrypt_seconds": encrypt_s, "decrypt_seconds": decrypt_s})
            histograms.append({"file": name, "mode": mode, "plaintext": ps, "ciphertext_payload": cs})
        print(f"Round trips and histograms: {name}", flush=True)
    csv_write(out / "results" / "roundtrips.csv", rows)
    dump(out / "results" / "histograms.json", histograms)
    return rows


def avalanche(out, core_samples, mode_samples):
    rng = random.Random(SEED + 1)
    rows = []
    for scope, samples, size, modes in [("core", core_samples, 16, ["BLOCK"]), ("mode", mode_samples, 64, MODES)]:
        for sample in range(samples):
            plain, key = rng.randbytes(size), rng.randbytes(16)
            keys = expand_round_keys(key)
            for mode in modes:
                nonce = None if mode in ("BLOCK", "ECB") else IV
                def enc(p, k, rk):
                    if mode == "BLOCK":
                        return encrypt_block(p, rk)
                    return parse_container(encrypt_bytes(p, k, rk, mode, nonce), k)[3]
                baseline = enc(plain, key, keys)
                for kind in ("plaintext", "key"):
                    for bit in range(128):
                        changed_key = flip(key, bit) if kind == "key" else key
                        changed_plain = flip(plain, bit) if kind == "plaintext" else plain
                        changed_keys = expand_round_keys(changed_key) if kind == "key" else keys
                        changed = enc(changed_plain, changed_key, changed_keys)
                        distance = bit_distance(baseline, changed)
                        rows.append({"scope": scope, "mode": mode, "sample": sample,
                                     "kind": kind, "bit": bit, "plaintext_hex": plain.hex(),
                                     "key_hex": key.hex(), "iv_hex": nonce.hex() if nonce else "",
                                     "baseline_ciphertext_hex": baseline.hex(), "changed_ciphertext_hex": changed.hex(),
                                     "changed_bits": distance, "ciphertext_bits": len(baseline) * 8,
                                     "changed_percent": 100 * distance / (len(baseline) * 8),
                                     "per_block_changed_bits": json.dumps([bit_distance(baseline[i:i+16], changed[i:i+16]) for i in range(0,len(baseline),16)])})
            print(f"Avalanche: {scope} sample {sample + 1}/{samples}", flush=True)
    csv_write(out / "results" / "avalanche_raw.csv", rows)
    summaries = []
    for scope, mode, kind in sorted({(r["scope"], r["mode"], r["kind"]) for r in rows}):
        values = [r["changed_percent"] for r in rows if (r["scope"], r["mode"], r["kind"]) == (scope,mode,kind)]
        summaries.append({"scope":scope,"mode":mode,"kind":kind,"trials":len(values),
                          "mean_percent":statistics.mean(values),"stddev_percent":statistics.stdev(values),
                          "min_percent":min(values),"max_percent":max(values)})
    csv_write(out / "results" / "avalanche_summary.csv", summaries)
    return summaries


def integrity(out):
    rows=[];keys=expand_round_keys(KEY)
    work=out / "results" / "integrity_work"
    work.mkdir(exist_ok=True)
    source,dest=work / "input.jav",work / "output.bin"
    def check(mode,name,data,key=KEY,expected=ValueError):
        source.write_bytes(data)
        for existing in (False,True):
            if dest.exists():dest.unlink()
            if existing:dest.write_bytes(b"existing output sentinel")
            try:
                decrypt_file(source,dest,key,expand_round_keys(key))
            except expected as exc:
                preserved=dest.read_bytes()==b"existing output sentinel" if existing else not dest.exists()
                assert preserved
                rows.append({"mode":mode,"case":name,"existing_output":existing,"rejected":True,"output_preserved":preserved,"error":str(exc)})
            else:raise AssertionError(f"accepted {mode}: {name}")
    for mode in MODES:
        nonce=None if mode=="ECB" else IV
        container=encrypt_bytes(b"Acceptance: integrity and padding",KEY,keys,mode,nonce)
        check(mode,"wrong_key",container,flip(KEY,0))
        legacy = Path("evidence/pre_revision_v1/data/encrypted") / f"edge_17.bin.{mode}.jav"
        if legacy.exists():
            check(mode, "legacy_v1_container", legacy.read_bytes())
        positions={"magic":0,"version":4,"mode":5,"nonce_length":6,"original_length":14,
                   "ciphertext":15+(16 if nonce else 0),"tag":len(container)-1}
        if nonce:positions["iv_counter"]=15
        for name,index in positions.items():check(mode,name,flip(container,index*8))
        for n in (0,14,len(container)-1):check(mode,f"truncated_{n}",container[:n])
        check(mode,"appended_byte",container+b"\0")
        # Construct an authenticated ciphertext whose decrypted last byte is 0.
        from jav128.modes import encrypt_mode
        invalid=bytes(16)
        payload,_=encrypt_mode(invalid,keys,mode,nonce,block_encryptor=encrypt_block)
        check(mode,"authenticated_invalid_padding",build_container(KEY,mode,1,nonce,payload))
        # Padding succeeds but authenticated claimed original length is wrong.
        forged=bytearray(encrypt_bytes(b"x",KEY,keys,mode,nonce));forged[7:15]=(2).to_bytes(8,"big")
        forged[-32:]=hmac.new(derive_mac_key(KEY),forged[:-32],hashlib.sha256).digest()
        check(mode,"authenticated_wrong_original_length",bytes(forged))
    from jav128.modes import encrypt_mode, decrypt_mode
    for operation in ("encrypt","decrypt"):
        try:
            if operation=="encrypt":encrypt_mode(bytes(32),keys,"CTR",bytes([255])*16,block_encryptor=encrypt_block)
            else:decrypt_mode(bytes(32),keys,"CTR",bytes([255])*16,block_encryptor=encrypt_block,block_decryptor=decrypt_block)
        except OverflowError as exc:rows.append({"mode":"CTR","case":operation+"_counter_overflow","existing_output":"N/A","rejected":True,"output_preserved":"N/A","error":str(exc)})
        else:raise AssertionError("counter wrapped")
    csv_write(out / "results" / "integrity.csv",rows)
    source.unlink()
    if dest.exists(): dest.unlink()
    work.rmdir()
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,default=Path("data"))
    parser.add_argument("--core-samples",type=int,default=16)
    parser.add_argument("--mode-samples",type=int,default=4)
    args=parser.parse_args()
    if min(args.core_samples,args.mode_samples)<2:parser.error("at least two samples required")
    out=args.output
    for folder in ("inputs","encrypted","decrypted","plots","results"):(out / folder).mkdir(parents=True,exist_ok=True)
    files=corpus(out / "inputs")
    rt=roundtrips(out,files)
    av=avalanche(out,args.core_samples,args.mode_samples)
    failures=integrity(out)
    sbox_metrics=evaluate_sbox(SBOX)
    from dataclasses import asdict
    dump(out / "results" / "sbox_verified.json",asdict(sbox_metrics))
    manifest={"cipher_revision": 2, "container_version": FORMAT_VERSION, "seed":SEED,"experiment_key_hex":KEY.hex(),"experiment_iv_hex":IV.hex(),
              "python":platform.python_version(),"platform":platform.platform(),
              "numpy":np.__version__,"matplotlib":matplotlib.__version__,
              "base_commit":subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip(),
              "working_tree_changes":subprocess.check_output(["git","status","--short"],text=True),
              "source_hashes":{str(p):digest(p.read_bytes()) for p in sorted([*Path('src').rglob('*.py'),*Path('tools').glob('*.py'),*Path('tests').glob('*.py'),Path('src/jav128/sbox_metadata.json')])},
              "inputs":[{"file":n,"bytes":len(d),"sha256":digest(d)} for n,d in files.items()],
              "core_samples":args.core_samples,"mode_samples":args.mode_samples,
              "roundtrip_cases":len(rt),"rejection_cases":len(failures),
              "command":"PYTHONPATH=src:. python -m tools.collect_data",
              "methodology":{"ciphertext":"payload only; PKCS#7 included; header/IV/HMAC excluded",
                 "avalanche":"LSB-first bit indices 0..127; mode plaintext flips in first block of 64-byte input; fixed IV across pairs; independent seeded samples; keys re-expanded after every key flip",
                 "timing":"single-run wall-clock encryption/decryption including file IO, not a controlled benchmark",
                 "empty_entropy":"undefined (null), not zero",
                 "corpus":"synthetic reproducible text, valid generated PNG, repeated blocks and seeded random bytes"}}
    dump(out / "results" / "manifest.json",manifest)
    print(json.dumps({"roundtrip_cases":len(rt),"rejection_cases":len(failures),"avalanche":av},indent=2))


if __name__=="__main__":main()
