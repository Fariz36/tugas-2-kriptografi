import argparse
import importlib
from pathlib import Path
import sys

from .constants import BLOCK_SIZE
from .encrypt import encrypt_file


def _parse_hex(value: str, label: str, expected_bytes: int) -> bytes:
    if len(value) != expected_bytes * 2:
        raise ValueError(f"{label} must be exactly {expected_bytes * 2} hex digits")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be hexadecimal") from exc
    if len(decoded) != expected_bytes:
        raise ValueError(f"{label} must encode exactly {expected_bytes} bytes")
    return decoded


def _load_round_keys(master_key: bytes):
    try:
        module = importlib.import_module("jav128.key_schedule")
    except ModuleNotFoundError as exc:
        if exc.name == "jav128.key_schedule":
            raise RuntimeError(
                "key scheduler is not integrated yet; it must provide "
                "expand_round_keys(master_key) -> 17 16-byte keys"
            ) from exc
        raise
    expand_round_keys = getattr(module, "expand_round_keys", None)
    if not callable(expand_round_keys):
        raise RuntimeError("jav128.key_schedule must define expand_round_keys(master_key)")
    return expand_round_keys(master_key)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jav128", description="JAV-128 file encryption")
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt = subparsers.add_parser("encrypt", help="encrypt a file")
    encrypt.add_argument("--input", required=True, type=Path)
    encrypt.add_argument("--output", required=True, type=Path)
    encrypt.add_argument("--key-hex", required=True, help="128-bit master key as 32 hex digits")
    encrypt.add_argument("--mode", required=True, choices=("ECB", "CBC", "CFB", "OFB", "CTR"))
    encrypt.add_argument("--nonce-hex", help="16-byte IV/counter; omit for a random value")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        master_key = _parse_hex(args.key_hex, "master key", BLOCK_SIZE)
        nonce = None
        if args.nonce_hex is not None:
            nonce = _parse_hex(args.nonce_hex, "IV/counter", BLOCK_SIZE)
        round_keys = _load_round_keys(master_key)
        encrypt_file(args.input, args.output, master_key, round_keys, args.mode, nonce)
    except (OSError, OverflowError, ValueError, RuntimeError) as exc:
        print(f"jav128: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
