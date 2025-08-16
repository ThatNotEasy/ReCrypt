from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

_ALG_CHOICES = ("aes-ecb", "aes-cbc", "aes-ctr")


def _normalize_hex(value: str) -> str:
    if value is None:
        return value
    s = value.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    s = s.replace(" ", "")
    if len(s) == 0 or len(s) % 2 != 0:
        raise argparse.ArgumentTypeError("hex must have even length and be non-empty")
    try:
        int(s, 16)
    except ValueError as e:
        raise argparse.ArgumentTypeError("invalid hex string") from e
    return s.upper()


def _algorithm(value: str) -> str:
    if value is None:
        return "aes-ecb"
    v = value.strip().lower()
    if v not in _ALG_CHOICES:
        raise argparse.ArgumentTypeError(
            f"algorithm must be one of: {', '.join(_ALG_CHOICES)}"
        )
    return v


@dataclass
class ParsedArgs:
    files: List[Path]
    aes_key_hex: Optional[str]
    iv_key_hex: Optional[str]
    algorithm: str
    use_default: bool


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Decrypt/unwrap helper with AES key/IV, multiple files, and algorithm selection.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    p.add_argument(
        "-f", "--file",
        dest="files",
        action="append",
        type=Path,
        required=True,
        metavar="PATH",
        help="Encrypted input file. Can be provided multiple times.",
    )

    p.add_argument(
        "--aes-key",
        dest="aes_key_hex",
        type=_normalize_hex,
        metavar="HEX",
        help="AES key in hex. 16/24/32 bytes depending on algorithm.",
    )

    p.add_argument(
        "--iv-key",
        dest="iv_key_hex",
        type=_normalize_hex,
        metavar="HEX",
        help="IV in hex (required for aes-cbc/aes-ctr). Must be 16 bytes.",
    )

    p.add_argument(
        "-alg", "--algorithm",
        dest="algorithm",
        type=_algorithm,
        default="aes-ecb",
        choices=_ALG_CHOICES,
        help="Cipher mode to assume for raw decrypt operations.",
    )

    p.add_argument(
        "-d", "--default",
        dest="use_default",
        action="store_true",
        help="Use built-in default AES-128-ECB key. Overrides --aes-key, --iv-key, and --algorithm.",
    )

    return p


def parse_args(argv: Optional[List[str]] = None) -> ParsedArgs:
    p = build_parser()
    ns = p.parse_args(argv)

    if ns.use_default:
        # force defaults
        ns.aes_key_hex = None
        ns.iv_key_hex = None
        ns.algorithm = "aes-ecb"
    else:
        # post-parse validation
        if ns.iv_key_hex is not None and len(ns.iv_key_hex) != 32:
            p.error("--iv-key must be 16 bytes (32 hex chars)")

        # if ns.algorithm in ("aes-cbc", "aes-ctr") and ns.iv_key_hex is None:
        #     p.error("--iv-key is required when --algorithm is aes-cbc or aes-ctr")

    # dedupe files
    seen, files = set(), []
    for f in ns.files:
        if f not in seen:
            seen.add(f)
            files.append(f)

    return ParsedArgs(
        files=files,
        aes_key_hex=ns.aes_key_hex,
        iv_key_hex=ns.iv_key_hex,
        algorithm=ns.algorithm,
        use_default=ns.use_default,
    )