from __future__ import annotations

import sys
from pathlib import Path

from modules.args_parser import parse_args
from modules.zgpriv import ZGPRIV
from modules.banners import banners
from modules.logger import message_info


def _validate_args(args) -> bool:
    if args.use_default and args.aes_key_hex:
        message_info("Choose either --default OR --aes-key, not both.")
        return False
    if not args.use_default and not args.aes_key_hex:
        message_info("No AES key provided. Use -d/--default or supply --aes-key <HEX>.")
        return False
    return True


def main() -> int:
    args = parse_args()
    banners()

    if not _validate_args(args):
        return 1

    zg = ZGPRIV()

    message_info("FILES     ", ", ".join(str(p) for p in args.files))
    message_info("ALGORITHM ", args.algorithm)
    message_info("DEFAULT   ", str(args.use_default))
    message_info("AES-KEY   ", args.aes_key_hex or "<none>")
    message_info("IV-KEY    ", args.iv_key_hex or "<default: 16*0>")
    print("═" * 100)

    if args.aes_key_hex:
        key_bytes = bytes.fromhex(args.aes_key_hex)
        zg._key_bytes = zg._aes_key = key_bytes

    if args.iv_key_hex:
        iv_bytes = bytes.fromhex(args.iv_key_hex)
        zg._iv_key = zg.iv_bytes = iv_bytes

    zg.algorithm = args.algorithm

    ok_count = 0
    for idx, path in enumerate(args.files, 1):
        success, _ = zg._process_file(Path(path))
        if success:
            ok_count += 1
        else:
            message_info(f"Failed processing: {path}")

    total = len(args.files)
    if ok_count == total:
        message_info("All files processed", f"{ok_count}/{total}\n")
        return 0
    else:
        message_info(f"Some files failed: {ok_count}/{total} succeeded\n")
        return 1


if __name__ == "__main__":
    banners()
    sys.exit(main())
