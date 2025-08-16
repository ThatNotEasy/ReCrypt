from __future__ import annotations

import sys
from pathlib import Path

from modules.args_parser import parse_args
from modules.zgpriv import ZGPRIV
from modules.banners import banners
from modules.logger import message_info, message_error, message_success


def main() -> int:
    args = parse_args()
    banners()

    # Show provided arguments
    message_info("Files", ", ".join(str(p) for p in args.files))
    message_info("Algorithm", args.algorithm)
    message_info("Use default key", str(args.use_default))
    message_info("AES key", args.aes_key_hex or "<none>")
    message_info("IV key", args.iv_key_hex or "<none>")
    print("═" * 50)

    # Validation
    if args.use_default and args.aes_key_hex:
        message_error("Choose either --default OR --aes-key, not both.")
        return 1

    if not args.use_default and not args.aes_key_hex:
        message_error("No AES key provided. Use -d/--default or supply --aes-key <HEX>.")
        return 1

    zg = ZGPRIV()

    # Apply overrides
    if args.aes_key_hex:
        key_bytes = bytes.fromhex(args.aes_key_hex)
        setattr(zg, "_key_bytes", key_bytes)
        setattr(zg, "_aes_key", key_bytes)
        message_info("AES key override applied", f"{len(key_bytes)} bytes")

    if args.iv_key_hex:
        iv_bytes = bytes.fromhex(args.iv_key_hex)
        setattr(zg, "_iv_key", iv_bytes)
        setattr(zg, "iv_bytes", iv_bytes)
        message_info("IV override applied", f"{len(iv_bytes)} bytes")

    setattr(zg, "algorithm", args.algorithm)

    # Process files
    total, ok_count = 0, 0
    for path in args.files:
        total += 1
        p = Path(path)
        success, _ = zg._process_file(p)
        if success:
            ok_count += 1
        else:
            message_error(f"Failed processing: {p}")

    if ok_count == total:
        message_success("All files processed", f"{ok_count}/{total}\n")
        return 0
    else:
        message_error(f"Some files failed: {ok_count}/{total} succeeded\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
