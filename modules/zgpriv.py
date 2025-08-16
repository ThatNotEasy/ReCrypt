from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple

from colorama import Fore

from modules.logger import *
from modules.utils import UTILS
from modules.algorithm import ALGORITHM
import time

class ZGPRIV:
    # Magic markers
    MSTAR_MAGIC = b"MSTAR_SECURE_STORE_FILE_MAGIC_ID"
    INNER_MAGIC = b"INNER_MSTAR_FILE"

    # Crypto constants
    DEFAULT_KEY_HEX = "0007FF4154534D92FC55AA0FFF0110E0"  # 16-byte AES key (hex)
    DEFAULT_IV_KEY_HEX = "00000000000000000000000000000000"  # 16-byte IV (hex)
    CMAC_SECRET_HEX = "8B222FFD1E76195659CF2703898C427F"
    CMAC_DATA_HEX = (
        "019CE93432C7D74016BA684763F801E13600000000000000000000000000000000000080"
    )

    def __init__(self) -> None:
        self.log = setup_logging(name="ReCrypt", level="DEBUG")
        self.path = Path("encrypted/")
        self.output_dir = Path("decrypted/")
        self.utils = UTILS()
        self.alg = ALGORITHM()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Defaults
        self._key_bytes = bytes.fromhex(self.DEFAULT_KEY_HEX)
        self._iv_bytes = bytes.fromhex(self.DEFAULT_IV_KEY_HEX)
        self._cmac_secret = bytes.fromhex(self.CMAC_SECRET_HEX)
        self._cmac_data = bytes.fromhex(self.CMAC_DATA_HEX)

        # Optional overrides
        self._aes_key: Optional[bytes] = None
        self._iv_key: Optional[bytes] = None
        self.algorithm: str = "aes-ecb"

    # ---------------------------- internal helpers ----------------------------
    def _contains(self, data: bytes, pattern: bytes) -> bool:
        return data.find(pattern) != -1

    def _effective_key(self) -> bytes:
        return self._aes_key if self._aes_key else self._key_bytes

    def _effective_iv(self) -> bytes:
        return self._iv_key if self._iv_key else self._iv_bytes

    # ------------------------------ core routine ------------------------------
    def _process_file(self, encrypted_file_path: Path) -> Tuple[bool, Optional[Path]]:
        try:
            if not encrypted_file_path.exists():
                message_info(f"FILE NOT FOUND", f"{encrypted_file_path}")
                return False, None

            enc_size_hr = self.utils.get_file_size(encrypted_file_path, human_readable=True)
            message_info("FILE SIZE   ", f"{encrypted_file_path.name} {Fore.RED}({enc_size_hr})")
            time.sleep(1)

            enc_bytes = encrypted_file_path.read_bytes()

            if not self._contains(enc_bytes, self.MSTAR_MAGIC):
                message_info(f"FIRST PATTERN NOT FOUND", f"{self.MSTAR_MAGIC!r}")
                return False, None
            message_info("FIRST PATTERN FOUND ", f"{self.MSTAR_MAGIC}")
            time.sleep(1)

            # decrypt
            dec_bytes = self.alg.decrypt(
                enc_bytes,
                key=self._effective_key(),
                mode=self.algorithm,
                iv=self._effective_iv(),
            )
            time.sleep(1)

            dec_path = self.output_dir / f"{encrypted_file_path.stem}_dec{encrypted_file_path.suffix}"
            dec_path.write_bytes(dec_bytes)

            if not self._contains(dec_bytes, self.INNER_MAGIC):
                message_info(f"SECOND PATTERN NOT FOUND {self.INNER_MAGIC!r}")
                return True, dec_path
            message_info("SECOND PATTERN FOUND", f" {self.INNER_MAGIC}")
            time.sleep(1)

            # Post-processing overwrite mode
            file_size = encrypted_file_path.stat().st_size
            inner_idx = dec_bytes.find(self.INNER_MAGIC) + len(self.INNER_MAGIC)

            if file_size in (160, 192):
                extracted = dec_bytes[inner_idx : inner_idx + 32]
                dec_path.write_bytes(extracted)
                out_hr = self.utils.get_file_size(dec_path, human_readable=True)
                message_info("STRIPPED OUT 32 BYTES", f" {dec_path.name} {Fore.RED}({out_hr})\n")
                time.sleep(1)
                message_info("w00t!", f" {dec_path.name}")
                return True, dec_path

            if file_size == 176:
                wrapped = dec_bytes[inner_idx : inner_idx + 48]
                unwrapped = self.alg.unwrap_176_key(wrapped, self._cmac_secret, self._cmac_data)
                dec_path.write_bytes(unwrapped)
                unwrap_hr = self.utils.get_file_size(dec_path, human_readable=True)
                message_info("UNWRAPPED 48 TO 32 BYTES", f" {dec_path.name} {Fore.RED}({unwrap_hr})\n")
                time.sleep(1)
                message_info("w00t!", f" {dec_path.name}")
                return True, dec_path

            message_info("Skipping extraction", f" Unsupported file size: {file_size} bytes (expected 160/176/192)\n")
            return True, dec_path

        except Exception as e:
            message_info(f"Error processing {encrypted_file_path.name}: {e}")
            return False, None

    # --------------------------------- public ---------------------------------
    def analyzer_zgpriv(self) -> List[Path]:
        decrypted_files: List[Path] = []
        try:
            files = self.utils.get_all_files(self.path)
            if not files:
                message_info(f"No files found in: {self.path}")
                return decrypted_files

            for file in files:
                file_path = Path(file)
                ok, out_path = self._process_file(file_path)
                if ok and out_path:
                    decrypted_files.append(out_path)

            message_info("Processing complete. Decrypted", f" {len(decrypted_files)} files")
            return decrypted_files
        except Exception as e:
            message_info(f"Analyzer failed: {e}")
            return decrypted_files
