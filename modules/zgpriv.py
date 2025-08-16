from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from colorama import Fore

from modules.logger import (
    setup_logging,
    message_info,
    message_error,
    message_success,
)
from modules.utils import UTILS


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

        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Precompute crypto bytes (default key)
        self._key_bytes = bytes.fromhex(self.DEFAULT_KEY_HEX)
        self._cmac_secret = bytes.fromhex(self.CMAC_SECRET_HEX)
        self._cmac_data = bytes.fromhex(self.CMAC_DATA_HEX)

        # Optional overrides (set by main.py if provided)
        self._aes_key: Optional[bytes] = None
        self._iv_key: Optional[bytes] = None
        self.algorithm: str = "aes-ecb"  # can be overridden to "aes-cbc" or "aes-ctr"

    # ---------------------------- internal helpers ----------------------------
    @staticmethod
    def _contains(data: bytes, pattern: bytes) -> bool:
        return data.find(pattern) != -1

    def _effective_key(self) -> bytes:
        return self._aes_key if self._aes_key else self._key_bytes

    def _effective_iv(self) -> bytes:
        if self._iv_key:
            return self._iv_key
        # Provide a sane default IV if mode needs one
        return bytes.fromhex(self.DEFAULT_IV_KEY_HEX)

    def _decrypt(self, raw: bytes) -> bytes:
        """
        Unified decryptor honoring self.algorithm:
          - aes-ecb: requires len%16==0
          - aes-cbc: requires len%16==0 + 16-byte IV
          - aes-ctr: any size + 16-byte IV (used as nonce|counter seed)
        """
        key = self._effective_key()

        mode = (self.algorithm or "aes-ecb").lower()
        if mode == "aes-ecb":
            if len(raw) % 16 != 0:
                raise ValueError(f"ECB input must be multiple of 16 (got {len(raw)})")
            cipher = AES.new(key, AES.MODE_ECB)
            return cipher.decrypt(raw)

        iv = self._effective_iv()
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes for CBC/CTR")

        if mode == "aes-cbc":
            if len(raw) % 16 != 0:
                raise ValueError(f"CBC input must be multiple of 16 (got {len(raw)})")
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            return cipher.decrypt(raw)

        if mode == "aes-ctr":
            # In PyCryptodome, CTR needs a counter; use nonce=iv[:8], initial_value from iv[8:]
            from Crypto.Util import Counter
            nonce = iv[:8]
            initial = int.from_bytes(iv[8:], "big")
            ctr = Counter.new(64, prefix=nonce, initial_value=initial)
            cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
            return cipher.decrypt(raw)

        raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def _unwrap_176_key(self, wrapped: bytes) -> bytes:
        """Return first 32 bytes from RFC3394 unwrap result (as in original)."""
        cmac = CMAC.new(self._cmac_secret, ciphermod=AES)
        cmac.update(self._cmac_data)
        kek = bytes.fromhex(cmac.hexdigest())
        return aes_key_unwrap(kek, wrapped)[:32]

    # ------------------------------ core routine ------------------------------
    def _process_file(self, encrypted_file_path: Path) -> Tuple[bool, Optional[Path]]:
        try:
            if not encrypted_file_path.exists():
                message_error(f"File not found: {encrypted_file_path}")
                return False, None

            enc_size_hr = self.utils.get_file_size(encrypted_file_path, human_readable=True)
            message_info("Processing file", f" {encrypted_file_path.name} {Fore.RED}({enc_size_hr})")

            enc_bytes = encrypted_file_path.read_bytes()

            # Pre-check outer magic in encrypted payload
            if not self._contains(enc_bytes, self.MSTAR_MAGIC):
                message_error(f"First pattern not found {self.MSTAR_MAGIC!r}")
                return False, None
            message_info("First pattern found", f" {self.MSTAR_MAGIC}")

            # Decrypt whole file (by selected algorithm; default aes-ecb)
            dec_bytes = self._decrypt(enc_bytes)

            # Save the raw decrypted file
            dec_path = self.output_dir / f"{encrypted_file_path.stem}_dec{encrypted_file_path.suffix}"
            dec_path.write_bytes(dec_bytes)

            # Check inner magic in decrypted payload
            if not self._contains(dec_bytes, self.INNER_MAGIC):
                message_error(f"Second pattern not found {self.INNER_MAGIC!r}")
                return True, dec_path

            message_info("Second pattern found", f" {self.INNER_MAGIC}")

            # Post-processing for known sizes
            file_size = encrypted_file_path.stat().st_size
            inner_idx = dec_bytes.find(self.INNER_MAGIC) + len(self.INNER_MAGIC)

            if file_size == 160:
                # direct extraction of 32 bytes after INNER_MAGIC
                extracted = dec_bytes[inner_idx : inner_idx + 32]
                out_path = self.output_dir / f"{encrypted_file_path.stem}_extracted{encrypted_file_path.suffix}"
                out_path.write_bytes(extracted)
                out_hr = self.utils.get_file_size(out_path, human_readable=True)
                message_info("Direct extraction completed", f" {out_path.name} {Fore.RED}({out_hr})")
                message_success("w00t! Decryption successfully completed", f" {dec_path.name}\n")
                return True, dec_path

            if file_size == 176:
                # unwrap 48 -> 32 bytes using derived KEK
                wrapped = dec_bytes[inner_idx : inner_idx + 48]
                unwrapped = self._unwrap_176_key(wrapped)
                unwrap_path = self.output_dir / f"{encrypted_file_path.stem}_unwrap{encrypted_file_path.suffix}"
                unwrap_path.write_bytes(unwrapped)

                dec_hr = self.utils.get_file_size(dec_path, human_readable=True)
                unwrap_hr = self.utils.get_file_size(unwrap_path, human_readable=True)
                message_info("Unwrapped 48 bytes to 32 bytes", f" {dec_path.name} {Fore.RED}({dec_hr})\n")
                message_success("w00t! Decryption successfully completed", f" {unwrap_path.name} {Fore.RED}({unwrap_hr})")
                return True, dec_path

            # Unknown size -> keep decrypted output only
            message_info("Skipping extraction", f" Unsupported file size: {file_size} bytes (needs 160 or 176)\n")
            return True, dec_path

        except Exception as e:
            message_error(f"Error processing {encrypted_file_path.name}: {e}")
            return False, None

    # --------------------------------- public ---------------------------------
    def analyzer_zgpriv(self) -> List[Path]:
        decrypted_files: List[Path] = []
        try:
            files = self.utils.get_all_files(self.path)
            if not files:
                message_error(f"No files found in: {self.path}")
                return decrypted_files

            for file in files:
                file_path = Path(file)
                ok, out_path = self._process_file(file_path)
                if ok and out_path:
                    decrypted_files.append(out_path)

            message_info("Processing complete. Decrypted", f" {len(decrypted_files)} files")
            return decrypted_files
        except Exception as e:
            message_error(f"Analyzer failed: {e}")
            return decrypted_files