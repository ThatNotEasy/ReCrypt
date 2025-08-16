from __future__ import annotations
from typing import Optional, Union
import binascii
from pathlib import Path

from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util.Padding import unpad
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap

from modules.logger import message_info, message_error, message_success


class ALGORITHM:
    def __init__(self, aes_key: Optional[bytes] = None, iv_key: Optional[bytes] = None):
        self._aes_key = aes_key
        self._iv_key = iv_key

    # ---------------------------- unified decrypt ----------------------------
    @staticmethod
    def decrypt(
        data: Union[bytes, str, Path],
        key: Optional[bytes] = None,
        mode: str = "aes-cbc",
        iv: Optional[bytes] = None,
        output_file: Optional[str] = None,
        auto_unpad: bool = True,
    ) -> bytes:

        if key is None:
            message_error("AES key is required but not provided. Use --aes-key or --default.")
            raise ValueError("AES key is required.")

        if iv is None:
            iv = b"\x00" * 16

        # Kalau input berupa file path, baca dulu
        if isinstance(data, (str, Path)):
            file_path = Path(data)
            if not file_path.exists():
                message_error(f"File not found: {file_path}")
                raise FileNotFoundError(file_path)
            message_info("Reading file", str(file_path))
            data = file_path.read_bytes()

        mode = mode.lower()

        try:
            if mode == "aes-ecb":
                if len(data) % 16 != 0:
                    raise ValueError(f"ECB input must be multiple of 16 (got {len(data)})")
                cipher = AES.new(key, AES.MODE_ECB)
                plaintext = cipher.decrypt(data)

            elif mode == "aes-cbc":
                if len(data) % 16 != 0:
                    raise ValueError(f"CBC input must be multiple of 16 (got {len(data)})")
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                plaintext = cipher.decrypt(data)

            elif mode == "aes-ctr":
                nonce = iv[:8]
                initial = int.from_bytes(iv[8:], "big")
                ctr = Counter.new(64, prefix=nonce, initial_value=initial)
                cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
                plaintext = cipher.decrypt(data)

            else:
                raise ValueError(f"Unsupported algorithm: {mode}")

            # Unpad kalau PKCS7
            if auto_unpad:
                try:
                    plaintext = unpad(plaintext, AES.block_size)
                except ValueError:
                    message_error("Invalid or missing PKCS7 padding. Returning raw data.")

            # Simpan kalau ada output_file
            if output_file:
                with open(output_file, "wb") as f:
                    f.write(plaintext)
                message_success("Decryption complete", f"Output saved to {output_file}")

            return plaintext

        except Exception as e:
            message_error(f"Decryption failed: {e}")
            raise

    # ------------------------- unwrap helper -------------------------
    @staticmethod
    def unwrap_176_key(wrapped: bytes, cmac_secret: bytes, cmac_data: bytes) -> bytes:
        """Return first 32 bytes from RFC3394 unwrap result (as in original)."""
        cmac = CMAC.new(cmac_secret, ciphermod=AES)
        cmac.update(cmac_data)
        kek = bytes.fromhex(cmac.hexdigest())
        return aes_key_unwrap(kek, wrapped)[:32]
