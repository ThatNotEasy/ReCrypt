from __future__ import annotations

import os
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

class BGROUPCERT:
    def __init__(self):
        self.log = setup_logging(name="ReCrypt", level="DEBUG")
        self.mstar_magic = b"MSTAR_SECURE_STORE_FILE_MAGIC_ID"
        self.inner_magic = b"INNER_MSTAR_FILE"
        self.chai_magic = b"CHAI"
        self.end_magic = b"\x93\xfa\xc5\xab"
        self.default_key = "0007FF4154534D92FC55AA0FFF0110E0"
        self.path = Path("encrypted/")
        self.output_dir = Path("decrypted/")
        self.utils = UTILS()
        
    def remove_header(self, data: bytes):
        data = data.split(self.inner_magic.encode())[-1]
        return data
    
    def process_bgroupcert(self, data: bytes) -> bytes:
        data = self.remove_header(data)
        start_index = data.find(self.chai_magic)
        end_index = data.find(self.end_magic)
        ret = data[start_index:end_index + len(self.end_magic)]
        return ret