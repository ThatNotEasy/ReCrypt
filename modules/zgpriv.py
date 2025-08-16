import os
import time
import subprocess
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from pathlib import Path
from typing import List, Optional, Tuple
from modules.logger import setup_logging, message_info, message_error, message_success
from modules.utils import UTILS
from colorama import Fore

class ZGPRIV:
    def __init__(self):
        self.log = setup_logging(name="ReCrypt", level="DEBUG")
        self.mstar_magic = b"MSTAR_SECURE_STORE_FILE_MAGIC_ID"
        self.inner_magic = b"INNER_MSTAR_FILE"
        self.default_key = "0007FF4154534D92FC55AA0FFF0110E0"
        self.path = Path("encrypted/")
        self.output_dir = Path("decrypted/")
        self.utils = UTILS()
        
        if not self.output_dir.exists():
            self.output_dir.mkdir(parents=True, exist_ok=True)
            message_success("Created output directory", f" {self.output_dir}")

    def _run_openssl(self, input_file: Path, output_file: Path) -> bool:
        try:
            time.sleep(0.5)
            message_info("Starting decryption for", f" {input_file.name}\n")
            time.sleep(0.5)
            
            cmd = [
                "openssl", "enc", "-d",
                "-aes-128-ecb",
                f"-K", self.default_key,
                "-in", str(input_file),
                "-out", str(output_file),
                "-nopad"
            ]
            
            result = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                time.sleep(0.5)
                return output_file
            message_error("OpenSSL error", f" {result.stderr}")
            return False
                
        except subprocess.CalledProcessError as e:
            message_error("Decryption failed", f" {e.stderr}")
            return False
        except Exception as e:
            message_error("Unexpected error", f" {str(e)}")
            return False

    def _check_pattern(self, data: bytes, pattern: bytes) -> bool:
        return pattern in data
        
    def _extract_and_overwrite(self, file_path: Path) -> bool:
        try:
            file_size = os.path.getsize(file_path)
            
            with open(file_path, "rb") as f:
                data = f.read()
            
            pattern_index = data.find(self.inner_magic)
            if pattern_index == -1:
                message_error("Inner pattern not found", f" {file_path.name}")
                return False
            
            extract_start = pattern_index + len(self.inner_magic)
            
            if file_size == 160:
                # Handle 160-byte files
                extracted_data = data[extract_start:extract_start+32]
                with open(file_path, "wb") as f:
                    f.write(extracted_data)
                message_info("Wrap and extracting out", f" {file_path.name}")
                
            elif file_size == 176:
                # Handle 176-byte files with CMAC and key unwrapping
                extracted_data = data[extract_start:extract_start+48]
                
                # CMAC key derivation
                cmac_secret = bytes.fromhex("8B222FFD1E76195659CF2703898C427F")
                cmac = CMAC.new(cmac_secret, ciphermod=AES)
                cmac_data = bytes.fromhex('019CE93432C7D74016BA684763F801E13600000000000000000000000000000000000080')
                cmac.update(cmac_data)
                KEK = cmac.hexdigest()
                
                # AES key unwrapping
                unwrapped_data = aes_key_unwrap(bytes.fromhex(KEK), extracted_data)[:32]
                
                # Save to new file with _unwrap suffix
                output_file = file_path.with_name(f"{file_path.stem}_unwrap{file_path.suffix}")
                with open(output_file, "wb") as f:
                    f.write(unwrapped_data)
                message_success("Unwrapped 48 bytes to 32 bytes", f" {output_file.name}")
                
            else:
                message_error("Unsupported file size", f" {file_size} bytes (needs 160 or 176)")
                return False
                
            return True
            
        except Exception as e:
            message_error("Processing failed", f" {file_path.name}: {str(e)}")
            return False

    def _process_file(self, file_path: Path) -> Tuple[bool, Optional[Path]]:
        try:
            time.sleep(0.5)
            file_size = os.path.getsize(file_path)
            human_size = self.utils.get_file_size(file_path, human_readable=True)
            message_info("Processing file", f" {file_path.name} {Fore.RED}({human_size})")
            
            if not file_path.exists():
                message_error(f"File not found: {file_path}")
                return (False, None)

            with open(file_path, "rb") as f:
                data = f.read()

            if not self._check_pattern(data, self.mstar_magic):
                message_error("First pattern not found", f" {self.mstar_magic}")
                return (False, None)

            time.sleep(0.5)
            message_info("First pattern found", f" {self.mstar_magic}")

            output_file = self.output_dir / f"{file_path.stem}_dec{file_path.suffix}"
            decrypted_file = self._run_openssl(file_path, output_file)
            if not decrypted_file:
                return (False, None)

            with open(decrypted_file, "rb") as f:
                decrypted_data = f.read()

            if not self._check_pattern(decrypted_data, self.inner_magic):
                message_error("Second pattern not found", f" {self.inner_magic}")
                return (True, decrypted_file)

            time.sleep(0.5)
            message_info("Second pattern found", f" {self.inner_magic}")
            
            if file_size in (160, 176):
                if self._extract_and_overwrite(decrypted_file):
                    message_success("w00t! Decryption successfully completed", f" {decrypted_file.name} {Fore.RED}({human_size})\n")
                else:
                    message_error("Extraction failed", f" {decrypted_file.name}")
            else:
                message_info("Skipping extraction", 
                        f" Unsupported file size: {file_size} bytes (needs 160 or 176)\n")
            
            print("=" * 50 + "\n")
            return (True, decrypted_file)

        except Exception as e:
            message_error(f"Error processing: {file_path.name}: {str(e)}")
            return (False, None)

    def analyzer_zgpriv(self) -> List[Path]:
        decrypted_files = []
        try:
            files = self.utils.get_all_files(self.path)
            if not files:
                message_error(f"No files found in: {self.path}")
                return decrypted_files

            for file in files:
                file_path = Path(file)
                success, output_path = self._process_file(file_path)
                if success and output_path:
                    decrypted_files.append(output_path)

            time.sleep(0.5)
            message_info("Processing complete. Decrypted", f" {len(decrypted_files)} files")
            return decrypted_files

        except Exception as e:
            message_error(f"Analyzer failed: {str(e)}")
            return decrypted_files