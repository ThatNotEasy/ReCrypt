# ReCrypt - PlayReady Certificate Decryption Tool

**ReCrypt** is a Python-based tool designed primarily for decrypting PlayReady certificates stored in MStar secure storage systems. The tool uses AES-128-ECB decryption and key unwrapping techniques to process encrypted files. It is built to handle PlayReady certificates, but may also work with other AES-encrypted files with a similar structure.

---

## Requirements

- **Python 3.8+**
- **External**:
  - OpenSSL (must be available in the system PATH)

---

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/ThatNotEasy/ReCrypt.git
   ```

2. Install required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Ensure **OpenSSL** is installed and accessible in your system PATH.

---

## Usage

### Running the Tool

1. Place encrypted files into the `encrypted/` folder.
2. Run the script:

   ```bash
   python main.py
   ```

3. Decrypted files will be saved in the `decrypted/` folder.

### Using ReCrypt Programmatically

---

## How It Works

1. **File Discovery**: The tool scans the `encrypted/` folder for files to decrypt.
2. **Pattern Validation**: It checks for the `MSTAR_SECURE_STORE_FILE_MAGIC_ID` and `INNER_MSTAR_FILE` patterns to confirm file integrity.
3. **AES Decryption**: Files are decrypted using the AES-128-ECB encryption algorithm and a predefined default key.
4. **File Extraction**: For 160-byte and 176-byte files, the tool extracts or unwraps data as needed:
   - **160 bytes**: Extracts 32 bytes of meaningful data.
   - **176 bytes**: Performs CMAC-based key unwrapping and saves the unwrapped 32-byte data.
5. **Decrypted Output**: Decrypted files are saved with an appropriate suffix (`_dec` or `_unwrap`) in the `decrypted/` directory.

---

## Footprints Notes:
- Currently is only working in `zgpriv`, and still constructing for bgroupcert & generate directly into `.prd`

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for more details.

---

## References & Credits:
- [replayready](https://github.com/astravaganza/replayready)
- [mstar](https://github.com/dipcore/mstar-bin-tool)