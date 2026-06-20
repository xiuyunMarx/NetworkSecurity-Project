#!/usr/bin/env python3
"""Textbook RSA 解密。

用法:  python rsa_dec.py <ciphertext_hex> [private_key_file]
       python rsa_dec.py "Ciphertext: <ciphertext_hex>" [private_key_file]

默认私钥文件为 Task1/RSA_Secret_Key.txt。打印 "Plaintext: ..."。
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rsa_core

TASK1_DIR = Path(__file__).resolve().parents[2]


def normalize_ciphertext(value: str) -> str:
    prefix = "Ciphertext:"
    if value.startswith(prefix):
        value = value[len(prefix):].strip()
    return value


def main(argv: list[str]) -> int:
    if not 2 <= len(argv) <= 3:
        print("Usage: python rsa_dec.py <ciphertext_hex> [private_key_file]",
              file=sys.stderr)
        return 1

    ciphertext_text = normalize_ciphertext(argv[1])
    private_key_file = argv[2] if len(argv) >= 3 else TASK1_DIR / "RSA_Secret_Key.txt"

    try:
        ciphertext = int(ciphertext_text, 16)
    except ValueError:
        print("ciphertext must be a hexadecimal integer", file=sys.stderr)
        return 1

    n, d = rsa_core.read_private_key(private_key_file)
    if ciphertext >= n:
        print("ciphertext is too large for this RSA key", file=sys.stderr)
        return 1

    message = rsa_core.rsa_decrypt_int(ciphertext, d, n)
    plaintext = rsa_core.int_to_bytes(message).decode("utf-8", errors="replace")
    print("Plaintext:", plaintext)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
