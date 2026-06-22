#!/usr/bin/env python3
"""Textbook RSA encryption for Task1 plaintext.

Usage:  python rsa_enc.py <plaintext> [public_key_file]

Default public key file is Task1/RSA_Public_Key.txt.
Prints "Ciphertext: <hex>", and writes Raw_Message.txt and Encrypted_Message.txt.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rsa_core

TASK1_DIR = Path(__file__).resolve().parents[2]


def main(argv: list[str]) -> int:
    if not 2 <= len(argv) <= 3:
        print("Usage: python rsa_enc.py <plaintext> [public_key_file]",
              file=sys.stderr)
        return 1

    plaintext = argv[1]
    public_key_file = argv[2] if len(argv) >= 3 else TASK1_DIR / "RSA_Public_Key.txt"

    n, e = rsa_core.read_public_key(public_key_file)
    message = rsa_core.bytes_to_int(plaintext.encode("utf-8"))
    if message >= n:
        print("plaintext is too large for this RSA key", file=sys.stderr)
        return 1

    ciphertext = rsa_core.rsa_encrypt_int(message, e, n)
    print("Ciphertext:", format(ciphertext, "x"))

    rsa_core.save_text(plaintext, TASK1_DIR / "Raw_Message.txt")
    rsa_core.save_ciphertext_hex(ciphertext, n.bit_length(),
                                 TASK1_DIR / "Encrypted_Message.txt")
    print("Plaintext and ciphertext have been saved to Raw_Message.txt / Encrypted_Message.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
