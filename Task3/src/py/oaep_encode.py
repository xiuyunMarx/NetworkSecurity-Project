#!/usr/bin/env python3
"""RSA-OAEP encryption (educational version, default k0=512 k1=64 SHA-512).

Usage:  python oaep_encode.py <plaintext> [k0_bits] [k1_bits] [public_key_file]

Reuses the RSA public key from Task1. Output (written to Task3/ directory):
  Random_Number.txt        : OAEP random number r (k0 bits, 128 hex)
  Message_After_Padding.txt: Encoded block EM = X || Y (n bits, 256 hex)
  Encrypted_Message.txt    : RSA-OAEP ciphertext (n bits, 256 hex)
"""

import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[3] / "Task1" / "src" / "py"))
sys.path.insert(0, str(_HERE.parent))
import rsa_core
import oaep

TASK3_DIR = _HERE.parents[2]
TASK1_DIR = _HERE.parents[3] / "Task1"


def main(argv: list[str]) -> int:
    if not 2 <= len(argv) <= 5:
        print("Usage: python oaep_encode.py <plaintext> [k0_bits] [k1_bits] "
              "[public_key_file]", file=sys.stderr)
        return 1

    plaintext = argv[1]
    k0 = int(argv[2]) if len(argv) >= 3 else oaep.DEFAULT_K0
    k1 = int(argv[3]) if len(argv) >= 4 else oaep.DEFAULT_K1
    public_key_file = argv[4] if len(argv) >= 5 else TASK1_DIR / "RSA_Public_Key.txt"

    n, e = rsa_core.read_public_key(public_key_file)
    proto = oaep.Protocol(k0=k0, k1=k1, hash="sha512")
    n_bits = n.bit_length()

    message_int = rsa_core.bytes_to_int(plaintext.encode("utf-8"))
    result = oaep.encrypt_message(message_int, e, n, proto)

    x_bits = n_bits - proto.k0
    print(f"RSA modulus bits: {n_bits}")
    print(f"Message capacity bits: {n_bits - proto.k0 - proto.k1}")
    print("r:", rsa_core.fixed_hex(result["r"], proto.k0))
    print("X:", rsa_core.fixed_hex(result["X"], x_bits))
    print("Y:", rsa_core.fixed_hex(result["Y"], proto.k0))
    print("OAEP encoded message:", rsa_core.fixed_hex(result["encoded"], n_bits))
    print("Ciphertext:", format(result["ciphertext"], "x"))

    (TASK3_DIR / "Random_Number.txt").write_text(
        rsa_core.fixed_hex(result["r"], proto.k0) + "\n")
    (TASK3_DIR / "Message_After_Padding.txt").write_text(
        rsa_core.fixed_hex(result["encoded"], n_bits) + "\n")
    (TASK3_DIR / "Encrypted_Message.txt").write_text(
        rsa_core.fixed_hex(result["ciphertext"], n_bits) + "\n")
    print("outputs written to Task3/Random_Number.txt, "
          "Message_After_Padding.txt, Encrypted_Message.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
