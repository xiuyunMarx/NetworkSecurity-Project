import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rsa_core

# yrq 0627 存到Task1/
TASK1_DIR = Path(__file__).resolve().parents[2]


def main(argv: list[str]) -> int:
    key_size = 1024
    if len(argv) >= 2:
        key_size = int(argv[1])
        if key_size < 16 or key_size % 2 != 0:
            print("key_size_bits must be an even number >= 16", file=sys.stderr)
            return 1

    keys = rsa_core.generate_rsa_keypair(key_size)
    rsa_core.save_public_key(keys["n"], keys["e"], TASK1_DIR / "RSA_Public_Key.txt")
    rsa_core.save_private_key(keys["n"], keys["d"], TASK1_DIR / "RSA_Secret_Key.txt")
    rsa_core.save_decimal(keys["n"], TASK1_DIR / "RSA_Moduler.txt")
    rsa_core.save_decimal(keys["p"], TASK1_DIR / "RSA_p.txt")
    rsa_core.save_decimal(keys["q"], TASK1_DIR / "RSA_q.txt")
    print(f"RSA key generated: {keys['n'].bit_length()} bits")
    print("Public key, private key, modulus, and prime numbers have been saved to Task1/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
