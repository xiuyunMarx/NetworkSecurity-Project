#!/usr/bin/env python3
"""生成 1024-bit Textbook RSA 密钥对并写出 Task1 要求的参数文件。

用法:  python keygen.py [key_size_bits]   (默认 1024)

输出（写到 Task1/ 目录）:
  RSA_Moduler.txt / RSA_p.txt / RSA_q.txt  : 十进制
  RSA_Public_Key.txt                       : "n e"
  RSA_Secret_Key.txt                       : "n d"
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rsa_core

# Task1/src/py/keygen.py -> Task1/
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
    print("公钥、私钥、模数与素数已保存到 Task1/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
