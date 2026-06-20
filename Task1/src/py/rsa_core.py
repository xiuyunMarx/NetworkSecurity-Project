"""Textbook RSA 核心库（Python 对照实现）。

与 Task1/src/cpp/rsa_utils.h 的 C++ 实现保持字节级一致，以便两版互相验证解密：
- 字节↔整数一律大端；
- 公钥文件 ``n e``、私钥文件 ``n d``（十进制、空格分隔、单行）；
- 1024-bit 密文固定 256 个小写十六进制字符，补前导零；
- 随机数使用 ``secrets``（密码学安全），不使用 ``random``。
"""

from __future__ import annotations

import secrets
from pathlib import Path

PUBLIC_EXPONENT = 65537

# 小素数筛，用于在 Miller–Rabin 之前快速排除合数。
_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251,
]


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """扩展欧几里得算法，返回 (g, x, y) 使得 a*x + b*y = g = gcd(a, b)。"""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def mod_inverse(a: int, modulus: int) -> int:
    """求 a 在模 modulus 下的乘法逆元。"""
    g, x, _ = egcd(a % modulus, modulus)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % modulus


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller–Rabin 素性测试，先做小素数筛。"""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # 将 n - 1 写成 d * 2^s，d 为奇数。
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)  # 2 <= a <= n - 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """生成一个 bits 位的素数，最高位与最低位置 1（保证位宽且为奇数）。"""
    while True:
        candidate = secrets.randbits(bits)
        candidate |= 1 << (bits - 1)
        candidate |= 1
        if is_probable_prime(candidate, 40):
            return candidate


def generate_rsa_keypair(bits: int = 1024) -> dict[str, int]:
    """生成 RSA 密钥对，保证 n 恰好为 bits 位。返回 {n, e, d, p, q}。"""
    e = PUBLIC_EXPONENT
    prime_bits = bits // 2
    while True:
        p = generate_prime(prime_bits)
        q = generate_prime(prime_bits)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if egcd(e, phi)[0] != 1:
            continue
        d = mod_inverse(e, phi)
        return {"n": n, "e": e, "d": d, "p": p, "q": q}


def rsa_encrypt_int(m: int, e: int, n: int) -> int:
    """Textbook RSA 加密：c = m^e mod n。"""
    if not 0 <= m < n:
        raise ValueError("message integer out of range [0, n)")
    return pow(m, e, n)


def rsa_decrypt_int(c: int, d: int, n: int) -> int:
    """Textbook RSA 解密：m = c^d mod n。"""
    if not 0 <= c < n:
        raise ValueError("ciphertext integer out of range [0, n)")
    return pow(c, d, n)


def bytes_to_int(data: bytes) -> int:
    """字节串转整数（大端），对应 C++ string_to_mpz。"""
    return int.from_bytes(data, "big")


def int_to_bytes(value: int) -> bytes:
    """整数转最小宽度字节串（大端，去高位前导零），对应 C++ mpz_to_string。"""
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def int_to_fixed_bytes(value: int, length: int) -> bytes:
    """整数转固定长度字节串（大端，左侧补零）。"""
    return value.to_bytes(length, "big")


def fixed_hex(value: int, bits: int) -> str:
    """以固定宽度小写十六进制表示（补前导零，不带 0x）。"""
    width = (bits + 3) // 4
    return format(value, "x").rjust(width, "0")


# --- 文件读写（格式严格对齐 C++ rsa_utils.h） -------------------------------

def save_decimal(value: int, path: str | Path) -> None:
    Path(path).write_text(f"{value}\n")


def save_text(text: str, path: str | Path) -> None:
    """保存原始文本明文，不追加换行（对应 C++ save_text）。"""
    Path(path).write_text(text, encoding="utf-8")


def save_public_key(n: int, e: int, path: str | Path) -> None:
    Path(path).write_text(f"{n} {e}\n")


def save_private_key(n: int, d: int, path: str | Path) -> None:
    Path(path).write_text(f"{n} {d}\n")


def save_ciphertext_hex(c: int, modulus_bits: int, path: str | Path) -> None:
    Path(path).write_text(fixed_hex(c, modulus_bits) + "\n")


def read_public_key(path: str | Path) -> tuple[int, int]:
    parts = Path(path).read_text().split()
    if len(parts) < 2:
        raise ValueError(f"failed to parse public key file: {path}")
    return int(parts[0]), int(parts[1])


def read_private_key(path: str | Path) -> tuple[int, int]:
    parts = Path(path).read_text().split()
    if len(parts) < 2:
        raise ValueError(f"failed to parse private key file: {path}")
    return int(parts[0]), int(parts[1])
