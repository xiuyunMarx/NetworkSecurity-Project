"""教学版 RSA-OAEP（Python 对照实现）。

与 Task3/src/cpp/OAEP_utils.h 的 C++ 实现保持字节级一致：
- 参数 n=1024, k0=512, k1=64, 哈希 SHA-512；
- G(r) = MGF1("G", r 的固定 k0 位字节, n-k0 位)；
- H(X) = MGF1("H", X 的固定 n-k0 位字节, k0 位)；
- MGF1 计数器 4 字节大端，从 0 开始；
- 编码 padded = m << k1, X = padded ^ G(r), Y = r ^ H(X), EM = (X << k0) + Y；
- 编码后若 EM >= n 则重新采样 r（指引做法 A）。

全程在整数域运算，与 C++ 的 mpz 实现完全等价。
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

DEFAULT_K0 = 512
DEFAULT_K1 = 64

_HASHES = {"sha256": hashlib.sha256, "sha512": hashlib.sha512}


@dataclass
class Protocol:
    k0: int = DEFAULT_K0
    k1: int = DEFAULT_K1
    hash: str = "sha512"


def _bit_mask(bits: int) -> int:
    return (1 << bits) - 1 if bits > 0 else 0


def _byte_len_for_bits(bits: int) -> int:
    return (bits + 7) // 8


def to_fixed_width_bytes(value: int, bits: int) -> bytes:
    """整数转固定 bits 位宽的字节串（大端，左侧补零）。"""
    if value < 0:
        raise ValueError("negative values cannot be encoded as bit strings")
    if value.bit_length() > bits:
        raise ValueError("value is too large for the requested bit width")
    return value.to_bytes(_byte_len_for_bits(bits), "big")


def mgf1(label: str, seed: bytes, output_bits: int, hash_name: str) -> int:
    """MGF1：digest = Hash(label || seed || counter_be32)，拼接到 output_bits。"""
    hash_fn = _HASHES[hash_name]
    output_bytes = _byte_len_for_bits(output_bits)
    out = bytearray()
    counter = 0
    label_bytes = label.encode("ascii")
    while len(out) < output_bytes:
        block = label_bytes + seed + counter.to_bytes(4, "big")
        out += hash_fn(block).digest()
        counter += 1
    return int.from_bytes(bytes(out[:output_bytes]), "big") & _bit_mask(output_bits)


def G(r: int, n_bits: int, proto: Protocol) -> int:
    x_bits = n_bits - proto.k0
    return mgf1("G", to_fixed_width_bytes(r, proto.k0), x_bits, proto.hash)


def H(X: int, n_bits: int, proto: Protocol) -> int:
    x_bits = n_bits - proto.k0
    return mgf1("H", to_fixed_width_bytes(X, x_bits), proto.k0, proto.hash)


def _validate(n_bits: int, proto: Protocol) -> None:
    if n_bits <= 0:
        raise ValueError("n must be positive")
    if proto.k0 >= n_bits or proto.k1 >= n_bits - proto.k0:
        raise ValueError("k0 + k1 must be smaller than n")


def oaep_encode_int(message: int, n_bits: int, proto: Protocol, r: int) -> dict:
    """用给定 r 编码（确定性，用于互验/单测）。返回 {r, X, Y, encoded}。"""
    _validate(n_bits, proto)
    if message < 0:
        raise ValueError("message must be non-negative")
    if message.bit_length() > n_bits - proto.k0 - proto.k1:
        raise ValueError("message is too large for OAEP parameters")
    if r < 0 or r.bit_length() > proto.k0:
        raise ValueError("r is too large for k0 bits")

    padded = message << proto.k1
    X = padded ^ G(r, n_bits, proto)
    Y = r ^ H(X, n_bits, proto)
    encoded = (X << proto.k0) + Y
    return {"r": r, "X": X, "Y": Y, "encoded": encoded}


def oaep_encode_random(message: int, n_bits: int, proto: Protocol) -> dict:
    """随机采样 r 编码（r 取 k0 位密码学安全随机数）。"""
    r = int.from_bytes(secrets.token_bytes(_byte_len_for_bits(proto.k0)), "big")
    r &= _bit_mask(proto.k0)
    return oaep_encode_int(message, n_bits, proto, r)


def oaep_decode_int(encoded: int, n_bits: int, proto: Protocol) -> dict:
    """OAEP 解码并校验尾部 k1 零位。返回 {X, Y, r, padded, message}。"""
    _validate(n_bits, proto)
    if encoded < 0:
        raise ValueError("encoded message must be non-negative")
    if encoded.bit_length() > n_bits:
        raise ValueError("encoded message is too large for OAEP parameters")

    X = encoded >> proto.k0
    Y = encoded & _bit_mask(proto.k0)
    r = Y ^ H(X, n_bits, proto)
    padded = X ^ G(r, n_bits, proto)

    if (padded & _bit_mask(proto.k1)) != 0:
        raise ValueError("invalid OAEP padding: trailing k1 bits are not zero")
    message = padded >> proto.k1
    if message.bit_length() > n_bits - proto.k0 - proto.k1:
        raise ValueError("invalid OAEP padding: message field is too large")
    return {"X": X, "Y": Y, "r": r, "padded": padded, "message": message}


def encrypt_message(message_int: int, e: int, n: int, proto: Protocol,
                    max_attempts: int = 128) -> dict:
    """OAEP 编码 + RSA 加密。循环重采样 r 直到 EM < n。"""
    n_bits = n.bit_length()
    for _ in range(max_attempts):
        enc = oaep_encode_random(message_int, n_bits, proto)
        if enc["encoded"] < n:
            enc["ciphertext"] = pow(enc["encoded"], e, n)
            return enc
    raise RuntimeError("failed to sample an OAEP encoded message smaller than n")


def decrypt_message(ciphertext: int, d: int, n: int, proto: Protocol) -> dict:
    """RSA 解密 + OAEP 解码。返回 {..., encoded, message}。"""
    if not 0 <= ciphertext < n:
        raise ValueError("ciphertext is outside the RSA message space")
    encoded = pow(ciphertext, d, n)
    result = oaep_decode_int(encoded, n.bit_length(), proto)
    result["encoded"] = encoded
    return result
