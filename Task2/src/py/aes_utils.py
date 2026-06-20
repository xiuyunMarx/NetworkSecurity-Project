"""AES-128-ECB + 手动 PKCS#7（Python 对照实现）。

指引要求自己实现 PKCS#7 padding，仅 AES 分组运算调用成熟库（pycryptodome）。
与 Task2/src/cpp/wup_cca2.cpp 的 OpenSSL EVP（自动 PKCS#7）结果字节级一致。
"""

from __future__ import annotations

from Crypto.Cipher import AES

BLOCK_SIZE = 16


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad = block_size - (len(data) % block_size)
    return data + bytes([pad]) * pad


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid PKCS#7 padded data length")
    pad = data[-1]
    if pad < 1 or pad > block_size:
        raise ValueError("invalid PKCS#7 padding value")
    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid PKCS#7 padding bytes")
    return data[:-pad]


def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(plaintext))


def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes | None:
    """解密并去 PKCS#7；失败（长度/填充非法）返回 None，对应 C++ 的 std::nullopt。"""
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        return None
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        return pkcs7_unpad(cipher.decrypt(ciphertext))
    except ValueError:
        return None
