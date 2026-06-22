"""AES-128-ECB + manual PKCS#7 (Python reference implementation).

The guidelines require implementing PKCS#7 padding manually, using a mature library (pycryptodome) only for AES block operations.
Maintains byte-level consistency with the OpenSSL EVP (automatic PKCS#7) results in Task2/src/cpp/wup_cca2.cpp.
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
    """Decrypt and remove PKCS#7 padding; returns None on failure (invalid length/padding), corresponding to std::nullopt in C++."""
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        return None
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        return pkcs7_unpad(cipher.decrypt(ciphertext))
    except ValueError:
        return None
