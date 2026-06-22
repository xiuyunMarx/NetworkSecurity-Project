"""Task 1: textbook RSA correctness and C++/Python interoperability."""

from math import gcd

from Crypto.PublicKey import RSA
from Crypto.Util.number import isPrime

from conftest import (TASK1_CPP, TASK1_PY, grep, make, requires_cpp, run)

E = 65537


# --- key generation -------------------------------------------------------

def test_primes_are_prime(keypair):
    # cross-check our Miller-Rabin against pycryptodome's primality test
    assert isPrime(keypair["p"])
    assert isPrime(keypair["q"])


def test_distinct_primes(keypair):
    assert keypair["p"] != keypair["q"]


def test_modulus_is_1024_bits(keypair):
    assert keypair["n"].bit_length() == 1024
    assert keypair["n"] == keypair["p"] * keypair["q"]


def test_exponents_consistent(keypair):
    phi = (keypair["p"] - 1) * (keypair["q"] - 1)
    assert gcd(E, phi) == 1
    assert (E * keypair["d"]) % phi == 1
    assert keypair["e"] == E


def test_our_keypair_loads_in_pycryptodome(keypair):
    # if pycryptodome accepts (n, e, d), the key really is a valid RSA key
    key = RSA.construct((keypair["n"], keypair["e"], keypair["d"]))
    assert key.n == keypair["n"]


# --- encrypt / decrypt round trip -----------------------------------------

def test_roundtrip_ascii(rsa_core, keypair):
    msg = b"Network Security Project - Demo"
    m = rsa_core.bytes_to_int(msg)
    c = rsa_core.rsa_encrypt_int(m, keypair["e"], keypair["n"])
    back = rsa_core.rsa_decrypt_int(c, keypair["d"], keypair["n"])
    assert rsa_core.int_to_bytes(back) == msg


def test_roundtrip_utf8(rsa_core, keypair):
    msg = "网络安全 Network Security".encode("utf-8")
    m = rsa_core.bytes_to_int(msg)
    c = rsa_core.rsa_encrypt_int(m, keypair["e"], keypair["n"])
    back = rsa_core.rsa_decrypt_int(c, keypair["d"], keypair["n"])
    assert rsa_core.int_to_bytes(back) == msg


def test_roundtrip_single_byte(rsa_core, keypair):
    m = rsa_core.bytes_to_int(b"A")
    c = rsa_core.rsa_encrypt_int(m, keypair["e"], keypair["n"])
    assert rsa_core.rsa_decrypt_int(c, keypair["d"], keypair["n"]) == m


def test_roundtrip_max_message(rsa_core, keypair):
    m = keypair["n"] - 1
    c = rsa_core.rsa_encrypt_int(m, keypair["e"], keypair["n"])
    assert rsa_core.rsa_decrypt_int(c, keypair["d"], keypair["n"]) == m


def test_message_must_be_below_modulus(rsa_core, keypair):
    import pytest
    with pytest.raises(ValueError):
        rsa_core.rsa_encrypt_int(keypair["n"], keypair["e"], keypair["n"])


def test_matches_pycryptodome_rsa(rsa_core, keypair):
    # textbook RSA is deterministic, so a raw m^e mod n must match
    m = rsa_core.bytes_to_int(b"check against library")
    ours = rsa_core.rsa_encrypt_int(m, keypair["e"], keypair["n"])
    theirs = pow(m, keypair["e"], keypair["n"])
    assert ours == theirs


# --- output file format ----------------------------------------------------

def test_fixed_hex_width(rsa_core):
    assert len(rsa_core.fixed_hex(1, 1024)) == 256
    assert rsa_core.fixed_hex(255, 1024)[-2:] == "ff"
    assert set(rsa_core.fixed_hex(2 ** 600, 1024)) <= set("0123456789abcdef")


# --- cross-language interoperability with the C++ build --------------------

@requires_cpp
def test_cpp_python_interop(tmp_path, rsa_core):
    """C++ and Python must produce identical ciphertext and decrypt each other."""
    make(TASK1_CPP)

    # generate a key pair with the C++ tool into a scratch location
    pub = tmp_path / "RSA_Public_Key.txt"
    sec = tmp_path / "RSA_Secret_Key.txt"
    run(["./keygen", "1024", str(pub), str(sec)], cwd=TASK1_CPP)

    msg = "Network Security Project - Demo"
    n, e = rsa_core.read_public_key(pub)

    # Python encrypts under the C++ key
    m = rsa_core.bytes_to_int(msg.encode())
    py_c = rsa_core.rsa_encrypt_int(m, e, n)
    py_hex = rsa_core.fixed_hex(py_c, 1024)

    # C++ encrypts the same message under the same key
    cpp_out = run(["./rsa_enc", msg, str(pub)], cwd=TASK1_CPP)
    cpp_hex = rsa_core.fixed_hex(int(grep(cpp_out, "Ciphertext:"), 16), 1024)

    # textbook RSA is deterministic -> byte-identical ciphertext
    assert py_hex == cpp_hex

    # C++ decrypts the Python ciphertext
    dec = run(["./rsa_dec", py_hex, str(sec)], cwd=TASK1_CPP)
    assert grep(dec, "Plaintext:") == msg
