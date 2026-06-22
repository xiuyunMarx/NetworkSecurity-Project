"""Task 3: teaching-version RSA-OAEP correctness and interoperability."""

import pytest

from conftest import TASK3_CPP, grep, make, requires_cpp, run

K0 = 512
K1 = 64
N_BITS = 1024


def test_block_sizes(oaep, rsa_core, keypair):
    proto = oaep.Protocol(K0, K1, "sha512")
    enc = oaep.encrypt_message(rsa_core.bytes_to_int(b"hi"),
                               keypair["e"], keypair["n"], proto)
    # r is k0 bits, X and Y are k0 bits each, EM is n bits, EM < n
    assert len(rsa_core.fixed_hex(enc["r"], K0)) == K0 // 4
    assert len(rsa_core.fixed_hex(enc["X"], N_BITS - K0)) == (N_BITS - K0) // 4
    assert len(rsa_core.fixed_hex(enc["Y"], K0)) == K0 // 4
    assert len(rsa_core.fixed_hex(enc["encoded"], N_BITS)) == N_BITS // 4
    assert enc["encoded"] < keypair["n"]


def test_encode_decode_roundtrip(oaep, rsa_core):
    proto = oaep.Protocol(K0, K1, "sha512")
    msg = rsa_core.bytes_to_int(b"Network Security Project - Demo")
    r = (1 << (K0 - 1)) | 12345  # fixed r keeps the test deterministic
    enc = oaep.oaep_encode_int(msg, N_BITS, proto, r)
    dec = oaep.oaep_decode_int(enc["encoded"], N_BITS, proto)
    assert dec["message"] == msg
    assert dec["r"] == r


def test_decrypt_roundtrip(oaep, rsa_core, keypair):
    proto = oaep.Protocol(K0, K1, "sha512")
    msg = b"hello oaep"
    enc = oaep.encrypt_message(rsa_core.bytes_to_int(msg),
                               keypair["e"], keypair["n"], proto)
    dec = oaep.decrypt_message(enc["ciphertext"], keypair["d"],
                               keypair["n"], proto)
    assert rsa_core.int_to_bytes(dec["message"]) == msg


def test_trailing_zero_bits_present(oaep, rsa_core):
    proto = oaep.Protocol(K0, K1, "sha512")
    msg = rsa_core.bytes_to_int(b"abc")
    enc = oaep.oaep_encode_int(msg, N_BITS, proto, 7)
    dec = oaep.oaep_decode_int(enc["encoded"], N_BITS, proto)
    assert (dec["padded"] & ((1 << K1) - 1)) == 0
    assert dec["padded"] == msg << K1


def test_single_bit_tamper_rejected(oaep, rsa_core):
    proto = oaep.Protocol(K0, K1, "sha512")
    enc = oaep.oaep_encode_int(rsa_core.bytes_to_int(b"abc"), N_BITS, proto, 9)
    rejected = 0
    for i in range(0, N_BITS, 7):  # sample bits across the block
        try:
            oaep.oaep_decode_int(enc["encoded"] ^ (1 << i), N_BITS, proto)
        except ValueError:
            rejected += 1
    assert rejected == len(range(0, N_BITS, 7))


def test_different_r_gives_different_ciphertext(oaep, rsa_core, keypair):
    proto = oaep.Protocol(K0, K1, "sha512")
    m = rsa_core.bytes_to_int(b"same message")
    a = oaep.encrypt_message(m, keypair["e"], keypair["n"], proto)
    b = oaep.encrypt_message(m, keypair["e"], keypair["n"], proto)
    assert a["ciphertext"] != b["ciphertext"]  # randomized padding


@requires_cpp
def test_cpp_python_interop(tmp_path, oaep, rsa_core, keypair):
    """Python-encoded OAEP ciphertext must decode correctly in the C++ tool.

    This proves the G/H/MGF1 definitions and the X||Y layout match byte for
    byte across the two implementations. The C++ decoder only reads, so this
    does not touch the tracked Task3 output files.
    """
    make(TASK3_CPP)

    sec = tmp_path / "sec.txt"
    rsa_core.save_private_key(keypair["n"], keypair["d"], sec)

    msg = "Network Security Project - Demo"
    proto = oaep.Protocol(K0, K1, "sha512")
    enc = oaep.encrypt_message(rsa_core.bytes_to_int(msg.encode()),
                               keypair["e"], keypair["n"], proto)
    ct_hex = rsa_core.fixed_hex(enc["ciphertext"], N_BITS)

    out = run(["./OAEP_decoding", ct_hex, "512", "64", str(sec)], cwd=TASK3_CPP)
    assert grep(out, "Plaintext:") == msg
