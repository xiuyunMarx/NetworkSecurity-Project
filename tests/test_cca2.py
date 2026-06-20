"""Task 2: WUP protocol, AES helpers, and the bit-by-bit CCA2 attack."""

import importlib.util
import secrets

import pytest
from Crypto.Cipher import AES

from conftest import TASK2_PY


def _load_wup_cca2(rsa_core):
    """Load wup_cca2.py with its sibling modules already importable."""
    # aes_utils and wup live next to it; conftest put TASK2_PY on sys.path
    spec = importlib.util.spec_from_file_location(
        "wup_cca2", TASK2_PY / "wup_cca2.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- AES + PKCS#7 ----------------------------------------------------------

def test_pkcs7_roundtrip(aes_utils):
    for length in range(0, 40):
        data = b"x" * length
        padded = aes_utils.pkcs7_pad(data)
        assert len(padded) % 16 == 0
        assert aes_utils.pkcs7_unpad(padded) == data


def test_aes_ecb_roundtrip(aes_utils):
    key = secrets.token_bytes(16)
    msg = b"WUP/1\ncmd=sync\nEND\n"
    ct = aes_utils.aes_ecb_encrypt(key, msg)
    assert aes_utils.aes_ecb_decrypt(key, ct) == msg


def test_aes_matches_pycryptodome(aes_utils):
    # cross-check our manual PKCS#7 + ECB against the library
    key = secrets.token_bytes(16)
    msg = b"browser-history-demo payload"
    ours = aes_utils.aes_ecb_encrypt(key, msg)
    ref = AES.new(key, AES.MODE_ECB).encrypt(aes_utils.pkcs7_pad(msg))
    assert ours == ref


def test_aes_decrypt_wrong_key_returns_none(aes_utils):
    key = secrets.token_bytes(16)
    ct = aes_utils.aes_ecb_encrypt(key, b"WUP/1\ncmd=sync\nEND\n")
    # a different key almost always breaks PKCS#7 -> None
    others = [aes_utils.aes_ecb_decrypt(secrets.token_bytes(16), ct)
              for _ in range(20)]
    assert any(o is None for o in others)


# --- WUP format ------------------------------------------------------------

def test_valid_wup_accepts_real_request():
    import wup
    assert wup.valid_wup(wup.build_wup_request("20260616"))


def test_valid_wup_rejects_garbage():
    import wup
    assert not wup.valid_wup(b"not a wup request")
    assert not wup.valid_wup(b"WUP/1\ncmd=sync\n")  # missing END


# --- server oracle ---------------------------------------------------------

def test_oracle_accepts_correct_key(rsa_core, keypair):
    mod = _load_wup_cca2(rsa_core)
    server = mod.WUPServer(keypair["n"], keypair["e"], keypair["d"])
    import wup, aes_utils
    key = secrets.token_bytes(16)
    rsa_ct = rsa_core.rsa_encrypt_int(rsa_core.bytes_to_int(key),
                                      keypair["e"], keypair["n"])
    aes_ct = aes_utils.aes_ecb_encrypt(key, wup.build_wup_request("x"))
    assert server.query(rsa_ct, aes_ct) is True


def test_oracle_rejects_wrong_key(rsa_core, keypair):
    mod = _load_wup_cca2(rsa_core)
    server = mod.WUPServer(keypair["n"], keypair["e"], keypair["d"])
    import wup, aes_utils
    real = secrets.token_bytes(16)
    rsa_ct = rsa_core.rsa_encrypt_int(rsa_core.bytes_to_int(real),
                                      keypair["e"], keypair["n"])
    wrong = secrets.token_bytes(16)
    aes_ct = aes_utils.aes_ecb_encrypt(wrong, wup.build_wup_request("x"))
    assert server.query(rsa_ct, aes_ct) is False


def test_attacker_does_not_hold_private_key(rsa_core, keypair):
    mod = _load_wup_cca2(rsa_core)
    server = mod.WUPServer(keypair["n"], keypair["e"], keypair["d"])
    attacker = mod.CCA2Attacker(server.public_key, server.query, 12345)
    # the attacker only knows n and e, never d or the real key
    assert keypair["d"] not in vars(attacker).values()
    assert keypair["d"] != getattr(attacker, "_e", None)


# --- full attack -----------------------------------------------------------

def test_full_key_recovery(rsa_core, keypair):
    mod = _load_wup_cca2(rsa_core)
    import wup, aes_utils
    server = mod.WUPServer(keypair["n"], keypair["e"], keypair["d"])

    aes_key = secrets.token_bytes(16)
    request = wup.build_wup_request("20260616")
    rsa_ct = rsa_core.rsa_encrypt_int(rsa_core.bytes_to_int(aes_key),
                                      keypair["e"], keypair["n"])
    aes_ct = aes_utils.aes_ecb_encrypt(aes_key, request)

    attacker = mod.CCA2Attacker(server.public_key, server.query, rsa_ct)
    log = []
    recovered, queries = attacker.recover_key(log)
    recovered_key = mod.low128_bytes(recovered)

    assert recovered_key == aes_key
    assert queries == 128
    assert aes_utils.aes_ecb_decrypt(recovered_key, aes_ct) == request
    assert len([line for line in log if line.startswith("[Round")]) == 128
