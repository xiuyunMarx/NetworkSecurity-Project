#!/usr/bin/env python3
"""Task2: WUP protocol + bit-by-bit CCA2 attack (reproducing Knockel et al. 2018 §4.1).

Workflow:
  1. Server generates its own 1024-bit RSA key;
  2. Client generates a 128-bit AES session key, encrypts it with RSA, and uses it to encrypt a WUP request via AES-128-ECB;
  3. Generate historical messages (RSA ciphertext + AES ciphertext);
  4. Attacker recovers the AES key bit-by-bit using only the public key, historical messages, and the server's ACCEPT/REJECT oracle;
  5. Decrypt the historical WUP using the recovered key.

Output (written to Task2/ directory):
  AES_Key.txt / WUP_Request.txt / AES_Encrypted_WUP.txt / History_Message.txt / attack_log.txt
"""

import secrets
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[3] / "Task1" / "src" / "py"))
sys.path.insert(0, str(_HERE.parent))
import rsa_core
import aes_utils
from wup import build_wup_request, valid_wup

TASK2_DIR = _HERE.parents[2]
PROBE_NONCE = "cca2-probe"


def low128_bytes(value: int) -> bytes:
    """Take the lowest 128 bits of the integer, exporting as 16 bytes (big-endian, right-aligned keeping leading zeros)."""
    return (value & ((1 << 128) - 1)).to_bytes(16, "big")


class WUPServer:
    """Holds the RSA private key and exposes only the ACCEPT/REJECT oracle query()->bool.

    Reproduces the key behavior of QQ Browser: after RSA decryption, only the lowest 128 bits are taken as the AES session key.
    """

    def __init__(self, n: int, e: int, d: int):
        self._n = n
        self._e = e
        self._d = d

    @property
    def public_key(self) -> tuple[int, int]:
        return self._n, self._e

    def query(self, rsa_ciphertext: int, aes_ciphertext: bytes) -> bool:
        rsa_plain = rsa_core.rsa_decrypt_int(rsa_ciphertext, self._d, self._n)
        key = low128_bytes(rsa_plain)
        request = aes_utils.aes_ecb_decrypt(key, aes_ciphertext)
        return request is not None and valid_wup(request)


class CCA2Attacker:
    """Only holds the public key and oracle callback, without access to the private key d or the actual AES key."""

    def __init__(self, public_key: tuple[int, int], oracle, victim_rsa_ct: int):
        self._n, self._e = public_key
        self._oracle = oracle
        self._victim_c = victim_rsa_ct
        self._probe = build_wup_request(PROBE_NONCE)

    def recover_key(self, log_lines: list[str]) -> tuple[int, int]:
        known = 0
        query_count = 0
        for bit in range(128):
            shift = 127 - bit
            factor = rsa_core.rsa_encrypt_int(1 << shift, self._e, self._n)
            shifted_rsa = self._victim_c * factor % self._n
            known_before = known

            guess_zero_key = low128_bytes(known << shift)
            encrypted_probe = aes_utils.aes_ecb_encrypt(guess_zero_key, self._probe)

            accepted = self._oracle(shifted_rsa, encrypted_probe)
            query_count += 1
            recovered_bit = 0 if accepted else 1
            if not accepted:
                known |= 1 << bit

            log_lines.append(
                f"[Round {bit + 1:03d}]\n"
                f"target_original_bit={bit}\n"
                f"shift={shift}\n"
                f"transformed_rsa_ciphertext={format(shifted_rsa, 'x')}\n"
                f"known_low_bits_before=0x{format(known_before, 'x')}\n"
                f"candidate_bit=0\n"
                f"candidate_server_key={guess_zero_key.hex()}\n"
                f"oracle_result={'ACCEPT' if accepted else 'REJECT'}\n"
                f"recovered_bit={recovered_bit}\n"
                f"known_low_bits_after=0x{format(known, 'x')}\n"
            )
            if (bit + 1) % 16 == 0:
                print(f"recovered {bit + 1}/128 bits")
        return known, query_count

def main() -> int:
    keys = rsa_core.generate_rsa_keypair(1024)
    n, e, d = keys["n"], keys["e"], keys["d"]
    server = WUPServer(n, e, d)

    # --- Client: Generate session key and historical messages ---
    aes_key = secrets.token_bytes(16)
    plain_request = build_wup_request("20260616")
    rsa_ct = rsa_core.rsa_encrypt_int(rsa_core.bytes_to_int(aes_key), e, n)
    encrypted_request = aes_utils.aes_ecb_encrypt(aes_key, plain_request)

    (TASK2_DIR / "AES_Key.txt").write_text(aes_key.hex() + "\n")
    (TASK2_DIR / "WUP_Request.txt").write_text(plain_request.hex() + "\n")
    (TASK2_DIR / "AES_Encrypted_WUP.txt").write_text(encrypted_request.hex() + "\n")
    (TASK2_DIR / "History_Message.txt").write_text(
        f"rsa_n_hex={format(n, 'x')}\n"
        f"rsa_e_dec={e}\n"
        f"rsa_encrypted_aes_key_hex={format(rsa_ct, 'x')}\n"
        f"aes_encrypted_wup_request_hex={encrypted_request.hex()}\n"
    )
    print("history written to History_Message.txt")
    print(f"RSA-encrypted AES key: {format(rsa_ct, 'x')}")
    print(f"AES-encrypted WUP request: {encrypted_request.hex()}\n")

    # --- Attacker: Recover key using only the public key + oracle ---
    attacker = CCA2Attacker(server.public_key, server.query, rsa_ct)
    log_lines: list[str] = []
    recovered, query_count = attacker.recover_key(log_lines)
    recovered_key = low128_bytes(recovered)

    recovered_request = aes_utils.aes_ecb_decrypt(recovered_key, encrypted_request)
    recovered_plaintext = (
        recovered_request.decode("utf-8", errors="replace")
        if recovered_request is not None else ""
    )
    keys_match = recovered_key == aes_key

    log_lines.append(
        f"\nactual_aes_key={aes_key.hex()}\n"
        f"recovered_aes_key={recovered_key.hex()}\n"
        f"keys_match={'true' if keys_match else 'false'}\n"
        f"history_wup_plaintext={recovered_plaintext}"
        f"query_count={query_count}\n"
    )
    (TASK2_DIR / "attack_log.txt").write_text("\n".join(log_lines))

    print(f"\nactual AES key:    {aes_key.hex()}")
    print(f"recovered AES key: {recovered_key.hex()}")
    print(f"keys_match: {keys_match}")
    print(f"query_count: {query_count}")
    print("decrypted historical request:")
    print(recovered_plaintext)
    return 0 if keys_match else 1


if __name__ == "__main__":
    raise SystemExit(main())
