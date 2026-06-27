import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[3] / "Task1" / "src" / "py"))
sys.path.insert(0, str(_HERE.parent))
import rsa_core
import oaep

TASK1_DIR = _HERE.parents[3] / "Task1"


def normalize_ciphertext(value: str) -> str:
    prefix = "Ciphertext:"
    if value.startswith(prefix):
        value = value[len(prefix):].strip()
    return value


def main(argv: list[str]) -> int:
    if not 2 <= len(argv) <= 5:
        print("Usage: python oaep_decode.py <ciphertext_hex> [k0_bits] [k1_bits] "
              "[private_key_file]", file=sys.stderr)
        return 1

    ciphertext_text = normalize_ciphertext(argv[1])
    k0 = int(argv[2]) if len(argv) >= 3 else oaep.DEFAULT_K0
    k1 = int(argv[3]) if len(argv) >= 4 else oaep.DEFAULT_K1
    private_key_file = argv[4] if len(argv) >= 5 else TASK1_DIR / "RSA_Secret_Key.txt"

    try:
        ciphertext = int(ciphertext_text, 16)
    except ValueError:
        print("ciphertext must be a hexadecimal integer", file=sys.stderr)
        return 1

    n, d = rsa_core.read_private_key(private_key_file)
    proto = oaep.Protocol(k0=k0, k1=k1, hash="sha512")
    n_bits = n.bit_length()
    x_bits = n_bits - proto.k0

    result = oaep.decrypt_message(ciphertext, d, n, proto)
    plaintext = rsa_core.int_to_bytes(result["message"]).decode("utf-8", errors="replace")

    print(f"RSA modulus bits: {n_bits}")
    print("OAEP encoded message:", rsa_core.fixed_hex(result["encoded"], n_bits))
    print("X:", rsa_core.fixed_hex(result["X"], x_bits))
    print("Y:", rsa_core.fixed_hex(result["Y"], proto.k0))
    print("Recovered r:", rsa_core.fixed_hex(result["r"], proto.k0))
    print("Recovered m00..0:", rsa_core.fixed_hex(result["padded"], x_bits))
    print("Plaintext:", plaintext)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
