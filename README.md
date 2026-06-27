# Network Security Project

Three tasks built around textbook RSA:

- **Task 1** – textbook RSA: 1024-bit key generation, encryption, and decryption.
- **Task 2** – a WUP protocol plus a bit-by-bit CCA2 attack that recovers a 128-bit AES session key from textbook RSA using only an accept/reject oracle (reproducing the QQ Browser attack from Knockel et al. 2018, §4.1).
- **Task 3** – a teaching version of RSA-OAEP that defends against the Task 2 attack.

Every task is implemented twice, once in **C++** (GMP + OpenSSL) and once in **Python** (hand-written big-integer crypto, pycryptodome only for the AES block cipher). The two versions read and write the same file formats.

## Directory layout

```
Task1/   textbook RSA
Task2/   WUP protocol + bit-by-bit CCA2 attack
Task3/   teaching RSA-OAEP
README.md
```

Inside every task:

```
TaskN/
├── src/
│   ├── cpp/     C++ source, Makefile, and the compiled binaries
│   └── py/      Python source
└── *.txt        the result files produced when you run the task
```

Result files are written to the task root (for example `Task1/RSA_Moduler.txt`).

**Dependencies between tasks.** Task 2 and Task 3 reuse Task 1's RSA core, so all three `src/` trees must stay in place:

- Task 2 / Task 3 C++ `#include` Task 1's `rsa_utils.h`.
- Task 2 / Task 3 Python `import` Task 1's `rsa_core.py`.
- Task 3 encrypts under the key pair produced by Task 1, so **run Task 1 first**.

## Environment

Tested with:

- Python 3.10
- g++ 12.2 (`-std=c++17`)
- GMP (`libgmp` / `libgmpxx`) – big integers in C++
- OpenSSL 3.x – AES, SHA-512, and `RAND_bytes` in C++
- pycryptodome – the AES block cipher in the Python version

The simplest setup is one conda environment, which puts the GMP and OpenSSL headers/libraries on the compiler path automatically:

```bash
conda create -y -n nsec-proj -c conda-forge python=3.10 gmp openssl make
conda activate nsec-proj
pip install pycryptodome
```

After `conda activate nsec-proj` the environment's `include` and `lib` are added to `CPATH` / `LIBRARY_PATH` / `LD_LIBRARY_PATH`, so the Makefiles need no `-I` / `-L` flags. If you build outside conda, install the GMP and OpenSSL development packages and make sure g++ can find their headers and libraries.

The Python version only needs `pycryptodome`; everything else (Miller-Rabin, modular inverse, RSA, OAEP, the attack) is written by hand.

## Build the C++ version

```bash
make -C Task1/src/cpp
make -C Task2/src/cpp
make -C Task3/src/cpp
```

The Python version needs no build step. Run the C++ tools from inside their `src/cpp` directory and the Python tools from inside their `src/py` directory, as shown below.

---

## Task 1 – textbook RSA

### Source files

| File | Role |
|------|------|
| `src/cpp/rsa_utils.h` | RSA core: Miller-Rabin, key generation, encrypt/decrypt, file I/O. Shared by all C++ tasks. |
| `src/cpp/keygen.cpp` → `keygen` | generate a 1024-bit key pair and write the key/prime/modulus files |
| `src/cpp/rsa_enc.cpp` → `rsa_enc` | encrypt a plaintext string |
| `src/cpp/rsa_dec.cpp` → `rsa_dec` | decrypt a hex ciphertext |
| `src/py/rsa_core.py` | the same RSA core in Python. Shared by all Python tasks. |
| `src/py/keygen.py` | generate a key pair |
| `src/py/rsa_enc.py` | encrypt |
| `src/py/rsa_dec.py` | decrypt |

### Usage

C++:

```bash
cd Task1/src/cpp
./keygen 1024
./rsa_enc "Network Security 网络安全 test"
./rsa_dec <ciphertext_hex>
```

Python:

```bash
cd Task1/src/py
python keygen.py 1024
python rsa_enc.py "Network Security 网络安全 test"
python rsa_dec.py <ciphertext_hex>
```

`rsa_dec` also accepts the full `Ciphertext: <hex>` line printed by `rsa_enc`, so you can paste it directly. The public exponent is fixed at `e = 65537`.

### Result files (written to `Task1/`)

| File | Content |
|------|---------|
| `RSA_Moduler.txt` | modulus `n`, decimal |
| `RSA_p.txt` | prime `p`, decimal |
| `RSA_q.txt` | prime `q`, decimal |
| `RSA_Public_Key.txt` | one line `n e` (decimal, space separated) |
| `RSA_Secret_Key.txt` | one line `n d` (decimal, space separated) |
| `Raw_Message.txt` | the plaintext, UTF-8, no trailing newline |
| `Encrypted_Message.txt` | ciphertext, 256 lowercase hex chars (zero-padded to the modulus width) |

---

## Task 2 – WUP protocol and CCA2 attack

### Source files

| File | Role |
|------|------|
| `src/cpp/wup_cca2.cpp` → `wup_cca2` | the whole experiment: builds an RSA key, plays client/server/attacker, recovers the AES key bit by bit, and writes all result files |
| `src/py/wup.py` | build a WUP request and check whether a decrypted blob is a valid WUP message |
| `src/py/aes_utils.py` | AES-128-ECB with hand-written PKCS#7 padding |
| `src/py/wup_cca2.py` | the same experiment in Python |

### Usage

C++:

```bash
cd Task2/src/cpp
./wup_cca2
```

Python:

```bash
cd Task2/src/py
python wup_cca2.py
```

Each run is self-contained: it generates its own 1024-bit RSA key, recovers the 128-bit AES key in 128 oracle queries, and decrypts the captured WUP request.

**How the attack works.** The client encrypts a 128-bit AES key with textbook RSA and sends an AES-128-ECB encrypted WUP request. The server decrypts the RSA ciphertext, keeps only the **low 128 bits** as the AES key (the QQ Browser behaviour the paper describes), decrypts the request, and replies only if it is a valid WUP message — that accept/reject answer is the oracle. For target bit `i` the attacker multiplies the captured ciphertext by `(2^(127-i))^e mod n`, which shifts the wanted bit into the top position of the recovered key; comparing the oracle's answer against a guess of `0` reveals the bit (accept → `0`, reject → `1`). The attacker only ever sees the public key and the oracle, never the private key or the real AES key.

A WUP request is valid if it starts with `WUP/1`, contains `cmd=`, and ends with `END`.

### Result files (written to `Task2/`)

| File | Content |
|------|---------|
| `AES_Key.txt` | the real 128-bit AES key, 32 lowercase hex chars |
| `WUP_Request.txt` | the raw WUP request bytes, hex |
| `AES_Encrypted_WUP.txt` | the AES-ECB ciphertext of the request, hex |
| `History_Message.txt` | the captured history: `rsa_n_hex`, `rsa_e_dec`, `rsa_encrypted_aes_key_hex`, `aes_encrypted_wup_request_hex` |
| `attack_log.txt` | one block per round (target bit, shift, transformed ciphertext, candidate key, oracle result, recovered bit) followed by a summary (real key, recovered key, `keys_match`, decrypted WUP, query count) |

---

## Task 3 – teaching RSA-OAEP

### Source files

| File | Role |
|------|------|
| `src/cpp/OAEP_utils.h` | OAEP core: MGF1, the `G` / `H` masks, encode/decode, encrypt/decrypt |
| `src/cpp/OAEP_encoding.cpp` → `OAEP_encoding` | OAEP-encode a plaintext and RSA-encrypt it |
| `src/cpp/OAEP_decoding.cpp` → `OAEP_decoding` | RSA-decrypt and OAEP-decode a ciphertext |
| `src/cpp/OAEP_cca2_demo.cpp` → `OAEP_cca2_demo` | bonus: forges a ciphertext the Task 2 way and shows OAEP rejecting it |
| `src/py/oaep.py` | the OAEP core in Python |
| `src/py/oaep_encode.py` | OAEP-encode + encrypt |
| `src/py/oaep_decode.py` | decrypt + OAEP-decode |

### Usage

Run Task 1 first; Task 3 reuses `Task1/RSA_Public_Key.txt` and `Task1/RSA_Secret_Key.txt`.

C++:

```bash
cd Task3/src/cpp
./OAEP_encoding "Network Security 网络安全 test"
./OAEP_decoding <ciphertext_hex>
./OAEP_cca2_demo <ciphertext_hex>     # bonus: shows the CCA2 attack failing
```

Python:

```bash
cd Task3/src/py
python oaep_encode.py "Network Security 网络安全 test"
python oaep_decode.py <ciphertext_hex>
```

The optional trailing arguments are `k0`, `k1`, and the key file; the defaults are `512`, `64`, and the Task 1 key.

**Parameters.** `n = 1024`, `k0 = 512`, `k1 = 64`, hash `SHA-512`. So `r`, `X`, and `Y` are each 512 bits and the encoded block `EM = X || Y` is 1024 bits. The encoding is

```
X  = (m || 0^k1) XOR G(r)
Y  = r XOR H(X)
EM = X || Y
```

`G` and `H` are MGF1 over SHA-512 with the labels `"G"` and `"H"` for domain separation (4-byte big-endian counter starting at 0). Because a random `EM` can exceed the modulus, `r` is resampled until `EM < n`. On decode the trailing `k1` bits are checked to be zero, otherwise the block is rejected — which is why the Task 2 multiplicative attack no longer works.

### Result files (written to `Task3/`)

| File | Content |
|------|---------|
| `Random_Number.txt` | the OAEP random `r`, 128 hex chars (512 bits) |
| `Message_After_Padding.txt` | the encoded block `EM = X \|\| Y`, 256 hex chars (1024 bits) |
| `Encrypted_Message.txt` | the RSA-OAEP ciphertext, 256 hex chars |

---

## Output file conventions

- All hex is lowercase with no `0x` prefix.
- Bytes map to integers big-endian.
- RSA ciphertext and OAEP blocks are zero-padded to the full modulus width
  (256 hex chars for a 1024-bit key).
- `RSA_*` parameter files are decimal; every other file is hex.
- The public key file is `n e`; the secret key file is `n d`.
