# Network Security Project

Textbook RSA, the bit-by-bit CCA2 attack against it, and a teaching version of
RSA-OAEP. Each task is implemented twice, once in C++ and once in Python, and
the two versions produce the same output files so they can decrypt each other.

The attack experiments here are only run against our own local code.

## Layout

```
Task1/   textbook RSA (key generation, encrypt, decrypt)
Task2/   WUP protocol + bit-by-bit CCA2 attack
Task3/   RSA-OAEP
tests/   self-checks, not part of the submission
legacy/  earlier standalone prototypes, kept for reference
```

Inside each task, `src/cpp/` holds the C++ version and `src/py/` holds the
Python version. The required output files (`RSA_Moduler.txt`, `AES_Key.txt`,
etc.) are written to the task root, e.g. `Task1/RSA_Moduler.txt`.

## Environment

Tested with:

- Python 3.10.20
- g++ 12.2.0, built with `-std=c++17`
- GMP (libgmp / libgmpxx) for big integers
- OpenSSL 3.6.x for AES, SHA, and `RAND_bytes`
- pycryptodome 3.23.0 (Python AES only)
- pytest 9.1.1 (tests only)

We manage everything with one conda environment so that the GMP and OpenSSL
headers/libraries are on the compiler path automatically:

```bash
conda create -y -n nsec-proj -c conda-forge python=3.10 gmp openssl make
conda activate nsec-proj
pip install -r requirements.txt
```

After `conda activate nsec-proj` the environment's `include` and `lib` are
added to `CPATH` / `LIBRARY_PATH` / `LD_LIBRARY_PATH`, so the Makefiles do not
need any `-I` / `-L` flags. If you build outside conda, install GMP and OpenSSL
development packages and make sure their headers and libraries are visible to
g++.

The Python scripts need pycryptodome (for AES in Task 2). Everything else
(big integers, Miller-Rabin, modular inverse, OAEP, the attack) is written by
hand.

## Build the C++ version

```bash
make -C Task1/src/cpp
make -C Task2/src/cpp
make -C Task3/src/cpp
```

The Python version needs no build step.

## Task 1: textbook RSA

C++:

```bash
cd Task1/src/cpp
./keygen 1024
./rsa_enc "Network Security Project - Demo"
./rsa_dec <ciphertext_hex>
```

Python:

```bash
cd Task1/src/py
python keygen.py 1024
python rsa_enc.py "Network Security Project - Demo"
python rsa_dec.py <ciphertext_hex>
```

`keygen` generates a fresh 1024-bit key. Both `rsa_dec` programs also accept the
full `Ciphertext: <hex>` line printed by `rsa_enc`, so you can copy-paste it
directly.

Output files (written to `Task1/`):

| File | Content |
|------|---------|
| `RSA_Moduler.txt` | modulus `n`, decimal |
| `RSA_p.txt` | prime `p`, decimal |
| `RSA_q.txt` | prime `q`, decimal |
| `RSA_Public_Key.txt` | one line: `n e` (decimal, space separated) |
| `RSA_Secret_Key.txt` | one line: `n d` (decimal, space separated) |
| `Raw_Message.txt` | the plaintext, UTF-8, no trailing newline |
| `Encrypted_Message.txt` | ciphertext, 256 lowercase hex chars, no `0x` |

The public exponent is `e = 65537`. Bytes are converted to the RSA integer in
big-endian order. The ciphertext is always padded to the full modulus width
(256 hex chars = 128 bytes for a 1024-bit key), so leading zero bytes are kept.
The plaintext length is recovered from `Raw_Message.txt`, because turning the
decrypted integer back into bytes drops leading zero bytes.

Primes are generated with our own Miller-Rabin (40 rounds, with a small-prime
sieve first). The random seed for the GMP generator comes from OpenSSL
`RAND_bytes` in C++ and from the `secrets` module in Python, not from a clock or
`mt19937`. We also check that `n` comes out to exactly 1024 bits.

## Task 2: WUP protocol and CCA2 attack

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

Each program builds its own 1024-bit RSA key, plays client, server, and
attacker, recovers the AES key one bit at a time, and decrypts the historical
WUP request.

What it models: the client encrypts a 128-bit AES session key with textbook RSA
and sends an AES-encrypted WUP request. The server decrypts the RSA ciphertext,
**keeps only the low 128 bits** as the AES key (this is the QQ Browser behaviour
the paper describes), decrypts the request, and answers only if the request is a
valid WUP message. That accept/reject answer is the oracle.

The attacker knows the public key, the captured history message, and can call
the oracle. It does not know the private key `d` or the real AES key. For target
bit `i` it shifts by `b = 127 - i`, builds `C_b = C * (2^b)^e mod n`, which
decrypts to `2^b * key`. The server keeps the low 128 bits, so the bit we care
about lands in the top position. The attacker encrypts a valid probe WUP under
the key guess where that bit is 0:

- oracle accepts -> the bit is 0
- oracle rejects -> the bit is 1

After 128 queries the whole key is known.

WUP request format (plain text):

```
WUP/1
cmd=sync
uid=10001
nonce=<nonce>
body=browser-history-demo
END
```

A message is valid if it starts with `WUP/1`, contains `cmd=`, and ends with
`END`. AES is **AES-128-ECB with PKCS#7 padding**. ECB needs no IV, which keeps
the history message simple and matches the setting analysed in the paper; it is
only used here for the experiment and should not be used in real systems. The
Python version implements PKCS#7 by hand and calls pycryptodome only for the AES
block operation; the C++ version uses OpenSSL EVP, which does PKCS#7 itself. The
two produce identical ciphertext.

Output files (written to `Task2/`):

| File | Content |
|------|---------|
| `AES_Key.txt` | the real AES key, 32 lowercase hex chars (leading zeros kept) |
| `WUP_Request.txt` | the raw WUP request bytes, hex |
| `AES_Encrypted_WUP.txt` | the AES-ECB ciphertext, hex |
| `History_Message.txt` | RSA-encrypted AES key + AES-encrypted request |
| `attack_log.txt` | one block per round, then the final summary |

`History_Message.txt` has four lines: `rsa_n_hex`, `rsa_e_dec`,
`rsa_encrypted_aes_key_hex`, and `aes_encrypted_wup_request_hex`. The attack log
records, for each round, the target bit, the shift, the transformed RSA
ciphertext, the candidate key, the oracle result, and the recovered bit; the end
of the file reports the real key, the recovered key, whether they match, the
decrypted WUP, and the query count (128).

The oracle only ever returns accept or reject. It does not leak the RSA
plaintext, the AES key, or any parse error, so the attack really does rely on a
single bit of feedback per query. In the code the server (which holds `d`) and
the attacker (which only holds the public key and the oracle callback) are
separate objects.

## Task 3: RSA-OAEP

C++:

```bash
cd Task3/src/cpp
./OAEP_encoding "Network Security Project - Demo"
./OAEP_decoding <ciphertext_hex>
./OAEP_cca2_demo <ciphertext_hex>     # bonus: shows the CCA2 attack failing
```

Python:

```bash
cd Task3/src/py
python oaep_encode.py "Network Security Project - Demo"
python oaep_decode.py <ciphertext_hex>
```

Task 3 reuses the Task 1 key pair (`Task1/RSA_Public_Key.txt` and
`Task1/RSA_Secret_Key.txt`), so run Task 1 first. The optional arguments are
`k0`, `k1`, and the key file; the defaults are 512, 64, and the Task 1 key.

Parameters: `n = 1024`, `k0 = 512`, `k1 = 64`, hash `SHA-512`. So `r`, `X`, and
`Y` are each 512 bits (64 bytes) and the encoded block `EM = X || Y` is 1024
bits (128 bytes). The encoding is

```
X = (m || 0^k1) xor G(r)
Y = r xor H(X)
EM = X || Y
```

`G` and `H` are both MGF1 over SHA-512 with different labels (`"G"` and `"H"`)
for domain separation; the MGF1 counter is 4 bytes, big-endian, starting at 0.
All intermediate values are handled as fixed-width big-endian byte strings so no
leading zeros are lost. Because a random 1024-bit `EM` can be larger than the
1024-bit modulus, we resample `r` until `EM < n` (the approach suggested in the
instructions). The message is right-padded with zeros to the fixed message
width, and the original length is taken from `Raw_Message.txt` on decode; the
decoder also checks that the trailing `k1` bits are zero and rejects the block
otherwise. This is the teaching OAEP from the slides, not the full RFC 8017
RSAES-OAEP.

Output files (written to `Task3/`):

| File | Content |
|------|---------|
| `Random_Number.txt` | `r`, 128 hex chars (512 bits) |
| `Message_After_Padding.txt` | `EM = X || Y`, 256 hex chars (1024 bits) |
| `Encrypted_Message.txt` | the RSA-OAEP ciphertext, 256 hex chars |

Note that both Task 1 and Task 3 have a file called `Encrypted_Message.txt`;
they live in different directories.

Why this stops the Task 2 attack: in textbook RSA the plaintext is the AES key
itself, so multiplying the ciphertext by `(2^b)^e` shifts the key in a
predictable way. With OAEP the RSA plaintext is the randomized block `EM`.
Multiplying the ciphertext by `s^e` gives `s * EM mod n`, which is almost never
a valid OAEP block, so the trailing-zero check fails and the decoder rejects it.
The underlying RSA math is still multiplicative; what changes is that a
multiplicative change to the encoded block no longer maps to a predictable
change in the original key. `OAEP_cca2_demo` shows this: it forges a ciphertext
the same way the Task 2 attack does and the OAEP decoder rejects it.

## Output file conventions

- All hex is lowercase, no `0x` prefix.
- Bytes map to integers big-endian.
- RSA ciphertext and OAEP blocks are zero-padded to the full modulus width.
- `RSA_*` parameter files are decimal; everything else is hex.
- The public key file is `n e`, the secret key file is `n d`.

## Checking that decryption works

Round trip in one language:

```bash
cd Task1/src/py
python keygen.py 1024
CT=$(python rsa_enc.py "Network Security Project - Demo" | sed -n 's/^Ciphertext: //p')
python rsa_dec.py "$CT"      # prints the original message
```

Cross-language (this is the point of keeping both versions):

```bash
# build the C++ tools first
make -C Task1/src/cpp
cd Task1/src/cpp
./keygen 1024                                  # writes the shared key files
PYCT=$(cd ../py && python rsa_enc.py "Network Security Project - Demo" \
       | sed -n 's/^Ciphertext: //p')
./rsa_dec "$PYCT"                              # C++ decrypts the Python ciphertext
```

For the same key and message the C++ and Python ciphertexts are byte-for-byte
identical (textbook RSA is deterministic), and each version can decrypt the
other. The same holds for the Task 3 OAEP ciphertext.

## Tests

The `tests/` directory is for our own checking before submission and is not part
of the deliverable, so it is allowed to use pycryptodome to cross-check our
code. Run them with:

```bash
conda activate nsec-proj
python -m pytest tests/
```

They cover the RSA, OAEP, and CCA2 checklists from the instructions, including
the C++/Python interoperability checks (those are skipped automatically if g++
is not available).
