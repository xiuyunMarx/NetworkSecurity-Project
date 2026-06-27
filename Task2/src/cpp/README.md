# WUP CCA2 Attack Demo

This folder simulates the WUP-style protocol described in the project:

1. Server creates a 1024-bit textbook RSA key pair.
2. Client creates a random 128-bit AES session key.
3. Client sends:
   - RSA-encrypted AES key: `C = key^e mod n`
   - AES-ECB-encrypted WUP request
4. Server decrypts `C`, keeps only the least significant 128 bits, and uses them as the AES key.
5. Server only sends an AES-encrypted response when the WUP request decrypts to a valid format.

## WUP Format

The demo request is plain text:

```text
WUP/1
cmd=sync
uid=10001
nonce=...
body=browser-history-demo
END
```

`valid_wup()` accepts plaintext that starts with `WUP/1`, contains `cmd=`, and ends with `END`.

## Attack

For captured history message:

```text
C = RSA_AES_key
R = AES_request
```

The attacker computes:

```text
C_b = C * (2^b)^e mod n
```

Because RSA is multiplicatively homomorphic, decrypting `C_b` gives `2^b * key`. Since the server discards all but the low 128 bits, `b = 127` moves the least significant key bit into the highest AES-key bit. The attacker sends a valid WUP request encrypted under the guess where that bit is `0`.

- If the server responds, the guessed bit is `0`.
- If the server does not respond, the bit is `1`.

Repeat for all 128 bits, then decrypt the historical AES request.

## Build And Run

```bash
cd Task2/src/cpp
make
./wup_cca2
```

The program writes `History_Message.txt`, recovers the AES key through the server oracle, and decrypts the historical WUP request.

## References

- When Textbook RSA is Used to Protect the Privacy of Hundreds of Millions of Users: https://arxiv.org/pdf/1802.03367
