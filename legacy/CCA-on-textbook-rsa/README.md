# CCA Attack on Textbook RSA

Textbook RSA has multiplicative homomorphism:

```text
Enc(m) = m^e mod n
Enc(m) * Enc(s) mod n = Enc(m * s mod n)
```

For a target ciphertext `c = Enc(m)`, choose invertible `s` and send a
different ciphertext to the decryption oracle:

```text
c' = c * s^e mod n
```

The oracle returns:

```text
Dec(c') = m * s mod n
```

Recover the original plaintext:

```text
m = Dec(c') * s^-1 mod n
```

## Build

```bash
make -C CCA-on-textbook-rsa
```

## Run

Generate keys and encrypt a message first:

```bash
cd textbook-rsa
make
./rsa/keygen
./rsa/rsa_enc "attack-test"
```

Use the printed ciphertext hex:

```bash
cd ..
./CCA-on-textbook-rsa/cca_attack <ciphertext_hex>
```

The program prints the forged ciphertext sent to the oracle and the recovered
plaintext. It never asks the oracle to decrypt the original target ciphertext.
