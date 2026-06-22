#include "../../../../Task1/src/cpp/rsa_utils.h"

#include <gmpxx.h>
#include <iostream>
#include <string>

int main(int argc, char **argv) {
	if (argc != 2) {
		std::cerr << "Usage: " << argv[0] << " <ciphertext_hex>\n";
		return 1;
	}

	mpz_class c, n, e, n2, d;
	if (c.set_str(argv[1], 16) != 0) {
		std::cerr << "ciphertext must be hex\n";
		return 1;
	}

	std::string self = argv[0];
	const auto slash = self.find_last_of("/\\");
	const std::string keydir =
		(slash == std::string::npos ? "." : self.substr(0, slash)) +
		"/../../../../Task1/";

	textbookRSA::read_public_key(n, e, keydir + "RSA_Public_Key.txt");
	textbookRSA::read_private_key(n2, d, keydir + "RSA_Secret_Key.txt");
	if (n != n2 || c < 0 || c >= n) {
		std::cerr << "bad key or ciphertext\n";
		return 1;
	}

	if (c == 0) {
		std::cout << "Recovered plaintext: \n";
		return 0;
	}

	mpz_class s_inv, forged;
	for (mpz_class s = 2;; ++s) {
		if (mpz_invert(s_inv.get_mpz_t(), s.get_mpz_t(), n.get_mpz_t()) == 0)
			continue;
		forged = c * textbookRSA::encrypt(s, e, n) % n;
		if (forged != c)
			break;
	}

	const mpz_class oracle_reply = textbookRSA::decrypt(forged, d, n);
	const mpz_class m = oracle_reply * s_inv % n;

	std::cout << "Forged ciphertext sent to oracle: " << forged.get_str(16)
			  << "\nRecovered plaintext: " << textbookRSA::mpz_to_string(m)
			  << "\nRecovered integer: " << m << "\n";
	return 0;
}
