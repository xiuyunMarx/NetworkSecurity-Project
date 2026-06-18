#include "rsa_utils.h"

#include <exception>
#include <gmpxx.h>
#include <iostream>
#include <string>

namespace {
auto print_usage(const char *program) -> void {
	std::cerr << "Usage: " << program << " <plaintext>\n";
}
} // namespace

auto main(int argc, char *argv[]) -> int {
	try {
		if (argc != 2) {
			print_usage(argv[0]);
			return 1;
		}

		const std::string plaintext = argv[1];

		mpz_class n, e;
		textbookRSA::read_public_key(n, e);

		const mpz_class message = textbookRSA::string_to_mpz(plaintext);
		if (message >= n)
			throw std::runtime_error("plaintext is too large for this RSA key");

		const mpz_class ciphertext = textbookRSA::encrypt(message, e, n);
		std::cout << "Ciphertext: " << ciphertext.get_str(16) << std::endl;
		return 0;
	} catch (const std::exception &ex) {
		std::cerr << "Error: " << ex.what() << std::endl;
		return 1;
	}
}
