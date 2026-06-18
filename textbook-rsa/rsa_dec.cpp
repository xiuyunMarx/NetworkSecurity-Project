#include "rsa_utils.h"

#include <algorithm>
#include <cctype>
#include <exception>
#include <gmpxx.h>
#include <iostream>
#include <string>

namespace {
auto print_usage(const char *program) -> void {
	std::cerr << "Usage: " << program
			  << " <ciphertext_hex|\"Ciphertext: ciphertext_hex\">\n";
}

auto trim_left(std::string value) -> std::string {
	value.erase(value.begin(),
				std::find_if(value.begin(), value.end(), [](unsigned char ch) {
					return !std::isspace(ch);
				}));
	return value;
}

auto normalize_ciphertext_arg(std::string value) -> std::string {
	const std::string prefix = "Ciphertext:";
	if (value.rfind(prefix, 0) == 0)
		value = trim_left(value.substr(prefix.size()));
	return value;
}
} // namespace

auto main(int argc, char *argv[]) -> int {
	try {
		if (argc != 2) {
			print_usage(argv[0]);
			return 1;
		}

		std::string ciphertext_text = normalize_ciphertext_arg(argv[1]);

		mpz_class ciphertext;
		if (ciphertext.set_str(ciphertext_text, 16) != 0)
			throw std::runtime_error("ciphertext must be a hexadecimal integer");

		mpz_class n, d;
		textbookRSA::read_private_key(n, d);
		if (ciphertext >= n)
			throw std::runtime_error("ciphertext is too large for this RSA key");

		const mpz_class message = textbookRSA::decrypt(ciphertext, d, n);
		std::cout << "Plaintext: " << textbookRSA::mpz_to_string(message)
				  << std::endl;
		return 0;
	} catch (const std::exception &ex) {
		std::cerr << "Error: " << ex.what() << std::endl;
		return 1;
	}
}
