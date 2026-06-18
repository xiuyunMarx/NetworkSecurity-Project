#include "OAEP_utils.h"

#include <algorithm>
#include <cctype>
#include <exception>
#include <gmpxx.h>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

constexpr std::size_t DEFAULT_K0 = 128;
constexpr std::size_t DEFAULT_K1 = 128;

auto print_usage(const char *program) -> void {
	std::cerr << "Usage: " << program
			  << " <ciphertext_hex|\"Ciphertext: ciphertext_hex\"> "
				 "[k0_bits] [k1_bits] [public_key_file] [private_key_file]\n";
}

auto parse_size(const std::string &value, const std::string &name)
	-> std::size_t {
	if (value.empty() || value[0] == '-')
		throw std::runtime_error(name + " must be a non-negative integer");

	std::size_t parsed_chars = 0;
	const auto parsed = std::stoul(value, &parsed_chars);
	if (parsed_chars != value.size())
		throw std::runtime_error(name + " must be a non-negative integer");
	return parsed;
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
		if (argc < 2 || argc > 7) {
			print_usage(argv[0]);
			return 1;
		}

		std::string ciphertext_text;
		int next_arg = 2;
		if (std::string(argv[1]) == "Ciphertext:") {
			if (argc < 3)
				throw std::runtime_error("missing ciphertext after Ciphertext:");
			ciphertext_text = argv[2];
			next_arg = 3;
		} else {
			ciphertext_text = normalize_ciphertext_arg(argv[1]);
		}

		if (argc - next_arg > 4) {
			print_usage(argv[0]);
			return 1;
		}

		const std::size_t k0 = argc > next_arg
								   ? parse_size(argv[next_arg], "k0_bits")
								   : DEFAULT_K0;
		const std::size_t k1 = argc > next_arg + 1
								   ? parse_size(argv[next_arg + 1], "k1_bits")
								   : DEFAULT_K1;
		const std::string public_key_file =
			argc > next_arg + 2 ? argv[next_arg + 2]
								: "../textbook-rsa/rsa_public_key.txt";
		const std::string private_key_file =
			argc > next_arg + 3 ? argv[next_arg + 3]
								: "../textbook-rsa/rsa_private_key.txt";

		mpz_class ciphertext;
		if (ciphertext.set_str(ciphertext_text, 16) != 0)
			throw std::runtime_error("ciphertext must be a hexadecimal integer");

		mpz_class n, e, private_n, d;
		textbookRSA::read_public_key(n, e, public_key_file);
		textbookRSA::read_private_key(private_n, d, private_key_file);
		if (n != private_n)
			throw std::runtime_error("public and private key moduli do not match");
		if (ciphertext < 0 || ciphertext >= n)
			throw std::runtime_error("ciphertext is outside the RSA message space");

		mpz_class s_inverse;
		mpz_class forged;
		mpz_class multiplier;
		mpz_class s;
		for (s = 2;; ++s) {
			if (mpz_invert(s_inverse.get_mpz_t(), s.get_mpz_t(),
						   n.get_mpz_t()) == 0)
				continue;
			multiplier = textbookRSA::encrypt(s, e, n);
			forged = ciphertext * multiplier % n;
			if (forged != ciphertext)
				break;
		}

		const OAEP::Protocol protocol = OAEP::OAEP_init_protocol(k0, k1);
		std::cout << "Chosen multiplier s: " << s << '\n'
				  << "Forged ciphertext: " << forged.get_str(16) << '\n';

		try {
			const OAEP::DecryptionResult result =
				OAEP::decrypt_message(forged, d, n, protocol);
			std::cout << "Forged ciphertext was accepted unexpectedly.\n"
					  << "Recovered plaintext: " << result.message << '\n';
		} catch (const std::exception &ex) {
			std::cout << "OAEP decryption rejected forged ciphertext: "
					  << ex.what() << '\n'
					  << "CCA2 multiplicative attack is blocked.\n";
		}

		return 0;
	} catch (const std::exception &ex) {
		std::cerr << "Error: " << ex.what() << std::endl;
		return 1;
	}
}
