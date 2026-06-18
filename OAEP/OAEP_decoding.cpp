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
				 "[k0_bits] [k1_bits] [private_key_file]\n";
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
		if (argc < 2 || argc > 6) {
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

		if (argc - next_arg > 3) {
			print_usage(argv[0]);
			return 1;
		}

		const std::size_t k0 = argc > next_arg
								   ? parse_size(argv[next_arg], "k0_bits")
								   : DEFAULT_K0;
		const std::size_t k1 = argc > next_arg + 1
								   ? parse_size(argv[next_arg + 1], "k1_bits")
								   : DEFAULT_K1;
		const std::string private_key_file =
			argc > next_arg + 2 ? argv[next_arg + 2]
								: "../textbook-rsa/rsa_private_key.txt";

		mpz_class ciphertext;
		if (ciphertext.set_str(ciphertext_text, 16) != 0)
			throw std::runtime_error("ciphertext must be a hexadecimal integer");

		mpz_class n, d;
		textbookRSA::read_private_key(n, d, private_key_file);

		const OAEP::Protocol protocol = OAEP::OAEP_init_protocol(k0, k1);
		const OAEP::DecryptionResult result =
			OAEP::decrypt_message(ciphertext, d, n, protocol);

		const std::size_t n_bits = OAEP::modulus_bits(n);
		const std::size_t x_bits = n_bits - protocol.k0;

		std::cout << "RSA modulus bits: " << n_bits << '\n'
				  << "OAEP encoded message: "
				  << OAEP::fixed_hex(result.encoded, n_bits) << '\n'
				  << "X: " << OAEP::fixed_hex(result.padding.X, x_bits)
				  << '\n'
				  << "Y: " << OAEP::fixed_hex(result.padding.Y, protocol.k0)
				  << '\n'
				  << "Recovered r: "
				  << OAEP::fixed_hex(result.padding.r, protocol.k0) << '\n'
				  << "Recovered m00..0: "
				  << OAEP::fixed_hex(result.padding.padded_message, x_bits)
				  << '\n'
				  << "Plaintext: " << result.message << '\n';
		return 0;
	} catch (const std::exception &ex) {
		std::cerr << "Error: " << ex.what() << std::endl;
		return 1;
	}
}
