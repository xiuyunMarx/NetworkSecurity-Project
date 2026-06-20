#include "rsa_utils.h"

#include <exception>
#include <gmpxx.h>
#include <iostream>
#include <string>

namespace {
auto print_usage(const char *program) -> void {
	std::cerr << "Usage: " << program << " <plaintext> [public_key_file]\n";
}
} // namespace

auto main(int argc, char *argv[]) -> int {
	try {
		if (argc < 2 || argc > 3) {
			print_usage(argv[0]);
			return 1;
		}

		const std::string plaintext = argv[1];
		const std::string public_key_file =
			argc >= 3 ? argv[2]
					  : textbookRSA::resolve_key_path("../../RSA_Public_Key.txt");

		mpz_class n, e;
		textbookRSA::read_public_key(n, e, public_key_file);

		const mpz_class message = textbookRSA::string_to_mpz(plaintext);
		if (message >= n)
			throw std::runtime_error("plaintext is too large for this RSA key");

		const mpz_class ciphertext = textbookRSA::encrypt(message, e, n);
		std::cout << "Ciphertext: " << ciphertext.get_str(16) << std::endl;

		const std::size_t modulus_bits = mpz_sizeinbase(n.get_mpz_t(), 2);
		textbookRSA::save_text(
			plaintext, textbookRSA::resolve_key_path("../../Raw_Message.txt"));
		textbookRSA::save_ciphertext_hex(
			ciphertext, modulus_bits,
			textbookRSA::resolve_key_path("../../Encrypted_Message.txt"));
		std::cout << "明文与密文已保存到 Raw_Message.txt / Encrypted_Message.txt"
				  << std::endl;
		return 0;
	} catch (const std::exception &ex) {
		std::cerr << "Error: " << ex.what() << std::endl;
		return 1;
	}
}
