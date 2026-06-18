#include "rsa_utils.h"

#include <exception>
#include <gmpxx.h>
#include <iostream>
#include <string>

namespace {
auto print_usage(const char *program) -> void {
	std::cerr << "Usage: " << program << " [key_size_bits]\n";
}

auto parse_key_size(const std::string &value) -> std::size_t {
	if (value.empty() || value[0] == '-')
		throw std::runtime_error("key_size_bits must be a positive integer");

	std::size_t parsed_chars = 0;
	const auto key_size = std::stoul(value, &parsed_chars);
	if (parsed_chars != value.size())
		throw std::runtime_error("key_size_bits must be a positive integer");
	if (key_size < 16 || key_size % 2 != 0)
		throw std::runtime_error("key_size_bits must be an even number >= 16");
	return key_size;
}
} // namespace

auto main(int argc, char *argv[]) -> int {
	try {
		if (argc > 2) {
			print_usage(argv[0]);
			return 1;
		}

		std::size_t key_size = 1024;

		if (argc >= 2)
			key_size = parse_key_size(argv[1]);

		mpz_class n, e, d;
		textbookRSA::generate_keys(key_size, n, e, d);
		textbookRSA::save_public_key(n, e);
		textbookRSA::save_private_key(n, d);

		std::cout << "密钥生成完成，公钥和私钥已保存。" << std::endl;
		return 0;
	} catch (const std::exception &ex) {
		std::cerr << "Error: " << ex.what() << std::endl;
		return 1;
	}
}
