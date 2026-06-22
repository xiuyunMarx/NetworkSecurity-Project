#include "rsa_utils.h"
#include <gmpxx.h>
#include <iostream>
#define DEFAULT_KEY_SIZE 1024
namespace {
auto print_usage(const char *program) -> void {
	std::cerr << "Usage: " << program
			  << " [key_size_bits] [public_key_file] [private_key_file]\n";
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
    if (argc > 4) {
        print_usage(argv[0]);
        return 1;
    }

    std::size_t key_size = DEFAULT_KEY_SIZE;
    if (argc >= 2)
        key_size = parse_key_size(argv[1]);

    const std::string public_key_file =
        argc >= 3 ? argv[2]
                    : textbookRSA::resolve_key_path("../../RSA_Public_Key.txt");
    const std::string private_key_file =
        argc >= 4 ? argv[3]
                    : textbookRSA::resolve_key_path("../../RSA_Secret_Key.txt");

    mpz_class n, e, d, p, q;
    textbookRSA::generate_keys(key_size, n, e, d, p, q);
    textbookRSA::save_public_key(n, e, public_key_file);
    textbookRSA::save_private_key(n, d, private_key_file);
    textbookRSA::save_decimal(
        n, textbookRSA::resolve_key_path("../../RSA_Moduler.txt"));
    textbookRSA::save_decimal(
        p, textbookRSA::resolve_key_path("../../RSA_p.txt"));
    textbookRSA::save_decimal(
        q, textbookRSA::resolve_key_path("../../RSA_q.txt"));

    std::cout << "Generated Public Key, Private Key, Big Prime and Modulus" << std::endl;
    return 0;

}
