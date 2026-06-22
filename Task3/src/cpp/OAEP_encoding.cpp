#include "OAEP_utils.h"

#include <exception>
#include <fstream>
#include <gmpxx.h>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

constexpr std::size_t DEFAULT_K0 = 512;
constexpr std::size_t DEFAULT_K1 = 64;
constexpr OAEP::HashAlgo DEFAULT_HASH = OAEP::HashAlgo::SHA512;

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

auto parse_hash(const std::string &value) -> OAEP::HashAlgo {
	if (value == "sha256" || value == "SHA256")
		return OAEP::HashAlgo::SHA256;
	if (value == "sha512" || value == "SHA512")
		return OAEP::HashAlgo::SHA512;
	throw std::runtime_error("hash must be sha256 or sha512");
}

} // namespace

auto main(int argc, char *argv[]) -> int {
    if (argc < 2 || argc > 6) {
        std::cerr<< "Usage: "<< argv[0] << " <plaintext> [k0_bits] [k1_bits] [public_key_file] [hash]\n";
        return 1;
    }

    const std::string plaintext = argv[1];
    const std::size_t k0 =
        argc >= 3 ? parse_size(argv[2], "k0_bits") : DEFAULT_K0;
    const std::size_t k1 =
        argc >= 4 ? parse_size(argv[3], "k1_bits") : DEFAULT_K1;
    const std::string public_key_file =
        argc >= 5 ? argv[4] : "../../../Task1/RSA_Public_Key.txt";
    const OAEP::HashAlgo hash =
        argc >= 6 ? parse_hash(argv[5]) : DEFAULT_HASH;

    mpz_class n, e;
    textbookRSA::read_public_key(n, e, public_key_file);

    const OAEP::Protocol protocol = OAEP::OAEP_init_protocol(k0, k1, hash);
    const OAEP::EncryptionResult result =
        OAEP::encrypt_message(plaintext, e, n, protocol);

    const std::size_t n_bits = OAEP::modulus_bits(n);
    const std::size_t x_bits = n_bits - protocol.k0;

    std::cout << "RSA modulus bits: " << n_bits << '\n'
                << "Message capacity bits: "
                << n_bits - protocol.k0 - protocol.k1 << '\n'
                << "r: " << OAEP::fixed_hex(result.padding.r, protocol.k0)
                << '\n'
                << "X: " << OAEP::fixed_hex(result.padding.X, x_bits)
                << '\n'
                << "Y: " << OAEP::fixed_hex(result.padding.Y, protocol.k0)
                << '\n'
                << "OAEP encoded message: "
                << OAEP::fixed_hex(result.padding.encoded, n_bits) << '\n'
                << "Ciphertext: " << result.ciphertext.get_str(16) << '\n';

    //   Random_Number.txt       : OAEP r（k0 bit，128 hex）
    //   Message_After_Padding.txt: segment EM = X || Y（n bit，256 hex）
    //   Encrypted_Message.txt    : RSA-OAEP ciphertext（n bit，256 hex）
    std::ofstream("../../Random_Number.txt")
        << OAEP::fixed_hex(result.padding.r, protocol.k0) << '\n';
    std::ofstream("../../Message_After_Padding.txt")
        << OAEP::fixed_hex(result.padding.encoded, n_bits) << '\n';
    std::ofstream("../../Encrypted_Message.txt")
        << OAEP::fixed_hex(result.ciphertext, n_bits) << '\n';
    std::cout << "outputs written to Task3/Random_Number.txt, "
                    "Message_After_Padding.txt, Encrypted_Message.txt\n";
    return 0;

}
