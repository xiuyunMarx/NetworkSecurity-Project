#ifndef OAEP_UTILS_H
#define OAEP_UTILS_H

#include "../textbook-rsa/rsa_utils.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace OAEP {

enum class HashAlgo { SHA256, SHA512 };

struct Protocol {
	std::size_t k0;
	std::size_t k1;
	HashAlgo hash = HashAlgo::SHA512;
};

struct EncodingResult {
	mpz_class r;
	mpz_class X;
	mpz_class Y;
	mpz_class encoded;
};

struct EncryptionResult {
	EncodingResult padding;
	mpz_class ciphertext;
};

struct DecodingResult {
	mpz_class X;
	mpz_class Y;
	mpz_class r;
	mpz_class padded_message;
	mpz_class message;
};

struct DecryptionResult {
	DecodingResult padding;
	mpz_class encoded;
	std::string message;
};

inline auto OAEP_init_protocol(std::size_t k0, std::size_t k1,
							   HashAlgo hash = HashAlgo::SHA512) -> Protocol {
	if (k0 == 0)
		throw std::runtime_error("k0 must be positive");
	return Protocol{k0, k1, hash};
}

inline auto bit_length(const mpz_class &value) -> std::size_t {
	if (value < 0)
		throw std::runtime_error("bit length is undefined for negative values");
	if (value == 0)
		return 0;
	return mpz_sizeinbase(value.get_mpz_t(), 2);
}

inline auto byte_length_for_bits(std::size_t bits) -> std::size_t {
	return (bits + 7) / 8;
}

inline auto bit_mask(std::size_t bits) -> mpz_class {
	if (bits == 0)
		return 0;
	return (mpz_class(1) << bits) - 1;
}

inline auto modulus_bits(const mpz_class &modulus) -> std::size_t {
	if (modulus <= 0)
		throw std::runtime_error("RSA modulus must be positive");
	return bit_length(modulus);
}

inline auto to_fixed_width_bytes(const mpz_class &value, std::size_t bits)
	-> std::vector<unsigned char> {
	if (value < 0)
		throw std::runtime_error("negative values cannot be encoded as bit strings");
	if (bit_length(value) > bits)
		throw std::runtime_error("value is too large for the requested bit width");

	const std::size_t width = byte_length_for_bits(bits);
	std::vector<unsigned char> out(width, 0);
	if (value == 0 || width == 0)
		return out;

	const std::size_t raw_width = byte_length_for_bits(bit_length(value));
	std::vector<unsigned char> raw(raw_width, 0);
	std::size_t written = 0;
	mpz_export(raw.data(), &written, 1, 1, 1, 0, value.get_mpz_t());
	raw.resize(written);
	std::copy(raw.begin(), raw.end(), out.end() - raw.size());
	return out;
}

inline auto bytes_to_mpz(const std::vector<unsigned char> &bytes) -> mpz_class {
	mpz_class value;
	if (!bytes.empty())
		mpz_import(value.get_mpz_t(), bytes.size(), 1, 1, 1, 0, bytes.data());
	return value;
}

inline auto sha256(const std::vector<unsigned char> &input)
	-> std::vector<unsigned char> {
	std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH, 0);
	SHA256(input.data(), input.size(), digest.data());
	return digest;
}

inline auto sha512(const std::vector<unsigned char> &input)
	-> std::vector<unsigned char> {
	std::vector<unsigned char> digest(SHA512_DIGEST_LENGTH, 0);
	SHA512(input.data(), input.size(), digest.data());
	return digest;
}

inline auto hash_digest(HashAlgo algo, const std::vector<unsigned char> &input)
	-> std::vector<unsigned char> {
	return algo == HashAlgo::SHA512 ? sha512(input) : sha256(input);
}

inline auto append_u32_be(std::vector<unsigned char> &buffer,
						  std::uint32_t value) -> void {
	buffer.push_back(static_cast<unsigned char>((value >> 24) & 0xff));
	buffer.push_back(static_cast<unsigned char>((value >> 16) & 0xff));
	buffer.push_back(static_cast<unsigned char>((value >> 8) & 0xff));
	buffer.push_back(static_cast<unsigned char>(value & 0xff));
}

inline auto mgf1(const std::string &label,
				 const std::vector<unsigned char> &seed,
				 std::size_t output_bits, HashAlgo algo) -> mpz_class {
	const std::size_t output_bytes = byte_length_for_bits(output_bits);
	std::vector<unsigned char> output;
	output.reserve(output_bytes);

	for (std::uint32_t counter = 0; output.size() < output_bytes; ++counter) {
		std::vector<unsigned char> block;
		block.reserve(label.size() + seed.size() + 4);
		block.insert(block.end(), label.begin(), label.end());
		block.insert(block.end(), seed.begin(), seed.end());
		append_u32_be(block, counter);

		const auto digest = hash_digest(algo, block);
		const std::size_t need = output_bytes - output.size();
		output.insert(output.end(), digest.begin(),
					  digest.begin() +
						  static_cast<std::ptrdiff_t>(
							  std::min<std::size_t>(digest.size(), need)));
	}

	return bytes_to_mpz(output) & bit_mask(output_bits);
}

inline auto G(const mpz_class &r, const Protocol &protocol,
			  std::size_t output_bits) -> mpz_class {
	return mgf1("G", to_fixed_width_bytes(r, protocol.k0), output_bits,
				protocol.hash);
}

inline auto H(const mpz_class &X, std::size_t x_bits,
			  const Protocol &protocol) -> mpz_class {
	return mgf1("H", to_fixed_width_bytes(X, x_bits), protocol.k0,
				protocol.hash);
}

inline auto random_bit_string(std::size_t bits) -> mpz_class {
	std::vector<unsigned char> bytes(byte_length_for_bits(bits), 0);
	if (!bytes.empty() && RAND_bytes(bytes.data(), bytes.size()) != 1)
		throw std::runtime_error("failed to generate OAEP random string");
	return bytes_to_mpz(bytes) & bit_mask(bits);
}

inline auto validate_parameters(std::size_t n, const Protocol &protocol)
	-> void {
	if (n == 0)
		throw std::runtime_error("n must be positive");
	if (protocol.k0 >= n || protocol.k1 >= n - protocol.k0)
		throw std::runtime_error("k0 + k1 must be smaller than n");
}

inline auto encode_integer_with_r(const mpz_class &message, std::size_t n,
								  const Protocol &protocol,
								  const mpz_class &r) -> EncodingResult {
	validate_parameters(n, protocol);
	if (message < 0)
		throw std::runtime_error("message must be non-negative");
	if (bit_length(message) > n - protocol.k0 - protocol.k1)
		throw std::runtime_error("message is too large for OAEP parameters");
	if (r < 0 || bit_length(r) > protocol.k0)
		throw std::runtime_error("r is too large for k0 bits");

	const std::size_t x_bits = n - protocol.k0;
	const mpz_class padded_message = message << protocol.k1;
	const mpz_class X = padded_message ^ G(r, protocol, x_bits);
	const mpz_class Y = r ^ H(X, x_bits, protocol);
	return EncodingResult{r, X, Y, (X << protocol.k0) + Y};
}

inline auto encode_integer(const mpz_class &message, std::size_t n,
						   const Protocol &protocol) -> EncodingResult {
	return encode_integer_with_r(message, n, protocol,
								 random_bit_string(protocol.k0));
}

inline auto encode_message(const std::string &message,
						   const mpz_class &rsa_modulus,
						   const Protocol &protocol) -> EncodingResult {
	return encode_integer(textbookRSA::string_to_mpz(message),
						  modulus_bits(rsa_modulus), protocol);
}

inline auto encrypt_message(const std::string &message, const mpz_class &e,
							const mpz_class &rsa_modulus,
							const Protocol &protocol) -> EncryptionResult {
	const mpz_class message_value = textbookRSA::string_to_mpz(message);
	const std::size_t n = modulus_bits(rsa_modulus);
	for (int attempt = 0; attempt < 128; ++attempt) {
		EncodingResult padding = encode_integer(message_value, n, protocol);
		if (padding.encoded < rsa_modulus) {
			return EncryptionResult{
				padding, textbookRSA::encrypt(padding.encoded, e, rsa_modulus)};
		}
	}
	throw std::runtime_error(
		"failed to sample an OAEP encoded message smaller than the RSA modulus");
}

inline auto decode_integer(const mpz_class &encoded, std::size_t n,
						   const Protocol &protocol) -> DecodingResult {
	validate_parameters(n, protocol);
	if (encoded < 0)
		throw std::runtime_error("encoded message must be non-negative");
	if (bit_length(encoded) > n)
		throw std::runtime_error("encoded message is too large for OAEP parameters");

	const std::size_t x_bits = n - protocol.k0;
	const mpz_class X = encoded >> protocol.k0;
	const mpz_class Y = encoded & bit_mask(protocol.k0);
	const mpz_class r = Y ^ H(X, x_bits, protocol);
	const mpz_class padded_message = X ^ G(r, protocol, x_bits);

	if ((padded_message & bit_mask(protocol.k1)) != 0)
		throw std::runtime_error("invalid OAEP padding: trailing k1 bits are not zero");

	const mpz_class message = padded_message >> protocol.k1;
	if (bit_length(message) > n - protocol.k0 - protocol.k1)
		throw std::runtime_error("invalid OAEP padding: message field is too large");

	return DecodingResult{X, Y, r, padded_message, message};
}

inline auto decode_message(const mpz_class &encoded,
						   const mpz_class &rsa_modulus,
						   const Protocol &protocol) -> DecodingResult {
	return decode_integer(encoded, modulus_bits(rsa_modulus), protocol);
}

inline auto decrypt_message(const mpz_class &ciphertext, const mpz_class &d,
							const mpz_class &rsa_modulus,
							const Protocol &protocol) -> DecryptionResult {
	if (ciphertext < 0 || ciphertext >= rsa_modulus)
		throw std::runtime_error("ciphertext is outside the RSA message space");

	const mpz_class encoded = textbookRSA::decrypt(ciphertext, d, rsa_modulus);
	DecodingResult padding = decode_message(encoded, rsa_modulus, protocol);
	return DecryptionResult{padding, encoded,
							textbookRSA::mpz_to_string(padding.message)};
}

inline auto fixed_hex(const mpz_class &value, std::size_t bits) -> std::string {
	std::string hex = value.get_str(16);
	const std::size_t width = (bits + 3) / 4;
	if (hex.size() < width)
		hex.insert(hex.begin(), width - hex.size(), '0');
	return hex;
}

} // namespace OAEP

#endif
