#include "../../../Task1/src/cpp/rsa_utils.h"

#include <fstream>
#include <gmpxx.h>
#include <iomanip>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;

Bytes bytes(const std::string &s) { return Bytes(s.begin(), s.end()); }

std::string hex(const Bytes &data) {
	std::ostringstream out;
	for (unsigned char c : data)
		out << std::hex << std::setw(2) << std::setfill('0') << int(c);
	return out.str();
}

mpz_class mpz_from_bytes(const Bytes &data) {
	mpz_class x;
	mpz_import(x.get_mpz_t(), data.size(), 1, 1, 1, 0, data.data());
	return x;
}


Bytes low128(mpz_class x) {
	static const mpz_class mask = (mpz_class(1) << 128) - 1;
	x &= mask;

	Bytes out(16), tmp(16);
	size_t written = 0;
	mpz_export(tmp.data(), &written, 1, 1, 1, 0, x.get_mpz_t());
	std::copy(tmp.begin(), tmp.begin() + written, out.end() - written);
	return out;
}

Bytes random_bytes(size_t n) {
	Bytes out(n);
	if (RAND_bytes(out.data(), out.size()) != 1)
		throw std::runtime_error("RAND_bytes failed");
	return out;
}

Bytes aes_ecb_encrypt(const Bytes &plain, const Bytes &key) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	Bytes out(plain.size() + 16);
	int len = 0, total = 0;

	EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr);
	EVP_EncryptUpdate(ctx, out.data(), &len, plain.data(), plain.size());
	total += len;
	EVP_EncryptFinal_ex(ctx, out.data() + total, &len);
	total += len;

	EVP_CIPHER_CTX_free(ctx);
	out.resize(total);
	return out;
}

std::optional<Bytes> aes_ecb_decrypt(const Bytes &cipher, const Bytes &key) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	Bytes out(cipher.size());
	int len = 0, total = 0;

	EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr);
	if (EVP_DecryptUpdate(ctx, out.data(), &len, cipher.data(), cipher.size()) !=
		1) {
		EVP_CIPHER_CTX_free(ctx);
		return std::nullopt;
	}
	total += len;
	if (EVP_DecryptFinal_ex(ctx, out.data() + total, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return std::nullopt;
	}
	total += len;

	EVP_CIPHER_CTX_free(ctx);
	out.resize(total);
	return out;
}

bool valid_wup(const Bytes &plain) {
	const std::string s(plain.begin(), plain.end());
	return s.rfind("WUP/1\n", 0) == 0 && s.find("\ncmd=") != std::string::npos &&
		   s.size() >= 4 && s.substr(s.size() - 4) == "END\n";
}

std::string wup_request(const std::string &nonce) {
	return "WUP/1\ncmd=sync\nuid=10001\nnonce=" + nonce +
		   "\nbody=browser-history-demo\nEND\n";
}

struct Server {
	mpz_class n, e, d;

	std::optional<Bytes> handle(const mpz_class &rsa_key,
								const Bytes &encrypted_request) const {
		const Bytes key = low128(textbookRSA::decrypt(rsa_key, d, n));
		const auto request = aes_ecb_decrypt(encrypted_request, key);
		if (!request || !valid_wup(*request))
			return std::nullopt;
		return aes_ecb_encrypt(bytes("WUP/1\nstatus=ok\nEND\n"), key);
	}
};

struct History {
	Bytes aes_key;
	mpz_class rsa_key;
	Bytes encrypted_request;
	std::string plain_request;
};

History client_send(const Server &server) {
	History h;
	h.aes_key = random_bytes(16);
	h.plain_request = wup_request("20260616");
	h.rsa_key = textbookRSA::encrypt(mpz_from_bytes(h.aes_key), server.e, server.n);
	h.encrypted_request = aes_ecb_encrypt(bytes(h.plain_request), h.aes_key);
	return h;
}

void write_history(const Server &server, const History &h) {
	std::ofstream out(textbookRSA::resolve_key_path("../../History_Message.txt"));
	out << "rsa_n_hex=" << server.n.get_str(16) << "\n";
	out << "rsa_e_dec=" << server.e << "\n";
	out << "rsa_encrypted_aes_key_hex=" << h.rsa_key.get_str(16) << "\n";
	out << "aes_encrypted_wup_request_hex=" << hex(h.encrypted_request) << "\n";
}

// Save output files.
//   AES_Key.txt          : 128-bit AES key, 32 lowercase hex characters, keeping leading zeros
//   WUP_Request.txt      : Hex of raw WUP request bytes
//   AES_Encrypted_WUP.txt: Hex of AES-128-ECB ciphertext
void write_client_files(const History &h) {
	std::ofstream(textbookRSA::resolve_key_path("../../AES_Key.txt"))
		<< hex(h.aes_key) << "\n";
	std::ofstream(textbookRSA::resolve_key_path("../../WUP_Request.txt"))
		<< hex(bytes(h.plain_request)) << "\n";
	std::ofstream(textbookRSA::resolve_key_path("../../AES_Encrypted_WUP.txt"))
		<< hex(h.encrypted_request) << "\n";
}

mpz_class recover_key(const Server &server, const History &h, std::ostream &log,
					  int &query_count) {
	mpz_class known = 0;
	const Bytes probe = bytes(wup_request("cca2-probe"));
	query_count = 0;

	for (int bit = 0; bit < 128; ++bit) {
		const int shift = 127 - bit;
		const mpz_class factor = mpz_class(1) << shift;
		const mpz_class shifted_rsa =
			h.rsa_key * textbookRSA::encrypt(factor, server.e, server.n) % server.n;
		const mpz_class known_before = known;
		const Bytes guess_zero_key = low128(known << shift);
		const Bytes encrypted_probe = aes_ecb_encrypt(probe, guess_zero_key);

		const bool accepted = server.handle(shifted_rsa, encrypted_probe).has_value();
		++query_count;
		const int recovered_bit = accepted ? 0 : 1;
		if (!accepted)
			known |= mpz_class(1) << bit;

		log << "[Round " << std::setw(3) << std::setfill('0') << (bit + 1) << "]\n"
			<< "target_original_bit=" << bit << "\n"
			<< "shift=" << shift << "\n"
			<< "transformed_rsa_ciphertext=" << shifted_rsa.get_str(16) << "\n"
			<< "known_low_bits_before=0x" << known_before.get_str(16) << "\n"
			<< "candidate_bit=0\n"
			<< "candidate_server_key=" << hex(guess_zero_key) << "\n"
			<< "oracle_result=" << (accepted ? "ACCEPT" : "REJECT") << "\n"
			<< "recovered_bit=" << recovered_bit << "\n"
			<< "known_low_bits_after=0x" << known.get_str(16) << "\n\n";

		if ((bit + 1) % 16 == 0)
			std::cout << "recovered " << bit + 1 << "/128 bits\n";
	}
	return known;
}

int main() {
	Server server;
	textbookRSA::generate_keys(1024, server.n, server.e, server.d);

	const History history = client_send(server);
	write_history(server, history);
	write_client_files(history);

	std::cout << "history written to History_Message.txt\n";
	std::cout << "RSA-encrypted AES key: " << history.rsa_key.get_str(16) << "\n";
	std::cout << "AES-encrypted WUP request: " << hex(history.encrypted_request)
			  << "\n\n";

	std::ofstream log(textbookRSA::resolve_key_path("../../attack_log.txt"));
	int query_count = 0;
	const mpz_class recovered = recover_key(server, history, log, query_count);
	const Bytes recovered_key = low128(recovered);
	const auto recovered_request =
		aes_ecb_decrypt(history.encrypted_request, recovered_key);
	const std::string recovered_plaintext =
		recovered_request
			? std::string(recovered_request->begin(), recovered_request->end())
			: std::string();
	const bool keys_match = recovered_key == history.aes_key;

	log << "actual_aes_key=" << hex(history.aes_key) << "\n"
		<< "recovered_aes_key=" << hex(recovered_key) << "\n"
		<< "keys_match=" << (keys_match ? "true" : "false") << "\n"
		<< "history_wup_plaintext=" << recovered_plaintext << "\n"
		<< "query_count=" << query_count << "\n";

	std::cout << "\nactual AES key:    " << hex(history.aes_key) << "\n";
	std::cout << "recovered AES key: " << hex(recovered_key) << "\n";
	std::cout << "decrypted historical request:\n" << recovered_plaintext;
	return 0;
}
