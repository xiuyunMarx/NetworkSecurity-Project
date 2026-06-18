#include <chrono>
#include <fstream>
#include <gmpxx.h>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
namespace textbookRSA {
inline auto power_mod(mpz_class base, mpz_class exp, mpz_class mod) {
	mpz_class ret;
	mpz_powm(ret.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
	return ret;
}

inline auto miller_rabin(const mpz_class &num, int k, gmp_randstate_t state) -> bool {
	if (num <= 1 || num == 4)
		return false;
	if (num <= 3)
		return true;
	if (num % 2 == 0)
		return false;

	// 将 num - 1 表示为 d * 2^s 的形式
	mpz_class d = num - 1;
	unsigned long long s = 0;
	while (d % 2 == 0) {
		d /= 2;
		s++;
	}

	for (int i = 0; i < k; i++) {
		mpz_class a;
		mpz_class limit = num - 3;
		mpz_urandomm(a.get_mpz_t(), state, limit.get_mpz_t());
		a += 2;

		mpz_class x = power_mod(a, d, num);
		if (x == 1 || x == num - 1) {
			continue;
		}

		bool composite = true;
		for (unsigned long long r = 1; r < s; r++) {
			x = power_mod(x, 2, num);
			if (x == num - 1) {
				composite = false;
				break;
			}
		}
		if (composite)
			return false;
	}
	return true; // 极大概率是素数
}

inline auto generate_prime(size_t bits, gmp_randstate_t state) -> mpz_class {
	while (true) {
		mpz_class candidate;
		mpz_urandomb(candidate.get_mpz_t(), state, bits);
		// 确保最高位和最低位为 1，以保证位宽且是奇数
		mpz_setbit(candidate.get_mpz_t(), bits - 1);
		mpz_setbit(candidate.get_mpz_t(), 0);

		if (miller_rabin(candidate, 40, state)) {
			return candidate;
		}
	}
}

// 密钥生成函数：生成 RSA 密钥对
inline void generate_keys(size_t key_size, mpz_class &n, mpz_class &e, mpz_class &d) {
	gmp_randstate_t state;
	gmp_randinit_default(state);
	unsigned long seed =
		std::chrono::high_resolution_clock::now().time_since_epoch().count();
	gmp_randseed_ui(state, seed);

	size_t prime_bits = key_size / 2;
	mpz_class p, q, phi;

	e = 65537; // 常用公钥指数

	while (true) {
		p = generate_prime(prime_bits, state);
		q = generate_prime(prime_bits, state);
		if (p == q)
			continue; // 保证 p 和 q 不相等

		n = p * q;
		phi = (p - 1) * (q - 1);

		// 确保 e 与 phi(n) 互质
		mpz_class gcd_val;
		mpz_gcd(gcd_val.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());
		if (gcd_val == 1) {
			break;
		}
	}

	// 计算私钥 d，满足 e * d = 1 (mod phi)
	mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());
	gmp_randclear(state);
}

// 辅助函数：将字符串转换为大整数
inline auto string_to_mpz(const std::string &str) -> mpz_class {
	mpz_class ret;
	if (str.empty())
		return ret;
	mpz_import(ret.get_mpz_t(), str.size(), 1, 1, 0, 0, str.data());
	return ret;
}

// 辅助函数：将大整数还原为字符串
inline auto mpz_to_string(const mpz_class &num) -> std::string {
	if (num == 0)
		return "";
	size_t max_bytes = (mpz_sizeinbase(num.get_mpz_t(), 2) + 7) / 8;
	std::string str(max_bytes, '\0');
	size_t written_bytes = 0;
	mpz_export(&str[0], &written_bytes, 1, 1, 0, 0, num.get_mpz_t());
	str.resize(written_bytes);
	return str;
}

// RSA 加密：C = M^e % n
inline auto encrypt(const mpz_class &m, const mpz_class &e, const mpz_class &n)
	-> mpz_class {
	return power_mod(m, e, n);
}

// RSA 解密：M = C^d % n
inline auto decrypt(const mpz_class &c, const mpz_class &d, const mpz_class &n)
	-> mpz_class {
	return power_mod(c, d, n);
}

inline auto save_public_key(const mpz_class &n, const mpz_class &e,
							const std::string &filename = "rsa_public_key.txt")
	-> void {
	std::ofstream ofs(filename);
	if (!ofs)
		throw std::runtime_error("无法打开文件 " + filename + " 进行写入");
	ofs << n << " " << e << std::endl;
	std::cout << "公钥已保存到 " << filename << std::endl;
}

inline auto save_private_key(const mpz_class &n, const mpz_class &d,
							 const std::string &filename = "rsa_private_key.txt")
	-> void {
	std::ofstream ofs(filename);
	if (!ofs)
		throw std::runtime_error("无法打开文件 " + filename + " 进行写入");
	ofs << n << " " << d << std::endl;
	std::cout << "私钥已保存到 " << filename << std::endl;
}

inline auto read_public_key(mpz_class &n, mpz_class &e,
							const std::string &filename = "rsa_public_key.txt")
	-> void {
	std::ifstream ifs(filename);
	if (!ifs)
		throw std::runtime_error("无法打开文件 " + filename + " 进行读取");
	if (!(ifs >> n >> e))
		throw std::runtime_error("读取公钥文件失败: " + filename);
}

inline auto read_private_key(mpz_class &n, mpz_class &d,
							 const std::string &filename = "rsa_private_key.txt")
	-> void {
	std::ifstream ifs(filename);
	if (!ifs)
		throw std::runtime_error("无法打开文件 " + filename + " 进行读取");
	if (!(ifs >> n >> d))
		throw std::runtime_error("读取私钥文件失败: " + filename);
}

} // namespace textbookRSA
