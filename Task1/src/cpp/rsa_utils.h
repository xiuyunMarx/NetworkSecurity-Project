#include <fstream>
#include <gmpxx.h>
#include <iostream>
#include <limits.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

namespace textbookRSA {
// 返回当前可执行文件所在目录
inline auto executable_dir() -> std::string {
	char buf[PATH_MAX];
	const ssize_t len = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
	if (len <= 0)
		return ".";
	buf[len] = '\0';
	const std::string path(buf);
	const auto slash = path.find_last_of('/');
	return slash == std::string::npos ? std::string(".") : path.substr(0, slash);
}

// 将相对文件名解析为相对可执行文件目录的路径
inline auto resolve_key_path(const std::string &filename) -> std::string {
	if (!filename.empty() && filename.front() == '/')
		return filename;
	return executable_dir() + "/" + filename;
}

// 用 OpenSSL RAND_bytes
inline auto seed_randstate(gmp_randstate_t state, std::size_t seed_bytes = 32)
	-> void {
	std::vector<unsigned char> buf(seed_bytes);
	if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1)
		throw std::runtime_error("RAND_bytes failed to seed GMP random state");
	mpz_class seed;
	mpz_import(seed.get_mpz_t(), buf.size(), 1, 1, 1, 0, buf.data());
	gmp_randseed(state, seed.get_mpz_t());
}

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
inline void generate_keys(size_t key_size, mpz_class &n, mpz_class &e,
						  mpz_class &d, mpz_class &p, mpz_class &q) {
	gmp_randstate_t state;
	gmp_randinit_default(state);
	seed_randstate(state);

	size_t prime_bits = key_size / 2;
	mpz_class phi;

	e = 65537; // 常用公钥指数

	while (true) {
		p = generate_prime(prime_bits, state);
		q = generate_prime(prime_bits, state);
		if (p == q)
			continue; // 保证 p 和 q 不相等

		n = p * q;
		// 保证 n 为 key_size 位
		if (mpz_sizeinbase(n.get_mpz_t(), 2) != key_size)
			continue;
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

inline void generate_keys(size_t key_size, mpz_class &n, mpz_class &e,
						  mpz_class &d) {
	mpz_class p, q;
	generate_keys(key_size, n, e, d, p, q);
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
							const std::string &filename = "RSA_Public_Key.txt")
	-> void {
	std::ofstream ofs(filename);
	if (!ofs)
		throw std::runtime_error("无法打开文件 " + filename + " 进行写入");
	ofs << n << " " << e << std::endl;
	std::cout << "公钥已保存到 " << filename << std::endl;
}

inline auto save_private_key(const mpz_class &n, const mpz_class &d,
							 const std::string &filename = "RSA_Secret_Key.txt")
	-> void {
	std::ofstream ofs(filename);
	if (!ofs)
		throw std::runtime_error("无法打开文件 " + filename + " 进行写入");
	ofs << n << " " << d << std::endl;
	std::cout << "私钥已保存到 " << filename << std::endl;
}

// 将单个大整数以十进制保存
inline auto save_decimal(const mpz_class &value, const std::string &filename)
	-> void {
	std::ofstream ofs(filename);
	if (!ofs)
		throw std::runtime_error("无法打开文件 " + filename + " 进行写入");
	ofs << value << std::endl;
}

// 保存原始文本消息
inline auto save_text(const std::string &text, const std::string &filename)
	-> void {
	std::ofstream ofs(filename);
	if (!ofs)
		throw std::runtime_error("无法打开文件 " + filename + " 进行写入");
	ofs << text;
}

// 将密文以固定宽度小写十六进制保存（不带 0x，补足前导零）。
// modulus_bits 为 RSA 模数位数，1024-bit -> 256 个 hex 字符。
inline auto save_ciphertext_hex(const mpz_class &c, std::size_t modulus_bits,
								const std::string &filename) -> void {
	std::string hex = c.get_str(16);
	const std::size_t width = (modulus_bits + 3) / 4;
	if (hex.size() < width)
		hex.insert(hex.begin(), width - hex.size(), '0');
	std::ofstream ofs(filename);
	if (!ofs)
		throw std::runtime_error("无法打开文件 " + filename + " 进行写入");
	ofs << hex << std::endl;
}

inline auto read_public_key(mpz_class &n, mpz_class &e,
							const std::string &filename = "RSA_Public_Key.txt")
	-> void {
	std::ifstream ifs(filename);
	if (!ifs)
		throw std::runtime_error("无法打开文件 " + filename + " 进行读取");
	if (!(ifs >> n >> e))
		throw std::runtime_error("读取公钥文件失败: " + filename);
}

inline auto read_private_key(mpz_class &n, mpz_class &d,
							 const std::string &filename = "RSA_Secret_Key.txt")
	-> void {
	std::ifstream ifs(filename);
	if (!ifs)
		throw std::runtime_error("无法打开文件 " + filename + " 进行读取");
	if (!(ifs >> n >> d))
		throw std::runtime_error("读取私钥文件失败: " + filename);
}

} // namespace textbookRSA
