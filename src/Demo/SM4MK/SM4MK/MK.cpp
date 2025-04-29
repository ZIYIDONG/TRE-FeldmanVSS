#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fstream>
#endif
#include <iostream>
#include <vector>
#include <iomanip>

int main() {
    std::vector<uint8_t> key(16); // 128位密钥

    // 使用系统安全的随机源生成密钥
#ifdef _WIN32
    HCRYPTPROV hProvider = 0;
    if (!CryptAcquireContext(&hProvider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "错误：无法获取加密上下文" << std::endl;
        return 1;
    }
    if (!CryptGenRandom(hProvider, static_cast<DWORD>(key.size()), key.data())) {
        std::cerr << "错误：生成随机数失败" << std::endl;
        CryptReleaseContext(hProvider, 0);
        return 1;
    }
    CryptReleaseContext(hProvider, 0);
#else
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom) {
        std::cerr << "错误：无法打开/dev/urandom" << std::endl;
        return 1;
    }
    urandom.read(reinterpret_cast<char*>(key.data()), key.size());
    if (urandom.gcount() != static_cast<std::streamsize>(key.size())) {
        std::cerr << "错误：读取随机数不完整" << std::endl;
        return 1;
    }
#endif

    // 输出十六进制格式的密钥
    std::cout << "生成的SM4密钥（十六进制）：";
    for (uint8_t byte : key) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl; // 恢复十进制输出

    return 0;
}