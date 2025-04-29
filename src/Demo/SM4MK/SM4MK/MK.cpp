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
    std::vector<uint8_t> key(16); // 128λ��Կ

    // ʹ��ϵͳ��ȫ�����Դ������Կ
#ifdef _WIN32
    HCRYPTPROV hProvider = 0;
    if (!CryptAcquireContext(&hProvider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "�����޷���ȡ����������" << std::endl;
        return 1;
    }
    if (!CryptGenRandom(hProvider, static_cast<DWORD>(key.size()), key.data())) {
        std::cerr << "�������������ʧ��" << std::endl;
        CryptReleaseContext(hProvider, 0);
        return 1;
    }
    CryptReleaseContext(hProvider, 0);
#else
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom) {
        std::cerr << "�����޷���/dev/urandom" << std::endl;
        return 1;
    }
    urandom.read(reinterpret_cast<char*>(key.data()), key.size());
    if (urandom.gcount() != static_cast<std::streamsize>(key.size())) {
        std::cerr << "���󣺶�ȡ�����������" << std::endl;
        return 1;
    }
#endif

    // ���ʮ�����Ƹ�ʽ����Կ
    std::cout << "���ɵ�SM4��Կ��ʮ�����ƣ���";
    for (uint8_t byte : key) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl; // �ָ�ʮ�������

    return 0;
}