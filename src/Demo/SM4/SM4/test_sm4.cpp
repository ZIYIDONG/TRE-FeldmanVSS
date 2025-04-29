#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

// ===================== SM4完整常量定义 =====================
static const uint8_t SBOX[256] = {
    0xD6,0x90,0xE9,0xFE,0xCC,0xE1,0x3D,0xB7,0x16,0xB6,0x14,0xC2,0x28,0xFB,0x2C,0x05,
    0x2B,0x67,0x9A,0x76,0x2A,0xBE,0x04,0xC3,0xAA,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9C,0x42,0x50,0xF4,0x91,0xEF,0x98,0x7A,0x33,0x54,0x0B,0x43,0xED,0xCF,0xAC,0x62,
    0xE4,0xB3,0x1C,0xA9,0xC9,0x08,0xE8,0x95,0x80,0xDF,0x94,0xFA,0x75,0x8F,0x3F,0xA6,
    0x47,0x07,0xA7,0xFC,0xF3,0x73,0x17,0xBA,0x83,0x59,0x3C,0x19,0xE6,0x85,0x4F,0xA8,
    0x68,0x6B,0x81,0xB2,0x71,0x64,0xDA,0x8B,0xF8,0xEB,0x0F,0x4B,0x70,0x56,0x9D,0x35,
    0x1E,0x24,0x0E,0x5E,0x63,0x58,0xD1,0xA2,0x25,0x22,0x7C,0x3B,0x01,0x21,0x78,0x87,
    0xD4,0x00,0x46,0x57,0x9F,0xD3,0x27,0x52,0x4C,0x36,0x02,0xE7,0xA0,0xC4,0xC8,0x9E,
    0xEA,0xBF,0x8A,0xD2,0x40,0xC7,0x38,0xB5,0xA3,0xF7,0xF2,0xCE,0xF9,0x61,0x15,0xA1,
    0xE0,0xAE,0x5D,0xA4,0x9B,0x34,0x1A,0x55,0xAD,0x93,0x32,0x30,0xF5,0x8C,0xB1,0xE3,
    0x1D,0xF6,0xE2,0x2E,0x82,0x66,0xCA,0x60,0xC0,0x29,0x23,0xAB,0x0D,0x53,0x4E,0x6F,
    0xD5,0xDB,0x37,0x45,0xDE,0xFD,0x8E,0x2F,0x03,0xFF,0x6A,0x72,0x6D,0x6C,0x5B,0x51,
    0x8D,0x1B,0xAF,0x92,0xBB,0xDD,0xBC,0x7F,0x11,0xD9,0x5C,0x41,0x1F,0x10,0x5A,0xD8,
    0x0A,0xC1,0x31,0x88,0xA5,0xCD,0x7B,0xBD,0x2D,0x74,0xD0,0x12,0xB8,0xE5,0xB4,0xB0,
    0x89,0x69,0x97,0x4A,0x0C,0x96,0x77,0x7E,0x65,0xB9,0xF1,0x09,0xC5,0x6E,0xC6,0x84,
    0x18,0xF0,0x7D,0xEC,0x3A,0xDC,0x4D,0x20,0x79,0xEE,0x5F,0x3E,0xD7,0xCB,0x39,0x48
};

static const uint32_t CK[32] = {
    0x00070E15,0x1C232A31,0x383F464D,0x545B6269,
    0x70777E85,0x8C939AA1,0xA8AFB6BD,0xC4CBD2D9,
    0xE0E7EEF5,0xFC030A11,0x181F262D,0x343B4249,
    0x50575E65,0x6C737A81,0x888F969D,0xA4ABB2B9,
    0xC0C7CED5,0xDCE3EAF1,0xF8FF060D,0x141B2229,
    0x30373E45,0x4C535A61,0x686F767D,0x848B9299,
    0xA0A7AEB5,0xBCC3CAD1,0xD8DFE6ED,0xF4FB0209,
    0x10171E25,0x2C333A41,0x484F565D,0x646B7279
};

static const uint32_t FK[4] = { 0xA3B1BAC6,0x56AA3350,0x677D9197,0xB27022DC };

// ===================== 核心算法实现 =====================
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static uint32_t L_transform(uint32_t data) {
    return data ^ ROTL32(data, 2) ^ ROTL32(data, 10) ^ ROTL32(data, 18) ^ ROTL32(data, 24);
}

static uint32_t T_transform(uint32_t data) {
    uint8_t bytes[4] = {
        SBOX[(data >> 24) & 0xFF],
        SBOX[(data >> 16) & 0xFF],
        SBOX[(data >> 8) & 0xFF],
        SBOX[data & 0xFF]
    };
    return L_transform((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
}

void sm4_key_expansion(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t k[36];
    for (int i = 0; i < 4; i++)
        k[i] = ((uint32_t)key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3] ^ FK[i];

    for (int i = 0; i < 32; i++) {
        k[i + 4] = k[i] ^ T_transform(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
        rk[i] = k[i + 4];
    }
}

// ===================== 文件操作 =====================
int validate_file_path(const char* path) {
    struct stat buffer;
    if (stat(path, &buffer) != 0) {
        printf("路径验证失败: %s\n", path);
        perror("    ├─ 系统错误详情");
        printf("    └─ 请检查:\n");
        printf("        1. 路径是否存在 (注意大小写)\n");
        printf("        2. 文件名是否正确 (当前路径: %s)\n", path);
        printf("        3. 文件扩展名是否完整 (如.txt)\n");
        return -1;
    }
    return 0;
}

int sm4_ecb_crypt_file(int encrypt_mode, const char* in_path, const char* out_path, const uint8_t key[16]) {
    // 前置验证
    if (validate_file_path(in_path) != 0) return -1;

    FILE* fin = fopen(in_path, "rb");
    FILE* fout = fopen(out_path, "wb");
    uint32_t rk[32];
    sm4_key_expansion(key, rk);

    // 设置轮密钥顺序
    if (!encrypt_mode) {
        for (int i = 0; i < 16; i++) {
            uint32_t temp = rk[i];
            rk[i] = rk[31 - i];
            rk[31 - i] = temp;
        }
    }

    uint8_t block[16];
    size_t bytes_read;
    long total_read = 0;

    while ((bytes_read = fread(block, 1, 16, fin)) > 0) {
        total_read += bytes_read;

        // 加密时填充处理
        if (encrypt_mode && bytes_read < 16) {
            uint8_t pad = 16 - bytes_read;
            memset(block + bytes_read, pad, 16 - bytes_read);
        }

        // 加密/解密处理
        uint32_t x[36];
        for (int i = 0; i < 4; i++)
            x[i] = (block[4 * i] << 24) | (block[4 * i + 1] << 16) | (block[4 * i + 2] << 8) | block[4 * i + 3];

        for (int i = 0; i < 32; i++)
            x[i + 4] = x[i] ^ T_transform(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]);

        for (int i = 0; i < 4; i++) {
            block[4 * i] = (x[35 - i] >> 24) & 0xFF;
            block[4 * i + 1] = (x[35 - i] >> 16) & 0xFF;
            block[4 * i + 2] = (x[35 - i] >> 8) & 0xFF;
            block[4 * i + 3] = x[35 - i] & 0xFF;
        }

        // 解密时移除填充
        size_t write_size = 16;
        if (!encrypt_mode && ftell(fin) == 0) {
            uint8_t pad = block[15];
            if (pad <= 16) write_size = 16 - pad;
        }

        fwrite(block, 1, write_size, fout);
    }

    fclose(fin);
    fclose(fout);
    return 0;
}

// ===================== 主程序逻辑 =====================
int main() {
    // 文件路径配置
    const char* DOC_PATH = "D:\\zbwj.txt";       // 原文件
    const char* ENC_PATH = "D:\\zbwj.enc";      // 加密文件
    const char* DEC_PATH = "D:\\zbwj_dec.txt";  // 解密文件

    // 原始密钥配置
    const uint8_t ORIGINAL_KEY[16] = {
        0x06,0x12,0x7a,0x78, 0x8e,0x83,0x38,0x6e,
        0xf8,0xff,0x1d,0xd5, 0x6b,0x8c,0xc7,0xf4
    };

    // 加密阶段
    printf(" 开始加密操作...\n");
    if (sm4_ecb_crypt_file(1, DOC_PATH, ENC_PATH, ORIGINAL_KEY) == 0) {
        printf("加密成功!\n   加密文件: %s\n", ENC_PATH);
    }
    else {
        printf("加密失败，请检查输入文件路径\n");
        return 1;
    }

    // 密钥验证
    printf("\n请输入解密密钥(06127A78 8E83386E F8FF1DD5 6B8CC7F4)\n> ");
    uint32_t input_keys[4];
    if (scanf("%8x %8x %8x %8x", &input_keys[0], &input_keys[1], &input_keys[2], &input_keys[3]) != 4) {
        printf("输入格式错误，请按空格分隔输入4个数字\n");
        return 1;
    }

    // 密钥转换
    uint8_t user_key[16];
    for (int i = 0; i < 4; i++) {
        user_key[4 * i] = (input_keys[i] >> 24) & 0xFF;
        user_key[4 * i + 1] = (input_keys[i] >> 16) & 0xFF;
        user_key[4 * i + 2] = (input_keys[i] >> 8) & 0xFF;
        user_key[4 * i + 3] = input_keys[i] & 0xFF;
    }

    // 密钥比对
    if (memcmp(user_key, ORIGINAL_KEY, 16) != 0) {
        printf("密钥验证失败，请检查输入值\n");
        printf("输入密钥: ");
        for (int i = 0; i < 16; i++) printf("%02X", user_key[i]);
        printf("\n正确密钥: ");
        for (int i = 0; i < 16; i++) printf("%02X", ORIGINAL_KEY[i]);
        printf("\n");
        return 1;
    }

    // 解密阶段
    printf("\n开始解密操作...\n");
    if (sm4_ecb_crypt_file(0, ENC_PATH, DEC_PATH, user_key) == 0) {
        printf("解密成功!\n   解密文件: %s\n", DEC_PATH);
    }
    else {
        printf("解密失败\n");
    }

    return 0;
}