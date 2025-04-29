#include "sm4.h"
#include <stdio.h>
#include<iostream>
/** SBox */
static const uint8_t SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
    0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
    0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
    0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
    0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
    0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
    0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
    0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
    0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
    0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
    0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
    0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
    0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
    0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
    0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
    0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};

/** 数据类型转换（char to int）八位（字节数组）转32位（字） */
static inline uint32_t _load_le_u32(const uint8_t bs[4]) {
    return *(uint32_t*)bs;
}
/** 数据类型转换（char to int）八位（字节数组）转32位（字） */
static inline uint32_t _load_be_u32(const uint8_t bs[4]) {
    return ((uint32_t)bs[0] << 24) | ((uint32_t)bs[1] << 16) | ((uint32_t)bs[2] << 8) | bs[3];
}
/** 数据类型转换（int to char）32位（字）转八位（字节数组） */
static inline void _store_le_u32(const uint32_t x, uint8_t bs[4]) {
    *(uint32_t*)bs = x;
}
/** 数据类型转换（int to char）32位（字）转八位（字节数组） */
static inline void _store_be_u32(const uint32_t x, uint8_t bs[4]) {
    bs[0] = (x >> 24) & 0xff;
    bs[1] = (x >> 16) & 0xff;
    bs[2] = (x >> 8) & 0xff;
    bs[3] = (x) & 0xff;
}
/** 数据类型转换（char to int）八位（字节数组）转64位*/
static inline void _store_le_u64(const uint64_t x, uint8_t bs[8]) {
    *(uint64_t*)bs = x;
}
/** 数据类型转换（char to int）八位（字节数组）转64位*/
static inline void _store_be_u64(const uint64_t x, uint8_t bs[8]) {
    bs[0] = (x >> 56) & 0xff;
    bs[1] = (x >> 48) & 0xff;
    bs[2] = (x >> 40) & 0xff;
    bs[3] = (x >> 32) & 0xff;
    bs[4] = (x >> 24) & 0xff;
    bs[5] = (x >> 16) & 0xff;
    bs[6] = (x >> 8) & 0xff;
    bs[7] = (x) & 0xff;
}
/**将x左移n位 */
static inline uint32_t _lshift(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}
/**将x右移n位 */
static inline uint32_t _rshift(uint32_t x, int n) {
    return (x << (32 - n)) | (x >> n);
}

/**求out和in按位异或的结果 结果存在out*/
static inline void _xor_block(uint8_t* out, const uint8_t* in, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        out[i] ^= in[i];
    }
}
/*转一位16进制*/
static inline char _hex(uint8_t n) {
    static const char HEX[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    return HEX[n];
}
// expand uint8 data to hex format in place, so data should have len * 2 space
//八位扩展到16位形式
static inline void _expand_hex(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        size_t j = len - 1 - i;
        uint8_t x = data[j];
        data[j * 2] = (uint8_t)_hex((x >> 4) & 0xf);
        data[j * 2 + 1] = (uint8_t)_hex(x & 0xf);
    }
}
/**
 * .
 *
 * \param x 32位输入
 * \return
 */
static uint32_t _sbox(uint32_t x) {
    uint8_t u[4];
    *(uint32_t*)u = x;
    u[0] = SBOX[u[0]];
    u[1] = SBOX[u[1]];
    u[2] = SBOX[u[2]];
    u[3] = SBOX[u[3]];
    return *(uint32_t*)u;
}

/** 线性变换L.输入输出都是32位的字*/
static inline uint32_t _st1(uint32_t x) {
    x = _sbox(x);
    return x ^ _lshift(x, 2) ^ _lshift(x, 10) ^ _lshift(x, 18) ^ _lshift(x, 24);
}

/** 密码扩展算法使用的线性变换.*/
static inline uint32_t _st2(uint32_t x) {
    x = _sbox(x);
    return x ^ _lshift(x, 13) ^ _lshift(x, 23);
}

/**常数FK*/
static const uint32_t FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
};

/**32个固定参数CK_i，每个CK_i是一个字*/
static const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

/**
 * 密钥扩展算法得到轮密钥.
 * \param key 初始密钥
 * \param rkey 轮密钥
 */
static void sm4_calc_key(const uint8_t key[16], uint32_t rkey[32]) {
    uint32_t x[5];
    /**
      * 将输入的密钥每32比特合并(得到MK_0,MK_1,MK_2,MK_3），
      */
    x[0] = _load_be_u32(key);
    x[1] = _load_be_u32(key + 4);
    x[2] = _load_be_u32(key + 8);
    x[3] = _load_be_u32(key + 12);
    /**
     * 并异或FK 得到（K_0,K_1,K_2,K_3）
    ( K_0,K_1,K_2,K_3)=(MK_0⊕FK_0,MK_1⊕FK_1,MK_2⊕FK_2,MK_3⊕FK_3)
     */
    x[0] ^= FK[0];
    x[1] ^= FK[1];
    x[2] ^= FK[2];
    x[3] ^= FK[3];
    /**
     * 32轮密钥拓展
     * For i=0,1,...,31 Do rk_i=K_(i+4)=K_i⊕T' (K_(i+1)⊕K_(i+2)⊕K_(i+3)⊕CK_i)
     */
    cout << "轮密钥生成！" << endl;

    for (int i = 0; i < 32; ++i) {
        uint32_t* y0 = x + (i % 5);
        uint32_t* y1 = x + ((i + 1) % 5);
        uint32_t* y2 = x + ((i + 2) % 5);
        uint32_t* y3 = x + ((i + 3) % 5);
        uint32_t* y4 = x + ((i + 4) % 5);

        *y4 = *y0 ^ _st2(*y1 ^ *y2 ^ *y3 ^ CK[i]);
        rkey[i] = *y4;
        cout << "第" << i + 1 << "个轮密钥: ";
        printf("%02x", rkey[i]);
        cout << endl;
    }

}

/**对轮密钥进行反序变换.*/
static inline void sm4_rev_key(uint32_t rkey[32]) {
    for (int i = 0; i < 16; ++i) {
        uint32_t t = rkey[i];
        rkey[i] = rkey[31 - i];
        rkey[31 - i] = t;
    }
}

/**
 * 用轮密钥对 in 加密 为 out
 * \param rkey
 * \param in
 * \param out
 */
static void sm4_calc_block(const uint32_t rkey[32], const uint8_t in[16], uint8_t out[16]) {
    /*
     cout << endl << "输 入 明 文： ";
     for (int i = 0; i < 16; i++)
         printf("%02x ", in[i]);
     cout << endl;
     */
    uint32_t x[5];
    // 将32比特数拆分成4个8比特数
    x[0] = _load_be_u32(in);
    x[1] = _load_be_u32(in + 4);
    x[2] = _load_be_u32(in + 8);
    x[3] = _load_be_u32(in + 12);

    for (int i = 0; i < 32; ++i) {
        uint32_t* y0 = x + (i % 5);
        uint32_t* y1 = x + ((i + 1) % 5);
        uint32_t* y2 = x + ((i + 2) % 5);
        uint32_t* y3 = x + ((i + 3) % 5);
        uint32_t* y4 = x + ((i + 4) % 5);
        //轮函数F(X_0, X_1, X_2, X_3, rk) = X_0⊕L(τ(X_1⊕X_2⊕X_3⊕rk))
       // cout << "第" << i+1 << "个轮密钥rkey["<<i<<"]: ";

        *y4 = *y0 ^ _st1(*y1 ^ *y2 ^ *y3 ^ rkey[i]);
        //cout << y1;
        /*
        cout << "第" << i + 1 << "轮输出: ";
        _store_be_u32(x[0], out);
        _store_be_u32(x[4], out + 4);
        _store_be_u32(x[3], out + 8);
        _store_be_u32(x[2], out + 12);
        printf("%02x ", x[2]);  printf("%02x ", x[3]); printf("%02x ", x[4]); printf("%02x ", x[0]);
        cout << endl;
        //printf("%02x ", y1); printf("%02x ", y2); printf("%02x ", y3); printf("%02x ", y4);
       */
    }
    _store_be_u32(x[0], out);
    _store_be_u32(x[4], out + 4);
    _store_be_u32(x[3], out + 8);
    _store_be_u32(x[2], out + 12);
    cout << "最终该分组加密结果(将第32轮结果反序后）：" << endl;
    // cout << "最终加密结果(将第32轮结果反序后）：" << endl;
    printf("%02x ", x[0]);  printf("%02x ", x[4]); printf("%02x ", x[3]); printf("%02x ", x[2]);
    cout << endl;
}


/** ECB模式 加密 （已生成的轮密钥做参数）（过程调用 功能函数）*/
static inline void _ecb(const uint32_t* rkey, size_t len, const uint8_t* in, uint8_t* out) {
    for (size_t i = 0; i < len; i += 16) {
        sm4_calc_block(rkey, in + i, out + i);//加密
    }
}

/**
 * ECB模式加密.（初始密钥做参数）
 * \param key 初始密钥
 * \param len
 * \param plain 明文
 * \param cipher 密文
 */
void sm4_ecb_encrypt(const uint8_t key[16], size_t len, const uint8_t* plain, uint8_t* cipher) {
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);//初始化轮密钥
    _ecb(rkey, len, plain, cipher);
    // memset(rkey, 0, sizeof(rkey));
}
/**
 * ECB模式解密
 * \param key 初始密钥
 * \param len
 * \param cipher 密文
 * \param plain 明文
 */
void sm4_ecb_decrypt(const uint8_t key[16], size_t len, const uint8_t* cipher, uint8_t* plain) {
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);//初始化轮密钥
    sm4_rev_key(rkey);
    _ecb(rkey, len, cipher, plain);
    // memset(rkey, 0, sizeof(rkey));
}

/**CBC模式 加密（已生成的轮密钥做参数）.工具函数 */
static inline void _cbc_encrypt(const uint32_t* rkey, uint8_t* iv, size_t len, const uint8_t* plain, uint8_t* cipher) {
    for (size_t i = 0; i < len; i += 16) {
        _xor_block(iv, plain + i, 16);//iv和plain异或  结果存在iv
        sm4_calc_block(rkey, iv, cipher + i); //加密
        memcpy(iv, cipher + i, 16);
    }
}

/** CBC 模式 解密 工具函数*/
static inline void _cbc_decrypt(const uint32_t* rkey, uint8_t* iv, size_t len, const uint8_t* cipher, uint8_t* plain) {
    for (size_t i = 0; i < len; i += 16) {
        sm4_calc_block(rkey, cipher + i, plain + i);
        _xor_block(plain + i, iv, 16);
        memcpy(iv, cipher + i, 16);
    }
}


/**
 * CBC 密码块链 (Cipher Block Chaining) 模式 加密
 * 无法单独对一个中间的明文分组进行加密
明文的微小改变会导致其后全部密文分组发生改变
 * \param key 初始密钥
 * \param iv 初始向量
 * \param len 分组数
 * \param plain 明文
 * \param cipher 密文
 */
void sm4_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* plain, uint8_t* cipher) {
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);//初始化轮密钥
    uint8_t out[16];
    memcpy(out, iv, 16);
    _cbc_encrypt(rkey, out, len, plain, cipher);
    // memset(rkey, 0, sizeof(rkey));
    // memset(out, 0, sizeof(out));
}

/**
 * CBC 密码块链 (Cipher Block Chaining) 模式 解密算法.
 * \param key 初始密钥
 * \param iv 初始向量
 * \param len 分组数
 * \param cipher 密文
 * \param plain 明文
 */
void sm4_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* cipher, uint8_t* plain) {
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    sm4_rev_key(rkey);
    uint8_t out[16];
    memcpy(out, iv, 16);
    _cbc_decrypt(rkey, out, len, cipher, plain);
    // memset(rkey, 0, sizeof(rkey));
    // memset(out, 0, sizeof(out));
}


/**
 * CFB模式 加密.（工具函数）
 加密：将前一个密文分组（或初始化向量 IV）进行再加密；
将明文分组和上一步处理得到的再加密的密文分组进行异或。
 */
static inline void _cfb_encrypt(const uint32_t* rkey, uint8_t* iv, size_t len, const uint8_t* plain, uint8_t* cipher) {
    for (size_t i = 0; i < len; i += 16) {
        sm4_calc_block(rkey, iv, cipher + i);
        _xor_block(cipher + i, plain + i, 16);
        memcpy(iv, cipher + i, 16);
    }
}


/**
 * CFB模式的解密过程几乎就是颠倒的CBC模式的加密过程。.
 * CFB模式 解密.（工具函数）
 * \param rkey
 * \param iv
 * \param len
 * \param cipher
 * \param plain
 */
static inline void _cfb_decrypt(const uint32_t* rkey, uint8_t* iv, size_t len, const uint8_t* cipher, uint8_t* plain) {
    for (size_t i = 0; i < len; i += 16) {
        sm4_calc_block(rkey, iv, plain + i);
        _xor_block(plain + i, cipher + i, 16);
        memcpy(iv, cipher + i, 16);
    }
}


/**
 * CFB模式 加密
 * \param key
 * \param iv
 * \param len
 * \param plain
 * \param cipher
 */
void sm4_cfb_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* plain, uint8_t* cipher) {
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    uint8_t out[16];
    memcpy(out, iv, 16);
    _cfb_encrypt(rkey, out, len, plain, cipher);
    // memset(rkey, 0, sizeof(rkey));
    // memset(out, 0, sizeof(out));
}
/**
 * CFB解密函数.
 * \param key 初始密钥
 * \param iv 初始向量
 * \param len 分组数
 * \param cipher 密文
 * \param plain 明文
 */
void sm4_cfb_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* cipher, uint8_t* plain) {
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    uint8_t out[16];
    memcpy(out, iv, 16);
    _cfb_decrypt(rkey, out, len, cipher, plain);
}


/**
 * .OFB模式 加密.（工具函数）
 * 加密：先将初始化向量 IV 用密钥加密生成密钥流
再将密钥流与明文流异或得到密文流
 * \param rkey
 * \param iv
 * \param len 明文分组数
 * \param in
 * \param out
 *//**OFB模式 加密.（工具函数）*/
static inline void _ofb(const uint32_t* rkey, uint8_t* iv, size_t len, const uint8_t* in, uint8_t* out) {
    for (size_t i = 0; i < len; i += 16) {
        sm4_calc_block(rkey, iv, out + i);
        memcpy(iv, out + i, 16);
        _xor_block(out + i, in + i, 16);
    }
}

/**
 * OFB模式 加密.
 * \param key 初始密钥
 * \param iv 初始向量
 * \param len 长度
 * \param plain 明文
 * \param cipher 密文
 */
void sm4_ofb_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* plain, uint8_t* cipher) {
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    uint8_t out[16];
    memcpy(out, iv, 16);
    _ofb(rkey, out, len, plain, cipher);
    // memset(rkey, 0, sizeof(rkey));
    // memset(out, 0, sizeof(out));
}
/**
 * OFB模式 解密
 * \param key 初始密钥
 * \param iv 初始向量
 * \param len 长度
 * \param cipher 密文
 * \param plain 明文
 */
void sm4_ofb_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* cipher, uint8_t* plain) {
    sm4_ofb_encrypt(key, iv, len, cipher, plain);
}


#define SM4_ENCRYPT 0x10
#define SM4_DECRYPT 0x20

void sm4_close(sm4_ctx_t* ctx) {
    memset(ctx, 0, sizeof(sm4_ctx_t));
}
/**
 * .SM4 初始化
 * \param ctx
 * \param mode 模式选择参数
 * \param key 初始密钥
 * \param iv 初始向量
 * \return
 */
int sm4_init(sm4_ctx_t* ctx, uint8_t mode, const uint8_t key[16], const uint8_t iv[16]) {
    if (mode < SM4_ECB_MODE || mode > SM4_OFB_MODE) {
        return -1;
    }
    if (mode == SM4_ECB_MODE && iv != NULL) {
        return -1;
    }
    if (mode != SM4_ECB_MODE && iv == NULL) {
        return -1;
    }
    ctx->mode = mode;
    sm4_calc_key(key, ctx->rkey);
    if (iv != NULL) {
        memcpy(ctx->iv, iv, 16);
    }
    else {
        memset(ctx->iv, 0, 16);
    }
    return 0;
}

/**
 * SM4加密 可选择四种方式.
 * \param ctx
 * \param len 长度
 * \param plain 明文
 * \param cipher 密文
 * \return
 */
int sm4_encrypt(sm4_ctx_t* ctx, size_t len, const uint8_t* plain, uint8_t* cipher) {
    if ((ctx->mode & 0xf0) == 0) {
        ctx->mode |= SM4_ENCRYPT;
    }
    if ((ctx->mode & 0xf0) != SM4_ENCRYPT) {
        return -1;
    }

    uint8_t m = ctx->mode & 0x0f;
    if (m == SM4_ECB_MODE) {
        _ecb(ctx->rkey, len, plain, cipher);
    }
    else if (m == SM4_CBC_MODE) {
        _cbc_encrypt(ctx->rkey, ctx->iv, len, plain, cipher);
    }
    else if (m == SM4_CFB_MODE) {
        _cfb_encrypt(ctx->rkey, ctx->iv, len, plain, cipher);
    }
    else if (m == SM4_OFB_MODE) {
        _ofb(ctx->rkey, ctx->iv, len, plain, cipher);
    }
    else {
        return -1;
    }
    return 0;
}

/**
 * SM4解密函数. 可选择四种工作模式
 * \param ctx 模式选择等函数
 * \param len 长度
 * \param cipher 密文
 * \param plain 明文
 * \return
 */
int sm4_decrypt(sm4_ctx_t* ctx, size_t len, const uint8_t* cipher, uint8_t* plain) {
    uint8_t m = ctx->mode & 0x0f;
    if ((ctx->mode & 0xf0) == 0) {
        ctx->mode |= SM4_DECRYPT;
        if (m != SM4_CFB_MODE && m != SM4_OFB_MODE) {
            sm4_rev_key(ctx->rkey);
        }
    }
    if ((ctx->mode & 0xf0) != SM4_DECRYPT) {
        return -1;
    }

    if (m == SM4_ECB_MODE) {
        _ecb(ctx->rkey, len, cipher, plain);
    }
    else if (m == SM4_CBC_MODE) {
        _cbc_decrypt(ctx->rkey, ctx->iv, len, cipher, plain);
    }
    else if (m == SM4_CFB_MODE) {
        _cfb_decrypt(ctx->rkey, ctx->iv, len, cipher, plain);
    }
    else if (m == SM4_OFB_MODE) {
        _ofb(ctx->rkey, ctx->iv, len, cipher, plain);
    }
    else {
        return -1;
    }
    return 0;
}
