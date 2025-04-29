#pragma once
#ifdef __cplusplus
#endif
#include <stdbool.h>
#include <stdint.h>
#include <string>

void sm4_ecb_encrypt(const uint8_t key[16], size_t len, const uint8_t* plain, uint8_t* cipher);
void sm4_ecb_decrypt(const uint8_t key[16], size_t len, const uint8_t* cipher, uint8_t* plain);

void sm4_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* plain, uint8_t* cipher);
void sm4_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* cipher, uint8_t* plain);

void sm4_cfb_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* plain, uint8_t* cipher);
void sm4_cfb_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* cipher, uint8_t* plain);

void sm4_ofb_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* plain, uint8_t* cipher);
void sm4_ofb_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* cipher, uint8_t* plain);



#define SM4_MIN_MODE SM4_ECB_MODE
#define SM4_ECB_MODE 1
#define SM4_CBC_MODE 2
#define SM4_CFB_MODE 3
#define SM4_OFB_MODE 4
#define SM4_MAX_MODE SM4_OFB_MODE

typedef struct {
    uint32_t rkey[32];
    uint8_t iv[16];
    uint8_t mode;
} sm4_ctx_t;

void sm4_close(sm4_ctx_t* ctx);
int sm4_init(sm4_ctx_t* ctx, uint8_t mode, const uint8_t key[16], const uint8_t iv[16]);
int sm4_encrypt(sm4_ctx_t* ctx, size_t len, const uint8_t* plain, uint8_t* cipher);
int sm4_decrypt(sm4_ctx_t* ctx, size_t len, const uint8_t* cipher, uint8_t* plain);

# ifdef __cplusplus

# endif

// #ifndef __MasterEncoder_H__
#define __MasterEncoder_H__
#include <mutex>
#include <string>
using namespace std;
class MasterEncoder
{
public:
    static MasterEncoder* getInstance();
    MasterEncoder();
    ~MasterEncoder();

    void setSignAndKey(char* sign, int signLen, unsigned char key);

    void decode(unsigned char* data, long size);
    void encode(unsigned char* data, long size);

    void writePDF(const string& filePath, unsigned char* data, long size);
    unsigned char* readPDF(const string& filepath, long& size);

public:
    void encodePDF(const string& pdfPath, const string& savePath);
    void decodePDF(const string& pdfPath, const string& savePath);
    unsigned char* decodePDF(const string& pdfPath, long& size);

private:
    static MasterEncoder* _instance;
    static mutex _mtx;

    unsigned char _codeKey;
    char* _sign;
    int _signLen;

};
