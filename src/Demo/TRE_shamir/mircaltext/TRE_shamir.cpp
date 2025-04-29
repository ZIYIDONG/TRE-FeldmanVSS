#include <iostream>
#include <fstream>
#include <cstring>
#include <time.h>
#include <thread>
#include <chrono>
using namespace std;

#include "big.h"
#include <vector>
#include "miracl.h" // ���� MIRACL ��
#include "mirdef.h"
#include "ecn.h"
#include "zzn.h"
#include "zzn2.h"

extern "C"
{
#include "miracl.h"
#include "mirdef.h"
}

FILE* __cdecl __iob_func(unsigned i) {
    return __acrt_iob_func(i);
}

#ifdef __cplusplus
extern "C"
#endif
FILE _iob[3] = { __iob_func(0)[0], __iob_func(1)[1], __iob_func(2)[2] };

#pragma comment(linker, "/NODEFAULTLIB:libc.lib")

#define HASH_LEN 64
#define PBITS 512
#define QBITS 160
#define N 5  // �ܷݶ���
#define K 4  // ����ֵ

Miracl precision(16, 0);

// ����ṹ��,ʱ���Լ��ܽ��
typedef struct Ciphertext {
    ECn C1;
    char C2[HASH_LEN];
} Ciphertext;

// ��������
Big H1(char* string);
int H2(ZZn2 x, char* s);
ECn map_to_point(char* ID);// ����ʶ��ӳ�䵽��Բ���ߵ�
BOOL ecap(ECn& P, ECn& Q, Big& order, ZZn2& cube, ZZn2& res);
BOOL fast_tate_pairing(ECn& P, ZZn2& Qx, ZZn2& Qy, Big& order, ZZn2& res);
Big getx(Big y);
void wait_until(const char* target_time);

void rand_int(Big& result, const Big& min, const Big& max);
Big eval_poly(const std::vector<Big>& poly, int k, const Big& x, const Big& p);
void generate_shares(const Big& secret, int n, int k, const Big& p, std::vector<Big>& x, std::vector<Big>& y);
Big lagrange_interpolation(const std::vector<Big>& x, const std::vector<Big>& y, int k, const Big& p);


// ������
int main() {

    miracl* mip = mirsys(20000, 16); // 20000 λ���ȣ�16 ����
    mip->IOBASE = 16; // �����������Ϊ 16 ����

    // ��ʼ���������
    long seed;  //���������ͱ����洢����
    std::cout<< "Enter 9 digit random number seed = ";
    cin >> seed;//ʹ��MIRACL�⺯����ʼ�������������
    irand(seed);

    // ������Բ���߲���
    Big q = pow((Big)2, 159) + pow((Big)2, 17) + 1; //��������q
    Big p, cof;// pΪ�������ɵ���Բ����������cofΪ������
    ZZn2 cube;// ������GF(p)���ϵ������������ڹ����ض�����
    ECn P, tSpub;// ��Բ�����ϵĻ���P��ʱ���������ԿtSpub
    Big s = rand(q);  // ʱ���������˽Կ
    Big r = rand(q);  // �����ߵ������

    // ������Բ���߲���
    Big t = (pow((Big)2, PBITS) - 1) / (2 * q); // PBITS��Ŀ������λ��������Ϊ256
    Big a = (pow((Big)2, PBITS - 1) - 1) / (2 * q);// �������a����ɸѡn
    Big n;
    //��������ѭ��
    forever{
        n = rand(t);
        if (n < a) continue;
        p = 2 * n * q - 1;
        if (p % 24 != 11) continue;  // must be 2 mod 3, also 3 mod 8 ��ȷ����Բ���߶���������GF(p)ʱ�����ض���ȫ�Ժ��Ż�ƽ��������Ч��
        if (prime(p)) break;
    }
    cof = 2 * n;  // ��Բ���������ӣ�n����֮ǰ��ѭ������
    ecurve(0, 1, p, MR_PROJECTIVE);  // ��ʼ����Բ���� y^2 = x^3 + 1 mod p��MR_PROJECTIVE��ʹ����Ӱ����ϵ�Ż�����

    // ������Բ�����ϵ�����Ԫ P
    forever{
        while (!P.set(randn()));// ���ѡ��x����ֱ���ҵ������ϵĵ�
        P *= cof;// ����������
        if (!P.iszero()) break;// ��֤�Ƿ�������������Ⱥ
    }

        // ʱ��������Ĺ�Կ tSpub = sP
    tSpub = s * P;

    std::cout << "Time Server's public key tSpub = sP: " << tSpub << endl;

    // ������Ϣ
    const char message[] = "06127A78 8E83386E F8FF1DD5 6B8CC7F4";
    char T[] = "20250425";  // ����ʱ��
    ECn H1_T = map_to_point(T);
    std::cout << "H1(T) mapped to point: " << H1_T << endl;

    ZZn2 e_P_H1_T;
    ecap(tSpub, H1_T, q, cube, e_P_H1_T);
    //std::cout << "e(tSpub, H1(T)): " << e_P_H1_T << endl;

    ZZn2 e_P_H1_T_r = pow(e_P_H1_T, r);
    //std::cout << "e(tSpub, H1(T))^r: " << e_P_H1_T_r << endl;

    char H2_e_P_H1_T_r[HASH_LEN];
    H2(e_P_H1_T_r, H2_e_P_H1_T_r);// ��˫���ԶԽ�����й�ϣ����
    std::cout << "H2(e(tSpub, H1(T))^r): ";// ��ʮ�����Ƹ�ʽ�����ϣֵ
    for (int i = 0; i < HASH_LEN; i++) {
        printf("%02x", (unsigned char)H2_e_P_H1_T_r[i]);
    }
    std::cout << endl;

    Ciphertext CT;
    CT.C1 = r * P;
    std::cout << "C1 = rP: " << CT.C1 << endl;
    Big x_, y_;
    CT.C1.get(x_, y_);
    //std::cout << "C1x " <<x_ << endl;
   

    for (int i = 0; i < HASH_LEN; i++) {
        CT.C2[i] = message[i] ^ H2_e_P_H1_T_r[i];// ������
    }

    std::cout << "C2 (encrypted message): ";

    for (int i = 0; i < HASH_LEN; i++) {
        printf("%02x",(unsigned char)CT.C2[i]);
    }
    std::cout << endl;

    std::string s1;
    //string s1;
    Big secret, secret1, secret2, prime;
    char secret_str[128];
    
    for (int i = 0; i < HASH_LEN; i++) {
        char buffer[3]; // ��ʱ�洢ÿ���ֽڵ�ʮ������
        snprintf(buffer, sizeof(buffer), "%02x", (unsigned char)CT.C2[i]);
        s1 += buffer; // ׷�ӵ��ַ���
    }
    std::cout << "s1: " << "("<<x_<<","<<y_<<")" << endl;
    std::cout << "s2: " << s1 <<endl;
    //char secret_str[] = s1;
    strncpy_s(secret_str, s1.c_str(), sizeof(secret_str) - 1);
    secret_str[sizeof(secret_str) - 1] = '\0'; // ��ȫ��ֹ
    
    char prime_str[] = "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    secret = Big(secret_str); // ʹ���ַ�����ʼ�� Big ����
    secret1 = x_;
	secret2 = y_;
    prime = Big(prime_str);   // ʹ���ַ�����ʼ�� Big ����
    //cout << "prime initialized: " << prime << endl;
    // cout << "secret: " << secret <<endl;
    
    if (secret >= prime || secret1 >= prime || secret2 >= prime) {
        std::cerr << "��������ֵ����С��������" << std::endl;
        return 1;
    }

    int n1 = N; // �ܷݶ���
    int k = K; // ����ֵ

    // ����洢�ݶ������
    std::vector<Big> x(n1), y(n1);
    std::vector<Big> x1(n1), y1(n1);
    std::vector<Big> x2(n1), y2(n1);

    // ���ɷݶ�
    generate_shares(secret, n1, k, prime, x, y);
    generate_shares(secret1, n1, k, prime, x1, y1);
    generate_shares(secret2, n1, k, prime, x2, y2);

    // ��ӡ�ݶ�
    std::cout << "Shares:\n";
    for (int i = 0; i < n1; i++) {
        std::cout << "(" << x[i] <<"," << "(" << y1[i] << ", " << y2[i] << ")" << "," << y[i] << ")\n";
    }

    // ��ԭ���ܣ�ʹ��ǰ k ���ݶ
    Big recovered_secret = lagrange_interpolation(x, y, k, prime);
    Big recovered_secret1 = lagrange_interpolation(x1, y1, k, prime);
    Big recovered_secret2 = lagrange_interpolation(x2, y2, k, prime);
    std::cout << "Recovered Secret: " << recovered_secret << std::endl;
    std::cout << "Recovered Secret1: " << recovered_secret1 << std::endl;
    std::cout << "Recovered Secret2: " << recovered_secret2 << std::endl;

    if (secret != recovered_secret || secret1 != recovered_secret1 || secret2 != recovered_secret2) {
        std::cout << "C2\C1����ʧ�ܣ��˳���" << std::endl;
        return 0;
    }

    // �ȴ�ֱ������ʱ�䵽��
    
    wait_until(T);
    // ������Ϣ
    char T_decrypt[] = "20250425";  // ����ʱ�䵽��
    ECn H1_T_decrypt = map_to_point(T_decrypt);
    //std::cout << "H1(T_decrypt) mapped to point: " << H1_T_decrypt << endl;

    ECn S_T = s * H1_T_decrypt;
    //std::cout << "S_T = s * H1(T_decrypt): " << S_T << endl;

    ZZn2 e_C1_S_T;
    ecap(CT.C1, S_T, q, cube, e_C1_S_T);
    //std::cout << "e(C1, S_T): " << e_C1_S_T << endl;

    char H2_e_C1_S_T[HASH_LEN];
    H2(e_C1_S_T, H2_e_C1_S_T);//������Կ
    std::cout << "H2(e(C1, S_T)): ";
    for (int i = 0; i < HASH_LEN; i++) {
        printf("%02x", (unsigned char)H2_e_C1_S_T[i]);
    }
    std::cout << endl;

    char decrypted_message[HASH_LEN];
    for (int i = 0; i < HASH_LEN; i++) {
        decrypted_message[i] = CT.C2[i] ^ H2_e_C1_S_T[i];
    }
    std::cout << "Decrypted message: " << decrypted_message << endl;

    return 0;
}


//TRE
// ��ϣ���� H1
Big H1(char* string) {      //�������ַ���ӳ�䵽�̶����ȵ�����
    Big h;
    char s[HASH_LEN];
    int i, j;
    sha256 sh;

    shs256_init(&sh);
    for (i = 0; string[i] != 0; i++) {
        shs256_process(&sh, string[i]);
    }
    shs256_hash(&sh, s);

    h = from_binary(HASH_LEN, s);
    return h;
}

// ��ϣ���� H2
int H2(ZZn2 x, char* s) {      //����չ��Ԫ�ع�ϣ��Ϊ�̶������ֽڴ�
    sha256 sh;
    Big a, b;
    int m;

    shs256_init(&sh);
    x.get(a, b);

    while (a > 0) {
        m = a % 256;
        shs256_process(&sh, m);
        a /= 256;
    }
    while (b > 0) {
        m = b % 256;
        shs256_process(&sh, m);
        b /= 256;
    }
    shs256_hash(&sh, s);

    return HASH_LEN;
}

// ӳ�䵽��Բ�����ϵĵ�
ECn map_to_point(char* ID) {
    ECn Q;
    Big x0, y0 = H1(ID);
    x0 = getx(y0);
    Q.set(x0, y0);
    return Q;
}

// ����˫���Զ�
BOOL ecap(ECn& P, ECn& Q, Big& order, ZZn2& cube, ZZn2& res) {
    ZZn2 Qx, Qy;
    Big xx, yy;
    Q.get(xx, yy);
    Qx = (ZZn)xx * cube;
    Qy = (ZZn)yy;

    if (fast_tate_pairing(P, Qx, Qy, order, res)) return TRUE;
    return FALSE;
}

// ʵ�� fast_tate_pairing
BOOL fast_tate_pairing(ECn& P, ZZn2& Qx, ZZn2& Qy, Big& order, ZZn2& res) {
    // ʵ�� Tate ����㷨
    res = pow(Qx, order);  
    return TRUE;
}

// ʵ�� getx
Big getx(Big y) {
    Big p = get_modulus();
    Big t = modmult(y + 1, y - 1, p);  // t = (y + 1) * (y - 1) mod p
    return pow(t, (2 * p - 1) / 3, p);  // x = t^{(2p-1)/3} mod p
}

// �ȴ�ֱ��ָ����ʱ��
void wait_until(const char* target_time) {
    time_t now;
    struct tm target_tm;
    time(&now);
    localtime_s(&target_tm, &now);

    // ����Ŀ��ʱ��
    sscanf_s(target_time, "%4d%2d%2d", &target_tm.tm_year, &target_tm.tm_mon, &target_tm.tm_mday);
    target_tm.tm_year -= 1900;  // tm_year �Ǵ� 1900 �꿪ʼ��
    target_tm.tm_mon -= 1;      // tm_mon �Ǵ� 0 ��ʼ��

    // ת��Ϊʱ���
    time_t target_time_t = mktime(&target_tm);
    int n = 0;
    // �ȴ�ֱ��Ŀ��ʱ�䵽��
    while (now < target_time_t) {
        if (n == 0) {
            printf("�ȴ�����ʱ����������������");
            n = 1;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
        time(&now);
    }
}


//shamir
//���������
void rand_int(Big& result, const Big& min, const Big& max) {
    Big range = max - min + 1;
    result = rand(range) + min;
}

// �������ʽ��ֵ f(x) = a0 + a1*x + a2*x^2 + ... + ak*x^k mod p
Big eval_poly(const std::vector<Big>& poly, int k, const Big& x, const Big& p) {
    Big result = 0;
    Big term, exponent;

    for (int i = 0; i <= k; i++) {
        exponent = i;
        term = pow(x, exponent, p); // term = x^i mod p
        term = (term * poly[i]) % p; // term *= poly[i]
        result = (result + term) % p; // result += term
    }

    return result;
}

// ���ɷݶ�
void generate_shares(const Big& secret, int n, int k, const Big& p, std::vector<Big>& x, std::vector<Big>& y) {
    std::vector<Big> poly(k);
    Big mod_secret = secret % p;  // ����ģ����ȷ������ֵ��������Χ��

    for (int i = 0; i < k; i++) {
        poly[i] = (i == 0) ? mod_secret : rand(p);
    }

    for (int i = 0; i < n; i++) {
        x[i] = i + 1;
        y[i] = eval_poly(poly, k - 1, x[i], p);
    }
}

// �������ղ�ֵ����ԭ����
Big lagrange_interpolation(const std::vector<Big>& x, const std::vector<Big>& y, int k, const Big& p) {
    Big result = 0;
    Big numerator, denominator, term, inv_denominator;

    for (int i = 0; i < k; i++) {
        numerator = 1;
        denominator = 1;

        for (int j = 0; j < k; j++) {
            if (j == i) continue;
            numerator = (numerator * x[j]) % p; // numerator *= x[j]
            term = (x[j] - x[i]) % p; // term = x[i] - x[j]
            denominator = (denominator * term) % p; // denominator *= term
        }

        // �����ĸ��ģ��Ԫ��
        inv_denominator = inverse(denominator, p); // inv_denominator = denominator^-1 mod p
        term = (y[i] * numerator) % p; // term = y[i] * numerator
        term = (term * inv_denominator) % p; // term *= inv_denominator
        result = (result + term) % p; // result += term
    }

    return (result + p) % p; // ȷ������ǷǸ���
}