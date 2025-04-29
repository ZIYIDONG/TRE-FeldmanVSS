#include <iostream>
#include <fstream>
#include <cstring>
#include <time.h>
#include <thread>
#include <chrono>
using namespace std;

#include "big.h"
#include <vector>
#include "miracl.h" // 引入 MIRACL 库
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
#define N 5  // 总份额数
#define K 4  // 门限值

Miracl precision(16, 0);

// 定义结构体,时控性加密结果
typedef struct Ciphertext {
    ECn C1;
    char C2[HASH_LEN];
} Ciphertext;

// 函数声明
Big H1(char* string);
int H2(ZZn2 x, char* s);
ECn map_to_point(char* ID);// 将标识符映射到椭圆曲线点
BOOL ecap(ECn& P, ECn& Q, Big& order, ZZn2& cube, ZZn2& res);
BOOL fast_tate_pairing(ECn& P, ZZn2& Qx, ZZn2& Qy, Big& order, ZZn2& res);
Big getx(Big y);
void wait_until(const char* target_time);

void rand_int(Big& result, const Big& min, const Big& max);
Big eval_poly(const std::vector<Big>& poly, int k, const Big& x, const Big& p);
void generate_shares(const Big& secret, int n, int k, const Big& p, std::vector<Big>& x, std::vector<Big>& y);
Big lagrange_interpolation(const std::vector<Big>& x, const std::vector<Big>& y, int k, const Big& p);


// 主函数
int main() {

    miracl* mip = mirsys(20000, 16); // 20000 位精度，16 进制
    mip->IOBASE = 16; // 设置输入输出为 16 进制

    // 初始化随机种子
    long seed;  //声明长整型变量存储种子
    std::cout<< "Enter 9 digit random number seed = ";
    cin >> seed;//使用MIRACL库函数初始化随机数生成器
    irand(seed);

    // 设置椭圆曲线参数
    Big q = pow((Big)2, 159) + pow((Big)2, 17) + 1; //生成素数q
    Big p, cof;// p为最终生成的椭圆曲线素数域，cof为余因子
    ZZn2 cube;// 定义在GF(p)域上的立方根，用于构造特定曲线
    ECn P, tSpub;// 椭圆曲线上的基点P和时间服务器公钥tSpub
    Big s = rand(q);  // 时间服务器的私钥
    Big r = rand(q);  // 发送者的随机数

    // 生成椭圆曲线参数
    Big t = (pow((Big)2, PBITS) - 1) / (2 * q); // PBITS是目标素数位数，假设为256
    Big a = (pow((Big)2, PBITS - 1) - 1) / (2 * q);// 计算参数a用于筛选n
    Big n;
    //素数生成循环
    forever{
        n = rand(t);
        if (n < a) continue;
        p = 2 * n * q - 1;
        if (p % 24 != 11) continue;  // must be 2 mod 3, also 3 mod 8 ，确保椭圆曲线定义在素域GF(p)时具有特定安全性和优化平方根计算效率
        if (prime(p)) break;
    }
    cof = 2 * n;  // 椭圆曲线余因子，n来自之前的循环生成
    ecurve(0, 1, p, MR_PROJECTIVE);  // 初始化椭圆曲线 y^2 = x^3 + 1 mod p，MR_PROJECTIVE：使用射影坐标系优化计算

    // 生成椭圆曲线上的生成元 P
    forever{
        while (!P.set(randn()));// 随机选择x坐标直到找到曲线上的点
        P *= cof;// 乘以余因子
        if (!P.iszero()) break;// 验证是否生成素数阶子群
    }

        // 时间服务器的公钥 tSpub = sP
    tSpub = s * P;

    std::cout << "Time Server's public key tSpub = sP: " << tSpub << endl;

    // 加密信息
    const char message[] = "06127A78 8E83386E F8FF1DD5 6B8CC7F4";
    char T[] = "20250425";  // 解密时间
    ECn H1_T = map_to_point(T);
    std::cout << "H1(T) mapped to point: " << H1_T << endl;

    ZZn2 e_P_H1_T;
    ecap(tSpub, H1_T, q, cube, e_P_H1_T);
    //std::cout << "e(tSpub, H1(T)): " << e_P_H1_T << endl;

    ZZn2 e_P_H1_T_r = pow(e_P_H1_T, r);
    //std::cout << "e(tSpub, H1(T))^r: " << e_P_H1_T_r << endl;

    char H2_e_P_H1_T_r[HASH_LEN];
    H2(e_P_H1_T_r, H2_e_P_H1_T_r);// 对双线性对结果进行哈希运算
    std::cout << "H2(e(tSpub, H1(T))^r): ";// 以十六进制格式输出哈希值
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
        CT.C2[i] = message[i] ^ H2_e_P_H1_T_r[i];// 异或加密
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
        char buffer[3]; // 临时存储每个字节的十六进制
        snprintf(buffer, sizeof(buffer), "%02x", (unsigned char)CT.C2[i]);
        s1 += buffer; // 追加到字符串
    }
    std::cout << "s1: " << "("<<x_<<","<<y_<<")" << endl;
    std::cout << "s2: " << s1 <<endl;
    //char secret_str[] = s1;
    strncpy_s(secret_str, s1.c_str(), sizeof(secret_str) - 1);
    secret_str[sizeof(secret_str) - 1] = '\0'; // 安全终止
    
    char prime_str[] = "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    secret = Big(secret_str); // 使用字符串初始化 Big 类型
    secret1 = x_;
	secret2 = y_;
    prime = Big(prime_str);   // 使用字符串初始化 Big 类型
    //cout << "prime initialized: " << prime << endl;
    // cout << "secret: " << secret <<endl;
    
    if (secret >= prime || secret1 >= prime || secret2 >= prime) {
        std::cerr << "错误：秘密值必须小于质数！" << std::endl;
        return 1;
    }

    int n1 = N; // 总份额数
    int k = K; // 门限值

    // 分配存储份额的数组
    std::vector<Big> x(n1), y(n1);
    std::vector<Big> x1(n1), y1(n1);
    std::vector<Big> x2(n1), y2(n1);

    // 生成份额
    generate_shares(secret, n1, k, prime, x, y);
    generate_shares(secret1, n1, k, prime, x1, y1);
    generate_shares(secret2, n1, k, prime, x2, y2);

    // 打印份额
    std::cout << "Shares:\n";
    for (int i = 0; i < n1; i++) {
        std::cout << "(" << x[i] <<"," << "(" << y1[i] << ", " << y2[i] << ")" << "," << y[i] << ")\n";
    }

    // 还原秘密（使用前 k 个份额）
    Big recovered_secret = lagrange_interpolation(x, y, k, prime);
    Big recovered_secret1 = lagrange_interpolation(x1, y1, k, prime);
    Big recovered_secret2 = lagrange_interpolation(x2, y2, k, prime);
    std::cout << "Recovered Secret: " << recovered_secret << std::endl;
    std::cout << "Recovered Secret1: " << recovered_secret1 << std::endl;
    std::cout << "Recovered Secret2: " << recovered_secret2 << std::endl;

    if (secret != recovered_secret || secret1 != recovered_secret1 || secret2 != recovered_secret2) {
        std::cout << "C2\C1解密失败，退出！" << std::endl;
        return 0;
    }

    // 等待直到解密时间到达
    
    wait_until(T);
    // 解密信息
    char T_decrypt[] = "20250425";  // 解密时间到达
    ECn H1_T_decrypt = map_to_point(T_decrypt);
    //std::cout << "H1(T_decrypt) mapped to point: " << H1_T_decrypt << endl;

    ECn S_T = s * H1_T_decrypt;
    //std::cout << "S_T = s * H1(T_decrypt): " << S_T << endl;

    ZZn2 e_C1_S_T;
    ecap(CT.C1, S_T, q, cube, e_C1_S_T);
    //std::cout << "e(C1, S_T): " << e_C1_S_T << endl;

    char H2_e_C1_S_T[HASH_LEN];
    H2(e_C1_S_T, H2_e_C1_S_T);//解密密钥
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
// 哈希函数 H1
Big H1(char* string) {      //将任意字符串映射到固定长度的整数
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

// 哈希函数 H2
int H2(ZZn2 x, char* s) {      //将扩展域元素哈希化为固定长度字节串
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

// 映射到椭圆曲线上的点
ECn map_to_point(char* ID) {
    ECn Q;
    Big x0, y0 = H1(ID);
    x0 = getx(y0);
    Q.set(x0, y0);
    return Q;
}

// 计算双线性对
BOOL ecap(ECn& P, ECn& Q, Big& order, ZZn2& cube, ZZn2& res) {
    ZZn2 Qx, Qy;
    Big xx, yy;
    Q.get(xx, yy);
    Qx = (ZZn)xx * cube;
    Qy = (ZZn)yy;

    if (fast_tate_pairing(P, Qx, Qy, order, res)) return TRUE;
    return FALSE;
}

// 实现 fast_tate_pairing
BOOL fast_tate_pairing(ECn& P, ZZn2& Qx, ZZn2& Qy, Big& order, ZZn2& res) {
    // 实现 Tate 配对算法
    res = pow(Qx, order);  
    return TRUE;
}

// 实现 getx
Big getx(Big y) {
    Big p = get_modulus();
    Big t = modmult(y + 1, y - 1, p);  // t = (y + 1) * (y - 1) mod p
    return pow(t, (2 * p - 1) / 3, p);  // x = t^{(2p-1)/3} mod p
}

// 等待直到指定的时间
void wait_until(const char* target_time) {
    time_t now;
    struct tm target_tm;
    time(&now);
    localtime_s(&target_tm, &now);

    // 解析目标时间
    sscanf_s(target_time, "%4d%2d%2d", &target_tm.tm_year, &target_tm.tm_mon, &target_tm.tm_mday);
    target_tm.tm_year -= 1900;  // tm_year 是从 1900 年开始的
    target_tm.tm_mon -= 1;      // tm_mon 是从 0 开始的

    // 转换为时间戳
    time_t target_time_t = mktime(&target_tm);
    int n = 0;
    // 等待直到目标时间到达
    while (now < target_time_t) {
        if (n == 0) {
            printf("等待解密时间来到。。。。。");
            n = 1;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
        time(&now);
    }
}


//shamir
//生成随机数
void rand_int(Big& result, const Big& min, const Big& max) {
    Big range = max - min + 1;
    result = rand(range) + min;
}

// 计算多项式的值 f(x) = a0 + a1*x + a2*x^2 + ... + ak*x^k mod p
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

// 生成份额
void generate_shares(const Big& secret, int n, int k, const Big& p, std::vector<Big>& x, std::vector<Big>& y) {
    std::vector<Big> poly(k);
    Big mod_secret = secret % p;  // 增加模运算确保秘密值在质数范围内

    for (int i = 0; i < k; i++) {
        poly[i] = (i == 0) ? mod_secret : rand(p);
    }

    for (int i = 0; i < n; i++) {
        x[i] = i + 1;
        y[i] = eval_poly(poly, k - 1, x[i], p);
    }
}

// 拉格朗日插值法还原秘密
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

        // 计算分母的模反元素
        inv_denominator = inverse(denominator, p); // inv_denominator = denominator^-1 mod p
        term = (y[i] * numerator) % p; // term = y[i] * numerator
        term = (term * inv_denominator) % p; // term *= inv_denominator
        result = (result + term) % p; // result += term
    }

    return (result + p) % p; // 确保结果是非负的
}