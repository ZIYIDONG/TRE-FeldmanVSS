/*
   Boneh & Franklin's Identity Based Encryption
   
   Set-up phase

   After this program has run the file common.ibe contains

   <Size of prime modulus in bits>
   <Prime p>
   <Prime q (divides p+1) >
   <Point P - x coordinate>
   <Point P - y coordinate>
   <Point Ppub - x coordinate>
   <Point Ppub - y coordinate>
   <Cube root of unity in Fp2 - x component >
   <Cube root of unity in Fp2 - y component >

   The file master.ibe contains

   <The master secret s>

   Requires: zzn2.cpp big.cpp zzn.cpp ecn.cpp

 */
#include <time.h>
#include <iostream>
#include <fstream>
#include <cstring>
using namespace std;

#include "ecn.h"
#include "zzn.h"
#include "zzn2.h"

//C++���������߱������ⲿ�ִ�����C���Ա�д�ģ����������ʱӦ��ʹ��C���Ե�����Լ��
extern "C"
{
   #include"miracl.h"
   #include"mirdef.h"
}

//2015�����
//�ṩһ�������Բ�,Ϊ���ڲ�ͬ�汾��MSVC����ʱ��֮���ṩһ�ּ����Ի��ƣ�ʹ�þɴ����ܹ����°汾�Ŀ����������У�������Ҫ�Դ�����д����޸ġ�
FILE* __cdecl __iob_func(unsigned i) {
    return __acrt_iob_func(i);
}

#ifdef __cplusplus
extern "C" 
#endif
//extern "C" { FILE __iob_func[3] = { *stdin,*stdout,*stderr }; }
FILE _iob[3] = {__iob_func(0)[0], __iob_func(1)[1], __iob_func(2)[2]}; 

//һ���ض���Microsoft Visual C++��������ָ����ڿ�������������Ϊ�����������Ǹ��������������ӹ����в�ҪĬ�����ӵ�libc.lib����⡣
#pragma comment(linker, "/NODEFAULTLIB:libc.lib")


#define renum 10001

#define HASH_LEN 32
#define HASH_LEN1 20   //������H2����Ϊ��������q��160λ�Ķ�����������160/8=20
                                        //H2�в���sha256Ҫ��HASH_LEN1 ������32�ı�������ˣ��Լ���H2�ڲ��������Ϊsha-1


#define PBITS 512
#define QBITS 160

// Using SHA-256 as basic hash algorithm

//
// Define one or the other of these
//
// Which is faster depends on the I/M ratio - See imratio.c
// Roughly if I/M ratio > 16 use PROJECTIVE, otherwise use AFFINE
//

// #define AFFINE
#define PROJECTIVE

// Define this to use this idea ftp://ftp.computing.dcu.ie/pub/resources/crypto/short.pdf
// which enables denominator elimination
#define SCOTT

Miracl precision(16,0);  // increase if PBITS increases. (32,0) for 1024 bit p

/*----------------------------------------------------------------------------Tate Paring ��������Ҫ�ĺ���-----------------------------------------------------*/
void extract(ECn& A,ZZn& x,ZZn& y)  //��������
{ 
    x=(A.get_point())->X;
    y=(A.get_point())->Y;
}

void extract(ECn& A,ZZn& x,ZZn& y,ZZn& z)  //��Ӱ����
{ 
    big t;
    x=(A.get_point())->X;
    y=(A.get_point())->Y;
    t=(A.get_point())->Z;
    if (A.get_status()!=MR_EPOINT_GENERAL) 
        z=1;
    else                                   
        z=t;
}

//
// Line from A to destination C. Let A=(x,y)
// Line Y-slope.X-c=0, through A, so intercept c=y-slope.x
// Line Y-slope.X-y+slope.x = (Y-y)-slope.(X-x) = 0
// Now evaluate at Q -> return (Qy-y)-slope.(Qx-x)
//

ZZn2 line(ECn& A, ECn& C, ZZn& slope, ZZn2& Qx, ZZn2& Qy)  //������Բ�����ϵĵ�Q��A��C��ֱ��
{ 
    ZZn2 n=Qx,w=Qy;
    ZZn x,y,z,t;
#ifdef AFFINE
    extract(A,x,y);
    n-=x; n*=slope;            // 2 ZZn muls
    w-=y; n-=w;
#endif
#ifdef PROJECTIVE
    extract(A,x,y,z);
    x*=z; t=z; z*=z; z*=t;          
    n*=z; n-=x;                // 9 ZZn muls
    w*=z; w-=y; 
    extract(C,x,y,z);
    w*=z; n*=slope; n-=w;                     
#endif
    return n;
}

#ifndef SCOTT

//
// Vertical line through point A
//

ZZn2 vertical(ECn& A,ZZn2& Qx)
{
    ZZn2 n=Qx;
    ZZn x,y,z;
#ifdef AFFINE
    extract(A,x,y);
    n-=x;
#endif
#ifdef PROJECTIVE
    extract(A,x,y,z);
    z*=z;                    
    n*=z; n-=x;                // 3 ZZn muls
#endif
    return n;
}

#endif

//
// Add A=A+B  (or A=A+A) 
// Bump up num and denom
//
// AFFINE doubling     - 12 ZZn muls, plus 1 inversion
// AFFINE adding       - 11 ZZn muls, plus 1 inversion
//
// PROJECTIVE doubling - 26 ZZn muls
// PROJECTIVE adding   - 34 ZZn muls
//


void g(ECn& A,ECn& B,ZZn2& Qx,ZZn2& Qy,ZZn2& num) 
{
    ZZn  lam,mQy;
    ZZn2 d,u;
    big ptr;
    ECn P=A;

// Evaluate line from A
    ptr=A.add(B);

#ifndef SCOTT
    if (A.iszero())   { u=vertical(P,Qx); d=1; }
    else
    {
#endif
        if (ptr==NULL)
            u=1;
        else 
        {
            lam=ptr;
            u=line(P,A,lam,Qx,Qy);
        }
#ifndef SCOTT
        d=vertical(A,Qx);
    }

    num*=(u*conj(d));    // 6 ZZn muls  
#else
// denominator elimination!
    num*=u;
#endif
}

//
// Tate Pairing 
//

BOOL fast_tate_pairing(ECn& P, ZZn2& Qx, ZZn2& Qy, Big& q, ZZn2& res) //P:����Ԫ��Qx,Qy:��Բ�����ϵĵ�Q�����꣬q:�����ף�res:˫���ԶԽ��
{ 
    int i,nb;
    Big n,p;
    ECn A;


// q.P = 2^17*(2^142.P +P) + P

    res=1;
    A=P;    // reset A

#ifdef SCOTT
// we can avoid last iteration..
    n=q-1;
#else
    n=q;
#endif
    nb=bits(n);

    for (i=nb-2;i>=0;i--)
    {
        res*=res;         
        g(A,A,Qx,Qy,res); 
        if (bit(n,i))
            g(A,P,Qx,Qy,res);       
    }

#ifdef SCOTT
    if (A!=-P || res.iszero()) return FALSE;
#else
    if (!A.iszero()) return FALSE;
#endif

    p=get_modulus();         // get p
    res= pow(res,(p+1)/q);   // raise to power of (p^2-1)/q
    res=conj(res)/res;
    if (res.isunity()) return FALSE;
    return TRUE;   
}
BOOL ecap(ECn& P,ECn& Q,Big& order,ZZn2& cube,ZZn2& res)  //P:����Ԫ��Q:����㣬order:�����ף�cube:��������res:˫���ԶԽ��
{
     ZZn2 Qx,Qy;
     Big xx,yy;
#ifdef SCOTT
     ZZn a,b,x,y,ib,w,t1,y2,ib2;
#else
     ZZn2 lambda,ox;
#endif
     Q.get(xx,yy);
     Qx=(ZZn)xx*cube;
     Qy=(ZZn)yy;

#ifndef SCOTT
// point doubling
     lambda=(3*Qx*Qx)/(Qy+Qy);
     ox=Qx;
     Qx=lambda*lambda-(Qx+Qx);
     Qy=lambda*(ox-Qx)-Qy;
#else
 //explicit point subtraction
     Qx.get(a,b);
     y=yy;
     ib=(ZZn)1/b;

     t1=a*b*b;
     y2=y*y;
     ib2=ib*ib;
     w=y2+2*t1;
     x=-w*ib2;
     y=-y*(w+t1)*(ib2*ib);
     Qx.set(x); 
     Qy.set((ZZn)0,y);

#endif

     if (fast_tate_pairing(P,Qx,Qy,order,res)) return TRUE;
     return FALSE;
}


//
// ecap(.) function - apply distortion map
//
// Qx is in ZZn if SCOTT is defined. Qy is in ZZn if SCOTT is not defined. 
// This can be exploited for some further optimisations. 
/*----------------------------------------------------------------------------Tate Paring ��������Ҫ�ĺ���-----------------------------------------------------*/


/*----------------------------------------------------------------------------���Hash��������ĺ���-----------------------------------------------------*/
// ʵ����һ�����ַ�����ϣ��С��ģ�� p �Ĵ����� Big �ĺ��� H1
Big H1(char *string)
{ // Hash a zero-terminated string to a number < modulus
    Big h,p;
    char s[HASH_LEN];
    int i,j; 
    sha256 sh;

    shs256_init(&sh);

    for (i=0;;i++)
    {
        if (string[i]==0) 
            break;
        shs256_process(&sh,string[i]);
    }
    shs256_hash(&sh,s);
    p=get_modulus();
	//cout<<"modulus"<<p<<endl;//�Լ��ӵĲ鿴pֵ����䣬ͨ��pֵ��֪get_modulus()������get_mip()������
	//��get_mip()�õ����ǵ�ǰ��������Ⱥ�Ľ�ֵq.
    h=1; j=0; i=1;
    forever
    {
        h*=256; 
        if (j==HASH_LEN)  
        {h+=i++; j=0;}
        else        
            h+=s[j++];
        if (h>=p)
            break;
    }
    h%=p;
    return h;
}

//��δ���ʵ����һ���� Fp2 Ԫ�ع�ϣ��һ�� n �ֽ��ַ����ĺ��� H2�����������Ŀ���ǽ� Fp2 ���е�Ԫ��ӳ�䵽һ���̶����ȵ��ַ���
//�����������Ҫ�����ǽ� Fp2 ���е�Ԫ��ͨ�� SHA-1 ��ϣ�㷨ת��Ϊһ���̶����ȵ��ַ���
int H2(ZZn2 x,char *s)
{ // Hash an Fp2 to an n-byte string s[.]. Return n
    sha sh;
    Big a,b;
    int m;  

    shs_init(&sh);
    x.get(a,b);

    while (a>0)
    {
        m=a%160;
        shs_process(&sh,m);
        a/=160;
    }
    while (b>0)
    {
        m=b%160;
        shs_process(&sh,m);
        b/=160;
    }
    shs_hash(&sh,s);

  return HASH_LEN1;
	/*sha256 sh;
    Big a,b;
    int m;

    shs256_init(&sh);
    x.get(a,b);

    while (a>0)
    {
        m=a%256;
        shs256_process(&sh,m);
        a/=256;
    }
    while (b>0)
    {
        m=b%256;
        shs256_process(&sh,m);
        b/=256;
    }
    shs256_hash(&sh,s);

  return HASH_LEN1;
	// return 20;*/
}

// ��δ���ʵ����һ��������ֹ�ַ�����ϣ��С�ڸ���ģ�� qm �Ĵ����� Big �ĺ��� H3��
// �����������Ҫ�����ǽ�������ַ���ͨ�� SHA-1 ��ϣ�㷨ת��Ϊһ���̶����ȵĹ�ϣֵ��
// Ȼ�������ϣֵӳ�䵽һ������������ȷ�����������С�ڸ�����ģ�� qm
Big H3(char *string,Big qm)
{ // Hash a zero-terminated string to a number < modulus q
    Big h;
    char s[HASH_LEN1];
    int i,j; 
    sha sh;

    shs_init(&sh);

    for (i=0;;i++)
    {
        if (string[i]==0) break;
        shs_process(&sh,string[i]);
    }
    shs_hash(&sh,s);
    //q=get_modulus();
	//cout<<"modulus"<<p<<endl;//�Լ��ӵĲ鿴pֵ����䣬ͨ��pֵ��֪get_modulus()�õ�����Բ�������������������P
    h=1; j=0; i=1;
    forever
    {
        h*=160; 
        if (j==HASH_LEN1)  
        {h+=i++; j=0;}
        else        
            h+=s[j++];
        if (h>=qm) break;
    }
    h%=qm;
    return h;
}
   
//
// Given y, get x=(y^2-1)^(1/3) mod p (from curve equation)
// �ڸ��� (y) ֵ������£�
// �ҵ�������Բ���߷��� (y^2 = x^3 + 1) �� (x) ֵ
//

Big getx(Big y)
{
    Big p=get_modulus();
    Big t=modmult(y+1,y-1,p);   // avoids overflow
    return pow(t,(2*p-1)/3,p);
}
 
// MapToPoint
//��һ���ַ�����ʶ����ID��ӳ�䵽��Բ�����ϵ�һ����Ĺ���
ECn map_to_point(char *ID)
{
    ECn Q;
    Big x0,y0=H1(ID);
 
    x0=getx(y0);

    Q.set(x0,y0);

    return Q;
}
/*----------------------------------------------------------------------------���Hash��������ĺ���-----------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------------------������---------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------------------������---------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------------------������---------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------------------������---------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------------------������---------------------------------------------------------------------------------------------------*/
int main()
{
    ofstream common("common.ibe");
    ofstream master("master.ibe");
    //ECn P,Ppub;
    ECn P, Q, R, Ppub, Qid;                    //Ppub:Master Public Key, Qid:Identity Public Key P:����Ԫ��Q:����㣬R:�м����
    //ZZn px,py;//�Լӣ�������ǵ��x,y����
    ZZn2 Qx, Qy, gid, gid1, cube, w;//�Լ�     //gid:˫���ԶԽ����gid1:˫���ԶԽ����cube:��������w:�������� Qx,Qy:��Բ�����ϵĵ�Q������
   // Big xx,yy,ab,r1;//�Լ�
    Big px, py, qx, qy, ab, r1;//�Լ�         //px,py:��Բ�����ϵĵ�P�����꣬qx,qy:��Բ�����ϵĵ�Q�����꣬ab:��Բ�����ϵĵ�Qid�����꣬r1:��ϣֵ
    int i, tag;//�Լ�                         //i:ѭ��������tag:��־λ
   // float t1,t_sub,t2,t_div,t3,t4,t5,t_ecsub,t6,t7,t8,t9,t10,t11,t_div_G2,t_comp;//�Լ�
    float t1, t_sub, t2, t_div, t3, t4, t5, t_ecsub, t6, t7, t8, t88, t9, t10, t11, t_div_G2, t_comp, t_G1_xor;//�Լ�  //:�����ף�t1:��ϣֵ����ʱ�䣬t_sub:�������ʱ�䣬t2:�������ʱ�䣬t_div:ģ������ʱ�䣬t3:ģ������ʱ�䣬t4:�������ʱ�䣬t5:�������ʱ�䣬t_ecsub:�������ʱ�䣬t6:˫���Զ�����ʱ�䣬t7:������ʱ�䣬t8:map_to_point,��H2:G2--->G1����ʱ�䣬t9:H2:G2--->{0,1}^logp����ʱ�䣬t10:H:{0,1}^*--->Z^*_q����ʱ�䣬t11:ģ������in G2��gid*gid1 ����ʱ�䣬t_div_G2:ģ������in G2��gid1/gid ����ʱ�䣬t_comp:����ZZn2�ϵ������Ƿ���ģ����
   // ZZn2 cube;
   // Big s,p,q,t,n,cof,x,y;
    Big a, b, c, d1, d2, p, q, t, n, cof, x, y;  //a:˽Կ��b:˽Կ��c:˽Կ��d1:˽Կ��d2:˽Կ��p:����p��q:����q��t:�����ף�n:�������cof:ϵ����x:��Բ�����ϵĵ�����꣬y:��Բ�����ϵĵ������
    big x1, y1, x2, y2;                          //x1,y1:��Բ�����ϵĵ�����꣬x2,y2:��Բ�����ϵĵ������
    long seed;                                   //seed:���������
    char pad[HASH_LEN1];//�Լ�                   //pad:��ϣֵ
    //char pad[20]={0};

    /*
    Big m = 44323244;
    Big ppp = 100000007;
    cout << "m =" << m << endl;
    cout << "1/m =" << inverse(m, ppp) << endl;
    cout << "1/m * m= " << (inverse(m, ppp) * m)<< endl;
    */

    miracl* mip = &precision;                    //miracl* mip:����

    cout << "������Щ����������ʱ����1���룬���л������������ظ�ִ��" << renum << "�� " << endl;
    cout << "Enter 9 digit random number seed  = ";
    cin >> seed;
    irand(seed);

    // SET-UP
    /*-------------------------------------------------------------����������q-------------------------------------------------------------------------*/
    q = pow((Big)2, 159) + pow((Big)2, 17) + 1; 
    //  q=pow((Big)2,160)-pow((Big)2,76)-1;

    cout << "q= " << q << endl;
    //int logq=bits(q);//����q�Ķ�����λ����������160
    //	cout << "log q= " << logq << endl;

/*--------------------------------------------------------------��������p-------------------------------------------------------------------------*/
//generate p
    t = (pow((Big)2, PBITS) - 1) / (2 * q);
    a = (pow((Big)2, PBITS - 1) - 1) / (2 * q);
    forever
    {
        n = rand(t);
        if (n < a) continue;
        p = 2 * n * q - 1;
        if (p % 24 != 11) continue;  // must be 2 mod 3, also 3 mod 8
        if (prime(p)) break;
    }

    cof = 2 * n;  //��Բ����������

    ecurve(0, 1, p, MR_PROJECTIVE);    // elliptic curve y^2=x^3+1 mod p����Ӱ����ϵͳ

    // Find suitable cube root of unity (solution in Fp2 of x^3=1 mod p)
   
    forever
    {
        //  cube=pow(randn2(),(p+1)*(p-1)/3);
            cube = pow(randn2(),(p + 1) / 3); 
            cube = pow(cube,p - 1);
            if (!cube.isunity()) break;  
    }

    cout << "Cube root of unity= " << cube << endl;

    if (!(cube * cube * cube).isunity())
    {
        cout << "sanity check failed" << endl;
        exit(0);
    }
    //
    // Choosing an arbitrary P ....
    /*-------------------------------------------------------------������Բ�����������P������Ԫ��-------------------------------------------------------------------------*/
    forever
    {
        while (!P.set(randn()));
        P *= cof;
        if (!P.iszero()) break;
    }

    // cout << "Point P= " << P << endl; //
    cout << "����ԪP=" << P << endl;

    //
        // Choosing an arbitrary Q ....
    /*-------------------------------------------------------------������Բ�����������Q-------------------------------------------------------------------------*/
    forever
    {
        while (!Q.set(randn()));
        Q *= cof;
        if (!Q.iszero()) break;
    }

    cout << "Point Q= " << Q << endl; //

 //
 // Pick a random master key s (s���ĳ���a)
    a = rand(q);
    b = rand(q);
    cout << "a= " << a << endl;
    cout << "b= " << b << endl;

    /*_________________________����������Ƿ���ȷ�����������������ȷ�ģ�-----*/
        /*P.get(px,py);
        Q.get(qx,qy);
        ecn_xor(px,py,qx,qy);


          cout << "Point R= (" << qx<<"," <<qy<<")"<< endl;
          ecn_xor(px,py,qx,qy);
         // P.get(xx,yy);
         // R.set(qx,qy);
         // P=Q^R;
          cout << "Point R= (" << qx<<"," <<qy<<")"<< endl;
          R.set(qx,qy);
        cout << "Point P= " << R << endl;
        R.get(qx,qy);
         cout << "Point R= (" << qx<<"," <<qy<<")"<< endl;

    /*---------------------------------------------------------------------- ----------------------------------------------------------------------------*/
    clock_t start_time, end_time;

    /*----------------------------------------------------------------------������㣺P+Q----------------------------------------------------------------------------*/
      // clock_t start_time,end_time;
    cout << "Q= " << Q << endl;
    R = Q;
    start_time = clock();
    for (i = 1; i < renum; i++)
        P + R;//P+R,��R=P+R���൱��R=P+Q��
    end_time = clock();
    t5 = end_time - start_time;
    cout << "P+Q����ʱ��Ϊ��" << t5 << "����" << endl;
    //ecurve_mult(a,P,Ppub);//��IBE�������¶����˴�����Big�࣬miracl�ṩ�Ĵ���������big��Ϊ��Big���������������
   // cout << "Secret a= " <<a << endl;
    cout << "�������P+Q= " << R << endl;
    //cout << "Point Q= " << Q << endl;
/*----------------------------------------------------------------------������㣺Q-P----------------------------------------------------------------------------*/
  // clock_t start_time,end_time;
    start_time = clock();
    for (i = 1; i < renum; i++)
        R - P;//R-P��R=R-P,�൱��Q=R-P��
    end_time = clock();
    t_ecsub = end_time - start_time;
    cout << "Q-P����ʱ��Ϊ��" << t_ecsub << "����" << endl;
    //ecurve_mult(a,P,Ppub);//��IBE�������¶����˴�����Big�࣬miracl�ṩ�Ĵ���������big��Ϊ��Big���������������
   // cout << "Secret a= " <<a << endl;
    cout << "�������Q-P= " << R << endl;
    //cout << "Point Q= " << Q << endl; 
    /*----------------------------------------------------------------------������㣺aP----------------------------------------------------------------------------*/
  // clock_t start_time,end_time;
    //a=a/2;
    //cout << "a= " <<a << endl;
    //cout << "b= " <<b << endl;
    start_time = clock();
    for (i = 1; i < renum; i++)
        Ppub = a * P;
    end_time = clock();
    t4 = end_time - start_time;
    cout << "aP����ʱ��Ϊ��" << t4 << "����" << endl;
    //ecurve_mult(a,P,Ppub);//��IBE�������¶����˴�����Big�࣬miracl�ṩ�Ĵ���������big��Ϊ��Big���������������
   // cout << "Secret a= " <<a << endl;
    //cout << "�������a*P= " << Ppub << endl;
    cout << "�������a*P= " << Ppub << endl;
    R = Q;
    //cout << "R= " << R << endl;

   /*--------------��������㣺Pģ2��Q,���ڵ��������Ч�ʲ��ߣ��Ҵ���ʵ�ֱ�ʾ�Ĳ����㣨��������ĵ�ܿ��ܲ�����Բ�����ϣ�����ϵͳ����ֵ��Ϊ��0,0����������޸ķ����е����Ϊ������㣬�����ǲ�ǿ���ã�0,0���Ĵ������⣬PBC���Ƿ����㣿----------------------------------------------------------------------------  */
       //R=P^Q;//����^,�����е�tֵ��ϵͳ����ʱ����Ϊ��0,0��������t�������������Ľ������ˣ�t�ܿ��ܲ�����Բ�����ϣ��������Ϊ��Infinity����Ϊ��������Զ�㣬������������Ϊ��0,0����

    start_time = clock();
    for (i = 1; i < renum; i++)
    {
        P.get(px, py);
        Q.get(qx, qy);
        ecn_xor(px, py, qx, qy);
    }
    end_time = clock();
    t_G1_xor = end_time - start_time;
    cout << "P^Q����ʱ��Ϊ��" << t_G1_xor << "����" << endl;
    cout << "P^Q= (" << qx << "," << qy << ")" << endl;
    /*ecn_xor(P,Q,xx,yy);

      cout << "Point R= (" << xx<<"," <<yy<<")"<< endl;
      R.set(xx,yy);
     // P=Q^R;
    cout << "Point P= " << R << endl;
    R.get(xx,yy);
     cout << "Point R= (" << xx<<"," <<yy<<")"<< endl;  */
     // cout<<"����ԪP="<<P<<endl;//���������䣬������epoint_get(a.get_point(),px,py)��ʵ����ȡ������ĺ������������ǣ�px=(a.get_point())->X;py=(a.get_point())->Y;
/*----------------------------------------------------------------------˫���Զ����㣺e(P,Q)----------------------------------------------------------------------------*/
 /*  //  ZZn2 Qx,Qy;
   //  Big xx,yy;
     Q=R;
     //	cout << "Point Q= " << Q << endl;
     Q.get(xx,yy);
     Qx=(ZZn)xx*cube;
     Qy=(ZZn)yy;
    //fast_tate_pairing(P,Qx,Qy,order,res);
//   clock_t start_time,end_time;*/
    start_time = clock();
    // fast_tate_pairing(P,Qx,Qy,q,gid);
    for (i = 1; i < renum; i++)
        ecap(P, Q, q, cube, gid);
    end_time = clock();
    t6 = end_time - start_time;
    cout << " e(P,Q)����ʱ��Ϊ��" << t6 << "����" << endl;
    //  cout << "e(P,Q)= (" << gid.a<<","<<gid.b<<")" << endl;
    cout << "e(P,Q)= " << gid << endl;


    /*----------------------------------------------------------------------������in G2��e(P,Q)^a----------------------------------------------------------------------------*/
       // r=rand(q);
    start_time = clock();
    for (i = 1; i < renum; i++)
        w = pow(gid, a);
    end_time = clock();
    t7 = end_time - start_time;
    cout << " gid^a(gid=e(P,Q))����ʱ��Ϊ��" << t7 << "����" << endl;
    //  cout << "e(P,Q)= (" << gid.a<<","<<gid.b<<")" << endl;
    cout << "gid^a(gid=e(P,Q))= " << w << endl;

    /*  Big a1,b1;
      gid.get(a1,b1);
          cout << "a1 " << a1 << endl;
          cout << "b1 " << b1 << endl;*/

          /*----------------------------------------------------------------------map_to_point,��H2:G2--->G1----------------------------------------------------------*/
    char idg[320] = "51341908562371167605710158199067961877051973585785126975865952864942182692255307043887891178551779856597871073815558580774624711401650558170516227136612693897559425945196872344227925384638844402629916160447986326191069372638589347839806296896192897540804561935865359967423094257397342627225356739623783946540";
    // cout << "Enter your correspondents email address (lower case)" << endl;
    // cin.get();
    // cin.getline(id,1000);
     //get_char_g2(gid,id);
    mip->IOBASE = 10;
    start_time = clock();
    for (i = 1; i < renum; i++)
        Qid = map_to_point(idg);
    end_time = clock();
    t8 = end_time - start_time;
    cout << " map_to_point,��H2:G2--->G1����ʱ��Ϊ��" << t8 << "����" << endl;
    cout << "H2:G2--->G1:" << Qid << endl;
    /*----------------------------------------------------------------------map_to_point,��H2:{0,1}^*--->G1----------------------------------------------------------*/
   // char id[320]="51341908562371167605710158199067961877051973585785126975865952864942182692255307043887891178551779856597871073815558580774624711401650558170516227136612693897559425945196872344227925384638844402629916160447986326191069372638589347839806296896192897540804561935865359967423094257397342627225356739623783946540";
   //cout << "Enter your correspondents email address (lower case)" << endl;
   //cin.get();
   //cin.getline(id,1000);
    //get_char_g2(gid,id);
    char id[100] = "yuanke_hhhh@163.com";
    mip->IOBASE = 10;
    start_time = clock();
    for (i = 1; i < renum; i++)
        Qid = map_to_point(id);
    end_time = clock();
    t88 = end_time - start_time;
    cout << " map_to_point,��H2:{0,1}^*--->G1����ʱ��Ϊ��" << t88 << "����" << endl;
    cout << "H2:{0,1}^*--->G1:" << Qid << endl;
    /*----------------------------------------------------------------------Z^*_q �ϵ�ģ������----------------------------------------------------------------------------*/

    /*--------------------------------------------------------------------H2:G2--->{0,1}^logp----------------------------------------------------------*/
    start_time = clock();
    for (i = 1; i < renum; i++)
        H2(w, pad);
    end_time = clock();
    t9 = end_time - start_time;
    cout << " H2:G2--->{0,1}^logp����ʱ��Ϊ��" << t9 << "����" << endl;
    //cout << "H2:G2--->{0,1}^logp " << pad << endl;
/*--------------------------------------------------------------------H:{0,1}^*--->Z^*_q----------------------------------------------------------*/
    char rt[100] = "2015-11-19-08-30";
    //cout << "Enter your correspondents email address (lower case)" << endl;
   // cin.get();
   // cin.getline(id,1000);
    start_time = clock();
    for (i = 1; i < renum; i++)
        r1 = H3(rt, q);
    end_time = clock();
    t10 = end_time - start_time;
    cout << " H:{0,1}^*--->Z^*_q����ʱ��Ϊ��" << t10 << "����" << endl;
    cout << "H1(rt) " << r1 << endl;

    /*----------------------------------------------------------------------ģ������in G2��gid*gid1��ZZn2�����ص��������㱾�����ģ���㣩-------------------------------------------------------------------------*/
        //gid1=randn2(void);
    ecap(Ppub, Qid, q, cube, gid1);
    start_time = clock();
    // fast_tate_pairing(P,Qx,Qy,q,gid);
    for (i = 1; i < renum; i++)
        gid1 = gid1 * gid;
    end_time = clock();
    t11 = end_time - start_time;
    cout << "ģ������in G2��gid*gid1 ����ʱ��Ϊ��" << t11 << "����" << endl;
    //  cout << "e(P,Q)= (" << gid.a<<","<<gid.b<<")" << endl;
    cout << "gid*gid1 = " << gid1 << endl;
    /*----------------------------------------------------------------------����ZZn2�ϵ������Ƿ���ģ����----------------------------------------------------------------------------*/
      /*ecap(Ppub,Qid,q,cube,gid1);
        cout << "ԭʼgid1= " << gid1 << endl;
        for(i=1;i<renum;i++)
            gid1=gid1*gid;
        for(i=1;i<renum;i++)
            gid1=gid1/gid;
        cout << "gid1*gid^rnum^{1/renm}= " << gid1 << endl;*/
        /*----------------------------------------------------------------------������ZZn2�ϵ�������ģ���㣬��Ϊgid1*gid^rnum^{1/renm}=gid1----------------------------------------------------------------------------*/
        /*----------------------------------------------------------------------ģ������in G2��gid1/gid��ZZn2�����ص��������㱾�����ģ���㣩-------------------------------------------------------------------------*/
            //gid1=randn2(void);
    start_time = clock();
    // fast_tate_pairing(P,Qx,Qy,q,gid);
    for (i = 1; i < renum; i++)
        gid1 = gid1 / gid;
    end_time = clock();
    t_div_G2 = end_time - start_time;
    cout << " ģ������in G2��gid1/gid��" << t_div_G2 << "����" << endl;
    //  cout << "e(P,Q)= (" << gid.a<<","<<gid.b<<")" << endl;
    cout << "gid1*gid^rnum^{1/renm}= " << gid1 << endl;


    /*-------------------------------Z^*_q �ϵ�ģ�Ӽ��˳������������a*P������ǰ���������������ܵ�ԭ���ǣ�Z^*_q �ϵ�ģ�Ӽ��˳����������nʣ�ຯ����ʹ��a,b�����nʣ�����͵�big ����---------------------------------------*/
        /*���磺ģ�Ӻ�����9.2.27	nres_modadd

    Function:	void nres_modadd(x,y,z)
            big x,y,z;

    Module:	mrmonty.c

    Description:	Modular addition of two n-residues

    Parameters:	Three n-residue numbers x, y, and z.
            On exit z=x+y mod n, where n is the current Montgomery modulus.

    Return value:	None

    Restrictions:	Must be preceded by a call to prepare_monty. */
    /*----------------------------------------------------------------------��������Ԫ��in G2�Ƿ����-------------------------------------------------------------------------*/
    start_time = clock();
    for (i = 1; i < renum; i++)
        tag = gid == gid;
    end_time = clock();
    t_comp = end_time - start_time;
    cout << "��������Ԫ��in G2�Ƿ���ȼ���ʱ��Ϊ��" << t_comp << "����" << endl;
    //  cout << "e(P,Q)= (" << gid.a<<","<<gid.b<<")" << endl;
    cout << "gid�Ƿ�ͬgid��ȣ�1��ʾ��ȣ�0��ʾ���ȣ� " << tag << endl;
    /*----------------------------------------------------------------------����ZZn2�ϵ������Ƿ���ģ����----------------------------------------------------------------------------*/

          /* start_time=clock();
        for(i=1;i<500;i++)
            c=(a+b)%q;
        end_time=clock();
        t1=end_time-start_time;
        cout<<"a+b mod q ����ʱ��Ϊ��"<<t1<<"����"<<endl;
        cout << "a+b mod q " <<c<< endl;*/
        // clock_t start_time,end_time;
    start_time = clock();
    for (i = 1; i < renum; i++)
        c = modadd(a, b, q);
    end_time = clock();
    t1 = end_time - start_time;
    cout << "a+b mod q ����ʱ��Ϊ��" << t1 << "����" << endl;
    cout << "a+b mod q " << c << endl;
    //modadd(const Big& b1,const Big& b2,const Big& z)
    /*----------------------------------------------------------------------Z^*_q �ϵ�ģ������----------------------------------------------------------------------------*/

   /* start_time=clock();
    for(i=1;i<500;i++)
        c=(a+b)%q;
    end_time=clock();
    t1=end_time-start_time;
    cout<<"a+b mod q ����ʱ��Ϊ��"<<t1<<"����"<<endl;
    cout << "a+b mod q " <<c<< endl;*/
    // clock_t start_time,end_time;
    start_time = clock();
    for (i = 1; i < renum; i++)
        a = modsub(c, b, q);
    end_time = clock();
    t_sub = end_time - start_time;
    cout << "c-b mod q ����ʱ��Ϊ��" << t_sub << "����" << endl;
    cout << "c-b mod q " << a << endl;
    //modadd(const Big& b1,const Big& b2,const Big& z)
/*----------------------------------------------------------------------Z^*_q �ϵ�ģ������----------------------------------------------------------------------------*/
    start_time = clock();
    for (i = 1; i < renum; i++)
        ab = modmult(a, b, q);
    end_time = clock();
    t2 = end_time - start_time;
    cout << "a*b mod q ����ʱ��Ϊ��" << t2 << "����" << endl;
    cout << "a*b mod q " << ab << endl;
    /*----------------------------------------------------------------------Z^*_q �ϵ�ģ������----------------------------------------------------------------------------*/
    start_time = clock();
    for (i = 1; i < renum; i++)
        d1 = moddiv(a, b, q);
    end_time = clock();
    t_div = end_time - start_time;
    cout << "a/b mod q ����ʱ��Ϊ��" << t_div << "����" << endl;
    cout << "a/b mod q " << d1 << endl;
    /*----------------------------------------------------------------------Z^*_q �ϵ�ģ������----------------------------------------------------------------------------*/
    start_time = clock();
    for (i = 1; i < renum; i++)
        d2 = inverse(b, q);
    end_time = clock();
    t3 = end_time - start_time;
    cout << "1/b mod q ����ʱ��Ϊ��" << t3 << "����" << endl;
    cout << "1/b mod q " << d2 << endl;

    /*----------------------------------------------------------------------Z^*_q �ϵ�ģ��ת��Ϊģ��ģ������a/b=a*(1/b),�����ʱ���������ַ�����ʱ�����ֱ��ʹ��ģ�������ĺ�ʱ��125%��ѭ��ִ��300�����ϣ���Ҳ���Ǹ�ֵ�Զ��ԭ��----------------------------------------------------------------------------*/
   /* start_time=clock();
    for(i=1;i<renum;i++)
       { d2= inverse(b,q);
         d1=modmult(a,d2,q);}
    end_time=clock();
    t1=end_time-start_time;
    cout<<"a/b=a*(1/b) mod q ����ʱ��Ϊ��"<<t1<<"����"<<endl;
    cout << "1/a mod q " <<d2<< endl;
    cout << "Point P= " << P << endl;
    cout << "Point Q= " << Q << endl; */


    /*-------------------------------------------------��������������ڵ������ļ���ʱ�����------------------------------------------------------*/
    t1 = t1 / t4;
    cout << "Z^*_q �ϵ�ģ��a+b mod q��ʱ����: " << t1 << endl;
    t_sub = t_sub / t4;
    cout << "Z^*_q �ϵ�ģ��a-b mod q��ʱ����: " << t_sub << endl;
    t2 = t2 / t4;
    cout << "Z^*_q �ϵ�ģ��a*b mod q��ʱ����: " << t2 << endl;
    t_div = t_div / t4;
    cout << "Z^*_q �ϵ�ģ��a/b mod q��ʱ����: " << t_div << endl;
    t3 = t3 / t4;
    cout << "Z^*_q �ϵ�ģ��1/b mod q��ʱ����: " << t3 << endl;
    //t4=t4/t4;
    cout << "������� aP ��ʱ����: " << 1 << endl;
    t5 = t5 / t4;
    cout << "������� P+Q=Rģ�Ӻ�ʱ����: " << t5 << endl;
    t_ecsub = t_ecsub / t4;
    cout << "������� Q=R-P ģ�Ӻ�ʱ����: " << t_ecsub << endl;
    t6 = t6 / t4;
    cout << "˫���Զ�����e(P,Q) ��ʱ����: " << t6 << endl;
    t7 = t7 / t4;
    cout << "������in G2 ��ʱ����: " << t7 << endl;
    t8 = t8 / t4;
    cout << "H1:G2--->G1��ʱ����: " << t8 << endl;
    t88 = t88 / t4;
    cout << "H1:{0,1}^*--->G1��ʱ����: " << t88 << endl;
    t9 = t9 / t4;
    cout << "H2:G2--->{0,1}^logp��ʱ����: " << t9 << endl;
    t10 = t10 / t4;
    cout << " H:{0,1}^*--->Z^*_q��ʱ����: " << t10 << endl;
    t11 = t11 / t4;
    cout << " ģ������in G2��gid*gid1 ��ʱ����: " << t11 << endl;
    t_div_G2 = t_div_G2 / t4;
    cout << " ģ������in G2��gid1/gid ��ʱ����: " << t_div_G2 << endl;
    t_comp = t_comp / t4;
    cout << " ��������Ԫ��in G2�Ƿ���� ��ʱ����: " << t_comp << endl;
    t_G1_xor = t_G1_xor / t4;
    cout << " ��������Ԫ��in G1������� ��ʱ����: " << t_G1_xor << endl;

    //return 0;
    int Readkey();
    int aa;
    cin >> aa;
}


	