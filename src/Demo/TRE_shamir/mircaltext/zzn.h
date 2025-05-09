#pragma once
/*
 *    MIRACL  C++ Header file zzn.h
 *
 *    AUTHOR  : M. Scott
 *
 *    PURPOSE : Definition of class ZZn  (Arithmetic mod n), using
 *              Montgomery's Method for modular multiplication
 *    NOTE    : Must be used in conjunction with zzn.cpp
 *              The modulus n is always set dynamically (via the modulo()
 *              routine) - so beware the pitfalls implicit in declaring
 *              static or global ZZn's (which are initialised before n is
 *              set!). Uninitialised data is OK
 *
 *    Copyright (c) 1988-2001 Shamus Software Ltd.
 */

#ifndef ZZN_H
#define ZZN_H

#include "big.h"

 /*

 #ifdef ZZNS
 #define MR_INIT_ZZN memset(mem,0,mr_big_reserve(1,ZZNS)); fn=(big)mirvar_mem_variable(mem,0,ZZNS);
 #define MR_CLONE_ZZN(x) fn->len=x->len; for (int i=0;i<ZZNS;i++) fn->w[i]=x->w[i];
 #define MR_ZERO_ZZN {fn->len=0; for (int i=0;i<ZZNS;i++) fn->w[i]=0;}
 #else
 #define MR_INIT_ZZN mem=(char *)memalloc(1); fn=(big)mirvar_mem(mem,0);
 #define MR_CLONE_ZZN(x) copy(x,fn);
 #define MR_ZERO_ZZN zero(fn);
 #endif

 */

#ifdef ZZNS
#ifdef MR_COMBA
#define UZZNS ZZNS
#else
#define UZZNS ZZNS + 1 // one extra required in case of carry overflow in addition
#endif
#endif

#ifdef ZZNS
#define MR_INIT_ZZN \
    fn = &b;        \
    b.w = a;        \
    b.len = UZZNS;
#define MR_CLONE_ZZN(x)             \
    b.len = x->len;                 \
    for (int i = 0; i < UZZNS; i++) \
        a[i] = x->w[i];
#define MR_ZERO_ZZN                     \
    {                                   \
        b.len = 0;                      \
        for (int i = 0; i < UZZNS; i++) \
            a[i] = 0;                   \
    }
#else
#define MR_INIT_ZZN fn = mirvar(0);
#define MR_CLONE_ZZN(x) copy(x, fn);
#define MR_ZERO_ZZN zero(fn);
#endif

class ZZn
{
    big fn;
#ifdef ZZNS
    mr_small a[UZZNS];
    bigtype b;
#endif

    /*
#ifdef ZZNS
    char mem[mr_big_reserve(1,ZZNS)];
#else
    char *mem;
#endif
*/

public:
    ZZn() { MR_INIT_ZZN MR_ZERO_ZZN } ZZn(int i)
    {
        MR_INIT_ZZN if (i == 0) MR_ZERO_ZZN else
        {
            convert(i, fn);
            nres(fn, fn);
        }
    }
    ZZn(const Big& c) { MR_INIT_ZZN nres(c.getbig(), fn); } /* Big -> ZZn */
    ZZn(big& c) { MR_INIT_ZZN MR_CLONE_ZZN(c); }
    ZZn(const ZZn& c) { MR_INIT_ZZN MR_CLONE_ZZN(c.fn); }
    ZZn(char* s)
    {
        MR_INIT_ZZN cinstr(fn, s);
        nres(fn, fn);
    }

    ZZn& operator=(const ZZn& c)
    {
        MR_CLONE_ZZN(c.fn)
            return *this;
    }
    ZZn& operator=(big c)
    {
        MR_CLONE_ZZN(c)
            return *this;
    }

    ZZn& operator=(int i)
    {
        if (i == 0)
            MR_ZERO_ZZN else
        {
            convert(i, fn);
            nres(fn, fn);
        }
        return *this;
    }
    ZZn& operator=(char* s)
    {
        cinstr(fn, s);
        nres(fn, fn);
        return *this;
    }

    /* Use fast in-line code */

    ZZn& operator++()
    {
        ZZn one = 1;
        nres_modadd(fn, one.fn, fn);
        return *this;
    }
    ZZn& operator--()
    {
        ZZn one = 1;
        nres_modsub(fn, one.fn, fn);
        return *this;
    }
    ZZn& operator+=(int i)
    {
        ZZn inc = i;
        nres_modadd(fn, inc.fn, fn);
        return *this;
    }
    ZZn& operator-=(int i)
    {
        ZZn dec = i;
        nres_modsub(fn, dec.fn, fn);
        return *this;
    }
    ZZn& operator+=(const ZZn& b)
    {
        nres_modadd(fn, b.fn, fn);
        return *this;
    }
    ZZn& operator-=(const ZZn& b)
    {
        nres_modsub(fn, b.fn, fn);
        return *this;
    }
    ZZn& operator*=(const ZZn& b)
    {
        nres_modmult(fn, b.fn, fn);
        return *this;
    }
    ZZn& operator*=(int i)
    {
        nres_premult(fn, i, fn);
        return *this;
    }

    ZZn& negate()
    {
        nres_negate(fn, fn);
        return *this;
    }

    BOOL iszero() const;

    operator Big()
    {
        Big c;
        redc(fn, c.getbig());
        return c;
    } /* ZZn -> Big */
    friend big getbig(ZZn& z) { return z.fn; }

    ZZn& operator/=(const ZZn& b)
    {
        nres_moddiv(fn, b.fn, fn);
        return *this;
    }
    ZZn& operator/=(int);

    friend ZZn operator-(const ZZn&);
    friend ZZn operator+(const ZZn&, int);
    friend ZZn operator+(int, const ZZn&);
    friend ZZn operator+(const ZZn&, const ZZn&);

    friend ZZn operator-(const ZZn&, int);
    friend ZZn operator-(int, const ZZn&);
    friend ZZn operator-(const ZZn&, const ZZn&);

    friend ZZn operator*(const ZZn&, int);
    friend ZZn operator*(int, const ZZn&);
    friend ZZn operator*(const ZZn&, const ZZn&);

    friend ZZn operator/(const ZZn&, int);
    friend ZZn operator/(int, const ZZn&);
    friend ZZn operator/(const ZZn&, const ZZn&);

    friend BOOL operator==(const ZZn& b1, const ZZn& b2)
    {
        if (mr_compare(b1.fn, b2.fn) == 0)
            return TRUE;
        else
            return FALSE;
    }
    friend BOOL operator!=(const ZZn& b1, const ZZn& b2)
    {
        if (mr_compare(b1.fn, b2.fn) != 0)
            return TRUE;
        else
            return FALSE;
    }

    friend ZZn pow(const ZZn&, const Big&);
    friend ZZn pow(const ZZn&, int);
    friend ZZn powl(const ZZn&, const Big&);
    friend ZZn pow(const ZZn&, const Big&, const ZZn&, const Big&);
    friend ZZn pow(int, ZZn*, Big*);
#ifndef MR_NO_RAND
    friend ZZn randn(void); // random number < modulus
#endif
    friend BOOL qr(const ZZn&);  // test for quadratic residue
    friend BOOL qnr(const ZZn&); // test for quadratic non-residue
    friend ZZn getA(void);        // get A parameter of elliptic curve
    friend ZZn getB(void);        // get B parameter of elliptic curve

    friend ZZn sqrt(const ZZn&); // only works if modulus is prime
    friend ZZn luc(const ZZn&, const Big&, ZZn* b3 = NULL);

    big getzzn(void) const;

#ifndef MR_NO_STANDARD_IO
    friend ostream& operator<<(ostream&, const ZZn&);
#endif

    ~ZZn()
    {
        // MR_ZERO_ZZN  // slower but safer
#ifndef ZZNS
        mr_free(fn);
#endif
    }
};
#ifndef MR_NO_RAND
extern ZZn randn(void);
#endif
extern ZZn getA(void);
extern ZZn getB(void);

#endif
