/*
 * ed25519_precomp.h — Precomputed-table scalar multiplication for Ed25519
 *
 * Provides build_precomp_table() and scalarmult_precomp_vartime() for
 * fast fixed-point scalar multiplication using a 32×8 Duif precomp table.
 *
 * Requires linking against the LOCAL libsodium build (private headers).
 */

#ifndef ED25519_PRECOMP_H
#define ED25519_PRECOMP_H

/* Auto-detect 128-bit integer support for fe_51 representation */
#if defined(__SIZEOF_INT128__) && !defined(HAVE_TI_MODE)
#define HAVE_TI_MODE 1
#endif
#ifndef CONFIGURED
#define CONFIGURED 1
#endif

/* sodium.h must come before the private header so sodium_is_zero() is declared */
#include <sodium.h>
#include <private/ed25519_ref10.h>

/* ══════════════════════════════════════════════════════════════════════
 * Static functions copied from libsodium ed25519_ref10.c (not exported).
 * These are needed for the precomputed-table scalar multiplication.
 * ══════════════════════════════════════════════════════════════════════ */

/* d2 = 2*d, the curve constant used in ge25519_p3_to_precomp / p3_to_cached */
#ifdef HAVE_TI_MODE
static const fe25519 ed25519_precomp_d2_ = {
    1859910466990425, 932731440258426, 1072319116312658, 1815898335770999, 633789495995903
};
#else
static const fe25519 ed25519_precomp_d2_ = {
    -21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199
};
#endif

static void
ge25519_p3_0_(ge25519_p3 *h)
{
    fe25519_0(h->X);
    fe25519_1(h->Y);
    fe25519_1(h->Z);
    fe25519_0(h->T);
}

static void
ge25519_p3_to_p2_(ge25519_p2 *r, const ge25519_p3 *p)
{
    fe25519_copy(r->X, p->X);
    fe25519_copy(r->Y, p->Y);
    fe25519_copy(r->Z, p->Z);
}

static void
ge25519_p2_dbl_(ge25519_p1p1 *r, const ge25519_p2 *p)
{
    fe25519 t0;

    fe25519_sq(r->X, p->X);
    fe25519_sq(r->Z, p->Y);
    fe25519_sq2(r->T, p->Z);
    fe25519_add(r->Y, p->X, p->Y);
    fe25519_sq(t0, r->Y);
    fe25519_add(r->Y, r->Z, r->X);
    fe25519_sub(r->Z, r->Z, r->X);
    fe25519_sub(r->X, t0, r->Y);
    fe25519_sub(r->T, r->T, r->Z);
}

static void
ge25519_p3_dbl_(ge25519_p1p1 *r, const ge25519_p3 *p)
{
    ge25519_p2 q;
    ge25519_p3_to_p2_(&q, p);
    ge25519_p2_dbl_(r, &q);
}

/* r = p + q  (mixed add with Duif precomp form) */
static void
ge25519_madd_(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_precomp *q)
{
    fe25519 t0;

    fe25519_add(r->X, p->Y, p->X);
    fe25519_sub(r->Y, p->Y, p->X);
    fe25519_mul(r->Z, r->X, q->yplusx);
    fe25519_mul(r->Y, r->Y, q->yminusx);
    fe25519_mul(r->T, q->xy2d, p->T);
    fe25519_add(t0, p->Z, p->Z);
    fe25519_sub(r->X, r->Z, r->Y);
    fe25519_add(r->Y, r->Z, r->Y);
    fe25519_add(r->Z, t0, r->T);
    fe25519_sub(r->T, t0, r->T);
}

/* r = p - q  (mixed sub with Duif precomp form) */
static void
ge25519_msub_(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_precomp *q)
{
    fe25519 t0;

    fe25519_add(r->X, p->Y, p->X);
    fe25519_sub(r->Y, p->Y, p->X);
    fe25519_mul(r->Z, r->X, q->yminusx);
    fe25519_mul(r->Y, r->Y, q->yplusx);
    fe25519_mul(r->T, q->xy2d, p->T);
    fe25519_add(t0, p->Z, p->Z);
    fe25519_sub(r->X, r->Z, r->Y);
    fe25519_add(r->Y, r->Z, r->Y);
    fe25519_sub(r->Z, t0, r->T);
    fe25519_add(r->T, t0, r->T);
}

/* p3 → Duif precomp form (y+x, y-x, 2dxy) via affine coordinates */
static void
ge25519_p3_to_precomp_(ge25519_precomp *pi, const ge25519_p3 *p)
{
    fe25519 recip;
    fe25519 x;
    fe25519 y;
    fe25519 xy;

    fe25519_invert(recip, p->Z);
    fe25519_mul(x, p->X, recip);
    fe25519_mul(y, p->Y, recip);
    fe25519_add(pi->yplusx, y, x);
    fe25519_sub(pi->yminusx, y, x);
    fe25519_mul(xy, x, y);
    fe25519_mul(pi->xy2d, xy, ed25519_precomp_d2_);
}

/* p3 → cached form (Y+X, Y-X, Z, 2dT) for extended addition */
static void
ge25519_p3_to_cached_(ge25519_cached *r, const ge25519_p3 *p)
{
    fe25519_add(r->YplusX, p->Y, p->X);
    fe25519_sub(r->YminusX, p->Y, p->X);
    fe25519_copy(r->Z, p->Z);
    fe25519_mul(r->T2d, p->T, ed25519_precomp_d2_);
}

/* r = p + q  (extended addition with cached form) */
static void
ge25519_add_cached_(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_cached *q)
{
    fe25519 t0;

    fe25519_add(r->X, p->Y, p->X);
    fe25519_sub(r->Y, p->Y, p->X);
    fe25519_mul(r->Z, r->X, q->YplusX);
    fe25519_mul(r->Y, r->Y, q->YminusX);
    fe25519_mul(r->T, q->T2d, p->T);
    fe25519_mul(r->X, p->Z, q->Z);
    fe25519_add(t0, r->X, r->X);
    fe25519_sub(r->X, r->Z, r->Y);
    fe25519_add(r->Y, r->Z, r->Y);
    fe25519_add(r->Z, t0, r->T);
    fe25519_sub(r->T, t0, r->T);
}

/* r = p - q  (extended subtraction with cached form) */
static void
ge25519_sub_cached_(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_cached *q)
{
    fe25519 t0;

    fe25519_add(r->X, p->Y, p->X);
    fe25519_sub(r->Y, p->Y, p->X);
    fe25519_mul(r->Z, r->X, q->YminusX);
    fe25519_mul(r->Y, r->Y, q->YplusX);
    fe25519_mul(r->T, q->T2d, p->T);
    fe25519_mul(r->X, p->Z, q->Z);
    fe25519_add(t0, r->X, r->X);
    fe25519_sub(r->X, r->Z, r->Y);
    fe25519_add(r->Y, r->Z, r->Y);
    fe25519_sub(r->Z, t0, r->T);
    fe25519_add(r->T, t0, r->T);
}

/* ══════════════════════════════════════════════════════════════════════
 * Precomputed-table scalar multiplication (same algorithm as
 * ge25519_scalarmult_base but for an arbitrary fixed point).
 * ══════════════════════════════════════════════════════════════════════ */

/* Build a 32×8 precomp table: table[i][j] = (j+1)·256^i·P in Duif form. */
static void
build_precomp_table(ge25519_precomp table[32][8], const ge25519_p3 *P)
{
    ge25519_p3   base;  /* 256^i · P */
    ge25519_p3   acc;
    ge25519_p1p1 r;
    int i, j;

    base = *P;

    for (i = 0; i < 32; i++) {
        acc = base;
        ge25519_p3_to_precomp_(&table[i][0], &acc);

        for (j = 1; j < 8; j++) {
            ge25519_cached base_cached;
            ge25519_p3_to_cached_(&base_cached, &base);
            ge25519_add_cached_(&r, &acc, &base_cached);
            ge25519_p1p1_to_p3(&acc, &r);
            ge25519_p3_to_precomp_(&table[i][j], &acc);
        }

        /* Advance base by 256× = 8 doublings */
        for (j = 0; j < 8; j++) {
            ge25519_p3_dbl_(&r, &base);
            if (j < 7) {
                ge25519_p1p1_to_p3(&base, &r);
            } else {
                if (i < 31)
                    ge25519_p1p1_to_p3(&base, &r);
            }
        }
    }
}

/*
 * Scalar multiplication using precomputed table (vartime).
 *
 * Algorithm: identical to ge25519_scalarmult_base.
 * 1) Decompose scalar into 64 signed 4-bit digits (range -8..8)
 * 2) Pass 1: odd positions → madd/msub with table[i/2]
 * 3) 4× doubling
 * 4) Pass 2: even positions → madd/msub with table[i/2]
 *
 * Vartime: verification inputs are public, so direct table indexing
 * is used instead of constant-time conditional moves.
 */
static void
scalarmult_precomp_vartime(ge25519_p3 *h, const unsigned char scalar[32],
                           const ge25519_precomp table[32][8])
{
    signed char    e[64];
    signed char    carry;
    ge25519_p1p1   r;
    ge25519_p2     s;
    int            i;

    /* Decompose scalar into signed 4-bit digits */
    for (i = 0; i < 32; ++i) {
        e[2 * i + 0] = (scalar[i] >> 0) & 15;
        e[2 * i + 1] = (scalar[i] >> 4) & 15;
    }
    carry = 0;
    for (i = 0; i < 63; ++i) {
        e[i] += carry;
        carry = e[i] + 8;
        carry >>= 4;
        e[i] -= carry * ((signed char) 1 << 4);
    }
    e[63] += carry;

    ge25519_p3_0_(h);

    /* Pass 1: odd positions (i=1,3,...,63) */
    for (i = 1; i < 64; i += 2) {
        signed char digit = e[i];
        int pos = i / 2;
        if (digit > 0) {
            ge25519_madd_(&r, h, &table[pos][digit - 1]);
            ge25519_p1p1_to_p3(h, &r);
        } else if (digit < 0) {
            ge25519_msub_(&r, h, &table[pos][-digit - 1]);
            ge25519_p1p1_to_p3(h, &r);
        }
    }

    /* 4× doubling */
    ge25519_p3_dbl_(&r, h);
    ge25519_p1p1_to_p2(&s, &r);
    ge25519_p2_dbl_(&r, &s);
    ge25519_p1p1_to_p2(&s, &r);
    ge25519_p2_dbl_(&r, &s);
    ge25519_p1p1_to_p2(&s, &r);
    ge25519_p2_dbl_(&r, &s);
    ge25519_p1p1_to_p3(h, &r);

    /* Pass 2: even positions (i=0,2,...,62) */
    for (i = 0; i < 64; i += 2) {
        signed char digit = e[i];
        int pos = i / 2;
        if (digit > 0) {
            ge25519_madd_(&r, h, &table[pos][digit - 1]);
            ge25519_p1p1_to_p3(h, &r);
        } else if (digit < 0) {
            ge25519_msub_(&r, h, &table[pos][-digit - 1]);
            ge25519_p1p1_to_p3(h, &r);
        }
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * Variable-time variable-base scalar multiplication (sliding window).
 * Generalizes ge25519_mul_l (ed25519_ref10.c:964-1016) to accept an
 * arbitrary scalar. Safe for verification where all inputs are public.
 * ══════════════════════════════════════════════════════════════════════ */

/* slide_vartime_: signed sliding-window decomposition of a 256-bit scalar.
 * Copied from libsodium ed25519_ref10.c:249-289 (static, not exported). */
static void
slide_vartime_(signed char *r, const unsigned char *a)
{
    int i;
    int b;
    int k;
    int ribs;
    int cmp;

    for (i = 0; i < 256; ++i) {
        r[i] = 1 & (a[i >> 3] >> (i & 7));
    }
    for (i = 0; i < 256; ++i) {
        if (! r[i]) {
            continue;
        }
        for (b = 1; b <= 6 && i + b < 256; ++b) {
            if (! r[i + b]) {
                continue;
            }
            ribs = r[i + b] << b;
            cmp = r[i] + ribs;
            if (cmp <= 15) {
                r[i] = cmp;
                r[i + b] = 0;
            } else {
                cmp = r[i] - ribs;
                if (cmp < -15) {
                    break;
                }
                r[i] = cmp;
                for (k = i + b; k < 256; ++k) {
                    if (! r[k]) {
                        r[k] = 1;
                        break;
                    }
                    r[k] = 0;
                }
            }
        }
    }
}

/*
 * Variable-time scalar multiplication: h = scalar * A
 *
 * Uses sliding-window algorithm with 8-entry precomp table (A, 3A, 5A, ..., 15A).
 * Identical structure to ge25519_mul_l but with dynamic scalar.
 * Output is ge25519_p3 for compatibility with subsequent point additions.
 */
static void
ge25519_scalarmult_vartime(ge25519_p3 *h, const unsigned char *scalar,
                           const ge25519_p3 *A)
{
    signed char    aslide[256];
    ge25519_cached Ai[8];
    ge25519_p1p1   t;
    ge25519_p3     u;
    ge25519_p3     A2;
    int            i;

    slide_vartime_(aslide, scalar);

    ge25519_p3_to_cached_(&Ai[0], A);
    ge25519_p3_dbl_(&t, A);
    ge25519_p1p1_to_p3(&A2, &t);
    ge25519_add_cached_(&t, &A2, &Ai[0]);
    ge25519_p1p1_to_p3(&u, &t);
    ge25519_p3_to_cached_(&Ai[1], &u);
    ge25519_add_cached_(&t, &A2, &Ai[1]);
    ge25519_p1p1_to_p3(&u, &t);
    ge25519_p3_to_cached_(&Ai[2], &u);
    ge25519_add_cached_(&t, &A2, &Ai[2]);
    ge25519_p1p1_to_p3(&u, &t);
    ge25519_p3_to_cached_(&Ai[3], &u);
    ge25519_add_cached_(&t, &A2, &Ai[3]);
    ge25519_p1p1_to_p3(&u, &t);
    ge25519_p3_to_cached_(&Ai[4], &u);
    ge25519_add_cached_(&t, &A2, &Ai[4]);
    ge25519_p1p1_to_p3(&u, &t);
    ge25519_p3_to_cached_(&Ai[5], &u);
    ge25519_add_cached_(&t, &A2, &Ai[5]);
    ge25519_p1p1_to_p3(&u, &t);
    ge25519_p3_to_cached_(&Ai[6], &u);
    ge25519_add_cached_(&t, &A2, &Ai[6]);
    ge25519_p1p1_to_p3(&u, &t);
    ge25519_p3_to_cached_(&Ai[7], &u);

    ge25519_p3_0_(h);

    for (i = 255; i >= 0; --i) {
        ge25519_p3_dbl_(&t, h);

        if (aslide[i] > 0) {
            ge25519_p1p1_to_p3(&u, &t);
            ge25519_add_cached_(&t, &u, &Ai[aslide[i] / 2]);
        } else if (aslide[i] < 0) {
            ge25519_p1p1_to_p3(&u, &t);
            ge25519_sub_cached_(&t, &u, &Ai[(-aslide[i]) / 2]);
        }

        ge25519_p1p1_to_p3(h, &t);
    }
}

#endif /* ED25519_PRECOMP_H */
