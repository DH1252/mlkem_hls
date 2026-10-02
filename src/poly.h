/*
 * poly.h - polynomials in R_q = Z_q[X]/(X^256 + 1) and the ML-KEM building
 * blocks that work on them (FIPS 203, sections 4.2 and 4.3).
 *
 * Every coefficient is kept fully reduced, in 0 .. q-1.
 */
#ifndef POLY_H
#define POLY_H

#include <stdint.h>

#include "hls.h"
#include "mlkem_params.h"

typedef struct
{
   uint16_t c[MLKEM_N];
} poly;

/* Arithmetic modulo q */
MLKEM_API uint16_t mod_q(uint32_t a); /* a < 2^24 */

/* Hardware leaves (see hls.h): one instance each in the accelerator */
/* Number-theoretic transform (Algorithms 9, 10, 11) */
MLKEM_LEAF void poly_ntt(poly* f);
MLKEM_LEAF void poly_invntt(poly* f);
MLKEM_LEAF void poly_basemul_acc(poly* acc, const poly* a, const poly* b); /* acc += a * b (NTT domain) */
MLKEM_LEAF void poly_add(poly* r, const poly* a);                          /* r += a */
MLKEM_LEAF void poly_sub(poly* r, const poly* a);                          /* r -= a */
MLKEM_LEAF void poly_zero(poly* r);

/* Encoding and compression (Algorithms 5, 6 and section 4.2.1) */
MLKEM_LEAF void poly_encode(uint8_t* out, const poly* f, int d); /* ByteEncode_d          */
MLKEM_LEAF int poly_decode(poly* f, const uint8_t* in, int d);   /* ByteDecode_d; returns 1
                                                                    if every 12-bit value
                                                                    was < q (d = 12)      */
MLKEM_LEAF void poly_compress(poly* f, int d);                   /* Compress_d, in place  */
MLKEM_LEAF void poly_decompress(poly* f, int d);                 /* Decompress_d          */

/* CBD_eta from 64*eta bytes of PRF output (Algorithm 8) */
MLKEM_LEAF void poly_cbd(poly* f, const uint8_t* buf, int eta);

/* Sampling (Algorithms 7, 8). These call the Keccak sponge, so they are
 * inlined into their callers rather than being leaves themselves. */
MLKEM_API void poly_sample_ntt(poly* a, const uint8_t rho[32], uint8_t j, uint8_t i);
MLKEM_API void poly_sample_cbd(poly* f, const uint8_t seed[32], uint8_t nonce, int eta);

#endif
