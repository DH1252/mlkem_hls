/*
 * poly.c - arithmetic in R_q = Z_q[X]/(X^256 + 1), NTT, sampling and
 * encoding for ML-KEM (FIPS 203, sections 4.2 and 4.3).
 *
 * Plain, readable arithmetic: every coefficient is kept in 0 .. q-1 and
 * reduced after each step. The reductions use multiply-and-shift instead of
 * a divider; test/test_unit.c checks them for every possible input.
 */
#include "poly.h"

#include "fips202.h"

/* zetas[i] = 17^BitRev7(i) mod q (FIPS 203, Appendix A) */
static const uint16_t zetas[128] = {
      1, 1729, 2580, 3289, 2642,  630, 1897,  848, 1062, 1919,  193,  797,
   2786, 3260,  569, 1746,  296, 2447, 1339, 1476, 3046,   56, 2240, 1333,
   1426, 2094,  535, 2882, 2393, 2879, 1974,  821,  289,  331, 3253, 1756,
   1197, 2304, 2277, 2055,  650, 1977, 2513,  632, 2865,   33, 1320, 1915,
   2319, 1435,  807,  452, 1438, 2868, 1534, 2402, 2647, 2617, 1481,  648,
   2474, 3110, 1227,  910,   17, 2761,  583, 2649, 1637,  723, 2288, 1100,
   1409, 2662, 3281,  233,  756, 2156, 3015, 3050, 1703, 1651, 2789, 1789,
   1847,  952, 1461, 2687,  939, 2308, 2437, 2388,  733, 2337,  268,  641,
   1584, 2298, 2037, 3220,  375, 2549, 2090, 1645, 1063,  319, 2773,  757,
   2099,  561, 2466, 2594, 2804, 1092,  403, 1026, 1143, 2150, 2775,  886,
   1722, 1212, 1874, 1029, 2110, 2935,  885, 2154
};

/* gammas[i] = 17^(2*BitRev7(i)+1) mod q, for the base-case multiplication */
static const uint16_t gammas[128] = {
     17, 3312, 2761,  568,  583, 2746, 2649,  680, 1637, 1692,  723, 2606,
   2288, 1041, 1100, 2229, 1409, 1920, 2662,  667, 3281,   48,  233, 3096,
    756, 2573, 2156, 1173, 3015,  314, 3050,  279, 1703, 1626, 1651, 1678,
   2789,  540, 1789, 1540, 1847, 1482,  952, 2377, 1461, 1868, 2687,  642,
    939, 2390, 2308, 1021, 2437,  892, 2388,  941,  733, 2596, 2337,  992,
    268, 3061,  641, 2688, 1584, 1745, 2298, 1031, 2037, 1292, 3220,  109,
    375, 2954, 2549,  780, 2090, 1239, 1645, 1684, 1063, 2266,  319, 3010,
   2773,  556,  757, 2572, 2099, 1230,  561, 2768, 2466,  863, 2594,  735,
   2804,  525, 1092, 2237,  403, 2926, 1026, 2303, 1143, 2186, 2150, 1179,
   2775,  554,  886, 2443, 1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300,
   2110, 1219, 2935,  394,  885, 2444, 2154, 1175
};

/* ---------------------------------------------------------------------------
 * Arithmetic modulo q = 3329
 * ------------------------------------------------------------------------- */

/* Barrett reduction for 0 <= a < 2^24: a mod q.
 * t = floor(a * 5039 / 2^24) is floor(a/q) or one less, so a - t*q < 2q. */
MLKEM_API uint16_t mod_q(uint32_t a)
{
   uint32_t t = (uint32_t)(((uint64_t)a * 5039u) >> 24);
   uint32_t r = a - t * MLKEM_Q;
   if(r >= MLKEM_Q)
      r -= MLKEM_Q;
   return (uint16_t)r;
}

MLKEM_LOCAL uint16_t add_q(uint16_t a, uint16_t b)
{
   uint16_t s = (uint16_t)(a + b);
   return (s >= MLKEM_Q) ? (uint16_t)(s - MLKEM_Q) : s;
}

MLKEM_LOCAL uint16_t sub_q(uint16_t a, uint16_t b)
{
   uint16_t s = (uint16_t)(a + MLKEM_Q - b);
   return (s >= MLKEM_Q) ? (uint16_t)(s - MLKEM_Q) : s;
}

MLKEM_LOCAL uint16_t mul_q(uint16_t a, uint16_t b)
{
   return mod_q((uint32_t)a * b);
}

MLKEM_LEAF void poly_zero(poly* r)
{
   int i;
   for(i = 0; i < MLKEM_N; i++)
      r->c[i] = 0;
}

MLKEM_LEAF void poly_add(poly* r, const poly* a)
{
   int i;
   for(i = 0; i < MLKEM_N; i++)
      r->c[i] = add_q(r->c[i], a->c[i]);
}

MLKEM_LEAF void poly_sub(poly* r, const poly* a)
{
   int i;
   for(i = 0; i < MLKEM_N; i++)
      r->c[i] = sub_q(r->c[i], a->c[i]);
}

/* ---------------------------------------------------------------------------
 * Number-theoretic transform
 * ------------------------------------------------------------------------- */

/* Algorithm 9: NTT, in place */
MLKEM_LEAF void poly_ntt(poly* f)
{
   int len, start, j, k = 1;
   for(len = 128; len >= 2; len >>= 1)
   {
      for(start = 0; start < MLKEM_N; start += 2 * len)
      {
         uint16_t zeta = zetas[k++];
         for(j = start; j < start + len; j++)
         {
            uint16_t t = mul_q(zeta, f->c[j + len]);
            f->c[j + len] = sub_q(f->c[j], t);
            f->c[j] = add_q(f->c[j], t);
         }
      }
   }
}

/* Algorithm 10: inverse NTT, in place */
MLKEM_LEAF void poly_invntt(poly* f)
{
   int len, start, j, k = 127;
   for(len = 2; len <= 128; len <<= 1)
   {
      for(start = 0; start < MLKEM_N; start += 2 * len)
      {
         uint16_t zeta = zetas[k--];
         for(j = start; j < start + len; j++)
         {
            uint16_t t = f->c[j];
            f->c[j] = add_q(t, f->c[j + len]);
            f->c[j + len] = mul_q(zeta, sub_q(f->c[j + len], t));
         }
      }
   }
   for(j = 0; j < MLKEM_N; j++)
      f->c[j] = mul_q(f->c[j], 3303); /* 3303 = 128^-1 mod q */
}

/* Algorithms 11 and 12: acc += a * b for polynomials in the NTT domain.
 * The product is 128 degree-1 multiplications modulo (X^2 - gamma). */
MLKEM_LEAF void poly_basemul_acc(poly* acc, const poly* a, const poly* b)
{
   int i;
   for(i = 0; i < MLKEM_N / 2; i++)
   {
      uint16_t a0 = a->c[2 * i], a1 = a->c[2 * i + 1];
      uint16_t b0 = b->c[2 * i], b1 = b->c[2 * i + 1];
      uint16_t c0 = add_q(mul_q(a0, b0), mul_q(mul_q(a1, b1), gammas[i]));
      uint16_t c1 = add_q(mul_q(a0, b1), mul_q(a1, b0));
      acc->c[2 * i] = add_q(acc->c[2 * i], c0);
      acc->c[2 * i + 1] = add_q(acc->c[2 * i + 1], c1);
   }
}

/* ---------------------------------------------------------------------------
 * Sampling
 * ------------------------------------------------------------------------- */

/* Algorithm 7: SampleNTT(rho || j || i). Rejection sampling of 12-bit values
 * from the SHAKE128 stream; the result is already in the NTT domain. */
MLKEM_API void poly_sample_ntt(poly* a, const uint8_t rho[32], uint8_t j, uint8_t i)
{
   keccak_state xof;
   uint8_t idx[2];
   uint8_t buf[3];
   int n = 0;

   idx[0] = j;
   idx[1] = i;
   keccak_init(&xof, SHAKE128_RATE);
   keccak_absorb(&xof, rho, 32);
   keccak_absorb(&xof, idx, 2);
   keccak_finalize(&xof, 0x1F);

   while(n < MLKEM_N)
   {
      uint16_t d1, d2;
      keccak_squeeze(&xof, buf, 3);
      d1 = (uint16_t)(buf[0] | ((buf[1] & 0x0F) << 8));
      d2 = (uint16_t)((buf[1] >> 4) | (buf[2] << 4));
      if(d1 < MLKEM_Q)
         a->c[n++] = d1;
      if(d2 < MLKEM_Q && n < MLKEM_N)
         a->c[n++] = d2;
   }
}

/* Algorithm 8, SamplePolyCBD_eta, on 64*eta bytes of PRF output.
 * Each coefficient is (sum of eta bits) - (sum of the next eta bits). */
MLKEM_LEAF void poly_cbd(poly* f, const uint8_t* buf, int eta)
{
   int i, j;
   for(i = 0; i < MLKEM_N; i++)
   {
      uint16_t x = 0, y = 0;
      for(j = 0; j < eta; j++)
      {
         int bx = 2 * i * eta + j;
         int by = 2 * i * eta + eta + j;
         x = (uint16_t)(x + ((buf[bx >> 3] >> (bx & 7)) & 1));
         y = (uint16_t)(y + ((buf[by >> 3] >> (by & 7)) & 1));
      }
      f->c[i] = sub_q(x, y);
   }
}

/* f = SamplePolyCBD_eta(PRF_eta(seed, nonce)), PRF = SHAKE256(seed || nonce) */
MLKEM_API void poly_sample_cbd(poly* f, const uint8_t seed[32], uint8_t nonce, int eta)
{
   uint8_t buf[64 * 3]; /* 64 * eta bytes, eta <= 3 */
   uint8_t in[33];
   int i;

   for(i = 0; i < 32; i++)
      in[i] = seed[i];
   in[32] = nonce;
   shake256(buf, (uint32_t)(64 * eta), in, 33);
   poly_cbd(f, buf, eta);
}

/* ---------------------------------------------------------------------------
 * Encoding and compression
 * ------------------------------------------------------------------------- */

/* Algorithm 5: ByteEncode_d. Coefficients (each < 2^d) are packed
 * least-significant bit first into 32*d bytes. */
MLKEM_LEAF void poly_encode(uint8_t* out, const poly* f, int d)
{
   uint32_t acc = 0;
   int nbits = 0, i, k = 0;
   for(i = 0; i < MLKEM_N; i++)
   {
      acc |= (uint32_t)f->c[i] << nbits;
      nbits += d;
      while(nbits >= 8)
      {
         out[k++] = (uint8_t)acc;
         acc >>= 8;
         nbits -= 8;
      }
   }
}

/* Algorithm 6: ByteDecode_d. For d = 12 the values are reduced mod q, and the
 * return value tells whether they already were (the ML-KEM modulus check). */
MLKEM_LEAF int poly_decode(poly* f, const uint8_t* in, int d)
{
   uint32_t acc = 0;
   uint32_t mask = (1u << d) - 1;
   int nbits = 0, i, k = 0, ok = 1;
   for(i = 0; i < MLKEM_N; i++)
   {
      uint32_t v;
      while(nbits < d)
      {
         acc |= (uint32_t)in[k++] << nbits;
         nbits += 8;
      }
      v = acc & mask;
      acc >>= d;
      nbits -= d;
      if(d == 12 && v >= MLKEM_Q)
      {
         ok = 0;
         v -= MLKEM_Q;
      }
      f->c[i] = (uint16_t)v;
   }
   return ok;
}

/* Compress_d(x) = round(2^d * x / q) mod 2^d, for d < 12.
 * floor(v / q) is computed as (v * 2580335) >> 33, exact for v < 2^23. */
MLKEM_LEAF void poly_compress(poly* f, int d)
{
   int i;
   for(i = 0; i < MLKEM_N; i++)
   {
      uint32_t v = ((uint32_t)f->c[i] << d) + MLKEM_Q / 2;
      uint32_t t = (uint32_t)(((uint64_t)v * 2580335u) >> 33);
      f->c[i] = (uint16_t)(t & ((1u << d) - 1));
   }
}

/* Decompress_d(y) = round(q * y / 2^d) */
MLKEM_LEAF void poly_decompress(poly* f, int d)
{
   int i;
   for(i = 0; i < MLKEM_N; i++)
      f->c[i] = (uint16_t)(((uint32_t)f->c[i] * MLKEM_Q + (1u << (d - 1))) >> d);
}
