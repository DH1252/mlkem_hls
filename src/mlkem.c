/*
 * mlkem.c - K-PKE and ML-KEM (FIPS 203, sections 5 and 6)
 *
 * Written to be both a readable companion to the standard and valid input
 * for high-level synthesis: fixed-size local arrays, no dynamic memory, no
 * recursion. The public matrix A is never stored; each entry is regenerated
 * with SampleNTT right when it is needed, which saves k*k polynomials of
 * memory.
 *
 * In the accelerator every function in this file is inlined into
 * mlkem_accel() (see hls.h); only the polynomial and Keccak leaves remain as
 * separate hardware modules.
 */
#include "mlkem.h"

#include "fips202.h"
#include "poly.h"

#define K MLKEM_K

MLKEM_LOCAL void copy_bytes(uint8_t* dst, const uint8_t* src, uint32_t n)
{
   uint32_t i;
   for(i = 0; i < n; i++)
      dst[i] = src[i];
}

/* ---------------------------------------------------------------------------
 * K-PKE, the underlying public-key encryption scheme (section 5)
 * ------------------------------------------------------------------------- */

/* Algorithm 13: K-PKE.KeyGen(d) -> (ek_PKE, dk_PKE) */
MLKEM_LOCAL void kpke_keygen(const uint8_t d[32], uint8_t ek[MLKEM_EK_BYTES],
                             uint8_t dk_pke[MLKEM_DK_PKE_BYTES])
{
   uint8_t seed_in[33];
   uint8_t rho_sigma[64]; /* rho = first 32 bytes, sigma = last 32 bytes */
   poly s_hat[K];
   poly a, e, t;
   int i, j;

   /* (rho, sigma) = G(d || k) */
   copy_bytes(seed_in, d, 32);
   seed_in[32] = K;
   sha3_512(rho_sigma, seed_in, 33);

   /* s = SamplePolyCBD_eta1(PRF(sigma, N)), N = 0 .. k-1; s_hat = NTT(s) */
   for(i = 0; i < K; i++)
   {
      poly_sample_cbd(&s_hat[i], rho_sigma + 32, (uint8_t)i, MLKEM_ETA1);
      poly_ntt(&s_hat[i]);
   }

   /* t_hat[i] = sum_j A_hat[i][j] * s_hat[j] + e_hat[i], e uses N = k .. 2k-1 */
   for(i = 0; i < K; i++)
   {
      poly_zero(&t);
      for(j = 0; j < K; j++)
      {
         poly_sample_ntt(&a, rho_sigma, (uint8_t)j, (uint8_t)i); /* A_hat[i][j] = SampleNTT(rho||j||i) */
         poly_basemul_acc(&t, &a, &s_hat[j]);
      }
      poly_sample_cbd(&e, rho_sigma + 32, (uint8_t)(K + i), MLKEM_ETA1);
      poly_ntt(&e);
      poly_add(&t, &e);
      poly_encode(ek + MLKEM_POLYBYTES * i, &t, 12);
   }

   /* ek_PKE = ByteEncode_12(t_hat) || rho,  dk_PKE = ByteEncode_12(s_hat) */
   copy_bytes(ek + MLKEM_POLYBYTES * K, rho_sigma, 32);
   for(i = 0; i < K; i++)
      poly_encode(dk_pke + MLKEM_POLYBYTES * i, &s_hat[i], 12);
}

/* Algorithm 14: K-PKE.Encrypt(ek_PKE, m, r) -> c */
MLKEM_LOCAL void kpke_encrypt(const uint8_t ek[MLKEM_EK_BYTES], const uint8_t m[32], const uint8_t r[32],
                              uint8_t c[MLKEM_CT_BYTES])
{
   const uint8_t* rho = ek + MLKEM_POLYBYTES * K;
   poly y_hat[K];
   poly a, e, u, v, t;
   int i, j;

   /* y = SamplePolyCBD_eta1(PRF(r, N)), N = 0 .. k-1; y_hat = NTT(y) */
   for(i = 0; i < K; i++)
   {
      poly_sample_cbd(&y_hat[i], r, (uint8_t)i, MLKEM_ETA1);
      poly_ntt(&y_hat[i]);
   }

   /* u[i] = NTT^-1(sum_j A_hat[j][i] * y_hat[j]) + e1[i], e1 uses N = k .. 2k-1
    * c1 = ByteEncode_du(Compress_du(u)) */
   for(i = 0; i < K; i++)
   {
      poly_zero(&u);
      for(j = 0; j < K; j++)
      {
         poly_sample_ntt(&a, rho, (uint8_t)i, (uint8_t)j); /* A_hat[j][i] = SampleNTT(rho||i||j) */
         poly_basemul_acc(&u, &a, &y_hat[j]);
      }
      poly_invntt(&u);
      poly_sample_cbd(&e, r, (uint8_t)(K + i), MLKEM_ETA2);
      poly_add(&u, &e);
      poly_compress(&u, MLKEM_DU);
      poly_encode(c + 32 * MLKEM_DU * i, &u, MLKEM_DU);
   }

   /* v = NTT^-1(t_hat^T * y_hat) + e2 + Decompress_1(ByteDecode_1(m)), e2 uses N = 2k
    * c2 = ByteEncode_dv(Compress_dv(v)) */
   poly_zero(&v);
   for(j = 0; j < K; j++)
   {
      poly_decode(&t, ek + MLKEM_POLYBYTES * j, 12);
      poly_basemul_acc(&v, &t, &y_hat[j]);
   }
   poly_invntt(&v);
   poly_sample_cbd(&e, r, (uint8_t)(2 * K), MLKEM_ETA2);
   poly_add(&v, &e);
   poly_decode(&t, m, 1);
   poly_decompress(&t, 1);
   poly_add(&v, &t);
   poly_compress(&v, MLKEM_DV);
   poly_encode(c + 32 * MLKEM_DU * K, &v, MLKEM_DV);
}

/* Algorithm 15: K-PKE.Decrypt(dk_PKE, c) -> m */
MLKEM_LOCAL void kpke_decrypt(const uint8_t dk_pke[MLKEM_DK_PKE_BYTES], const uint8_t c[MLKEM_CT_BYTES],
                              uint8_t m[32])
{
   poly u, s, v, w;
   int i;

   /* w = v' - NTT^-1(s_hat^T * NTT(u')) */
   poly_zero(&w);
   for(i = 0; i < K; i++)
   {
      poly_decode(&u, c + 32 * MLKEM_DU * i, MLKEM_DU);
      poly_decompress(&u, MLKEM_DU);
      poly_ntt(&u);
      poly_decode(&s, dk_pke + MLKEM_POLYBYTES * i, 12);
      poly_basemul_acc(&w, &s, &u);
   }
   poly_invntt(&w);
   poly_decode(&v, c + 32 * MLKEM_DU * K, MLKEM_DV);
   poly_decompress(&v, MLKEM_DV);
   poly_sub(&v, &w);

   /* m = ByteEncode_1(Compress_1(w)) */
   poly_compress(&v, 1);
   poly_encode(m, &v, 1);
}

/* ---------------------------------------------------------------------------
 * ML-KEM (section 6)
 * ------------------------------------------------------------------------- */

/* Algorithm 16: ML-KEM.KeyGen_internal(d, z) -> (ek, dk)
 * dk = dk_PKE || ek || H(ek) || z */
MLKEM_API void mlkem_keygen_internal(const uint8_t d[32], const uint8_t z[32], uint8_t ek[MLKEM_EK_BYTES],
                           uint8_t dk[MLKEM_DK_BYTES])
{
   kpke_keygen(d, ek, dk);
   copy_bytes(dk + MLKEM_DK_PKE_BYTES, ek, MLKEM_EK_BYTES);
   sha3_256(dk + MLKEM_DK_PKE_BYTES + MLKEM_EK_BYTES, ek, MLKEM_EK_BYTES);
   copy_bytes(dk + MLKEM_DK_PKE_BYTES + MLKEM_EK_BYTES + 32, z, 32);
}

/* Algorithm 17: ML-KEM.Encaps_internal(ek, m) -> (K, c) */
MLKEM_API void mlkem_encaps_internal(const uint8_t ek[MLKEM_EK_BYTES], const uint8_t m[32],
                           uint8_t Kout[MLKEM_SS_BYTES], uint8_t c[MLKEM_CT_BYTES])
{
   uint8_t g_in[64];
   uint8_t kr[64]; /* K = first 32 bytes, r = last 32 bytes */

   /* (K, r) = G(m || H(ek)) */
   copy_bytes(g_in, m, 32);
   sha3_256(g_in + 32, ek, MLKEM_EK_BYTES);
   sha3_512(kr, g_in, 64);

   kpke_encrypt(ek, m, kr + 32, c);
   copy_bytes(Kout, kr, 32);
}

/* Algorithm 18: ML-KEM.Decaps_internal(dk, c) -> K
 * Re-encrypts the decrypted message and compares with c. On a mismatch the
 * result is the "implicit rejection" key J(z || c), chosen without a branch
 * so the time taken does not reveal which case happened. */
MLKEM_API void mlkem_decaps_internal(const uint8_t dk[MLKEM_DK_BYTES], const uint8_t c[MLKEM_CT_BYTES],
                           uint8_t Kout[MLKEM_SS_BYTES])
{
   const uint8_t* dk_pke = dk;
   const uint8_t* ek_pke = dk + MLKEM_DK_PKE_BYTES;
   const uint8_t* h = dk + MLKEM_DK_PKE_BYTES + MLKEM_EK_BYTES;
   const uint8_t* z = h + 32;
   uint8_t g_in[64];
   uint8_t kr[64];
   uint8_t k_bar[32];
   uint8_t c_prime[MLKEM_CT_BYTES];
   keccak_state j;
   uint32_t diff = 0;
   uint8_t mask;
   int i;

   /* m' = K-PKE.Decrypt(dk_PKE, c);  (K', r') = G(m' || h) */
   kpke_decrypt(dk_pke, c, g_in);
   copy_bytes(g_in + 32, h, 32);
   sha3_512(kr, g_in, 64);

   /* K_bar = J(z || c) = SHAKE256(z || c, 32) */
   keccak_init(&j, SHAKE256_RATE);
   keccak_absorb(&j, z, 32);
   keccak_absorb(&j, c, MLKEM_CT_BYTES);
   keccak_finalize(&j, 0x1F);
   keccak_squeeze(&j, k_bar, 32);

   /* c' = K-PKE.Encrypt(ek_PKE, m', r'); if c != c' then K' = K_bar */
   kpke_encrypt(ek_pke, g_in, kr + 32, c_prime);
   for(i = 0; i < MLKEM_CT_BYTES; i++)
      diff |= (uint32_t)(c[i] ^ c_prime[i]);
   diff = (diff | (0u - diff)) >> 31; /* 1 if any byte differed, else 0 */
   mask = (uint8_t)(0u - diff);       /* 0xFF or 0x00 */
   for(i = 0; i < 32; i++)
      Kout[i] = (uint8_t)(kr[i] ^ (mask & (kr[i] ^ k_bar[i])));
}

/* Section 7.2, modulus check: every 12-bit value in ek must be < q */
MLKEM_API int mlkem_check_ek(const uint8_t ek[MLKEM_EK_BYTES])
{
   poly t;
   int i, ok = 1;
   for(i = 0; i < K; i++)
      ok &= poly_decode(&t, ek + MLKEM_POLYBYTES * i, 12);
   return ok;
}

/* Section 7.3, hash check: H(ek part of dk) must equal the stored hash */
MLKEM_API int mlkem_check_dk(const uint8_t dk[MLKEM_DK_BYTES])
{
   uint8_t h[32];
   const uint8_t* stored = dk + MLKEM_DK_PKE_BYTES + MLKEM_EK_BYTES;
   uint32_t diff = 0;
   int i;
   sha3_256(h, dk + MLKEM_DK_PKE_BYTES, MLKEM_EK_BYTES);
   for(i = 0; i < 32; i++)
      diff |= (uint32_t)(h[i] ^ stored[i]);
   return diff == 0;
}
