/*
 * mlkem_params.h - ML-KEM parameter sets (FIPS 203, Table 2)
 *
 * Choose the parameter set at compile time with -DMLKEM_K=2, 3 or 4:
 *
 *   MLKEM_K = 2  ->  ML-KEM-512   (NIST security category 1)
 *   MLKEM_K = 3  ->  ML-KEM-768   (category 3, the recommended default)
 *   MLKEM_K = 4  ->  ML-KEM-1024  (category 5)
 */
#ifndef MLKEM_PARAMS_H
#define MLKEM_PARAMS_H

#ifndef MLKEM_K
#define MLKEM_K 3
#endif

#define MLKEM_N 256  /* coefficients per polynomial */
#define MLKEM_Q 3329 /* the prime modulus q */

#if MLKEM_K == 2
#define MLKEM_NAME "ML-KEM-512"
#define MLKEM_ETA1 3
#define MLKEM_DU 10
#define MLKEM_DV 4
#elif MLKEM_K == 3
#define MLKEM_NAME "ML-KEM-768"
#define MLKEM_ETA1 2
#define MLKEM_DU 10
#define MLKEM_DV 4
#elif MLKEM_K == 4
#define MLKEM_NAME "ML-KEM-1024"
#define MLKEM_ETA1 2
#define MLKEM_DU 11
#define MLKEM_DV 5
#else
#error "MLKEM_K must be 2, 3 or 4"
#endif
#define MLKEM_ETA2 2

/* Byte sizes (FIPS 203, Table 3) */
#define MLKEM_SYMBYTES 32                          /* d, z, m, rho, sigma, K, H(ek) */
#define MLKEM_POLYBYTES 384                        /* one polynomial, 12 bits/coeff */
#define MLKEM_EK_BYTES (384 * MLKEM_K + 32)        /* encapsulation key */
#define MLKEM_DK_PKE_BYTES (384 * MLKEM_K)         /* K-PKE decryption key */
#define MLKEM_DK_BYTES (768 * MLKEM_K + 96)        /* decapsulation key */
#define MLKEM_CT_BYTES (32 * (MLKEM_DU * MLKEM_K + MLKEM_DV)) /* ciphertext */
#define MLKEM_SS_BYTES 32                          /* shared secret K */

#endif
