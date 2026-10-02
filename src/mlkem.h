/*
 * mlkem.h - ML-KEM key-encapsulation mechanism (FIPS 203)
 *
 * These are the deterministic "internal" algorithms of FIPS 203, section 6.
 * The caller supplies the random seeds (d, z for KeyGen, m for Encaps) from
 * an approved random bit generator; that is what makes the same code usable
 * as a hardware accelerator, where the random numbers come from the CPU.
 *
 *   mlkem_keygen_internal   Algorithm 16  (d, z)  -> (ek, dk)
 *   mlkem_encaps_internal   Algorithm 17  (ek, m) -> (K, c)
 *   mlkem_decaps_internal   Algorithm 18  (dk, c) -> K
 *
 *   mlkem_check_ek          section 7.2 modulus check, before Encaps
 *   mlkem_check_dk          section 7.3 hash check, before Decaps
 *
 * Educational implementation: it follows the standard closely and passes the
 * NIST ACVP test vectors, but it has not been reviewed for side channels and
 * is not a validated (CMVP) module.
 */
#ifndef MLKEM_H
#define MLKEM_H

#include <stdint.h>

#include "hls.h"
#include "mlkem_params.h"

MLKEM_API void mlkem_keygen_internal(const uint8_t d[32], const uint8_t z[32], uint8_t ek[MLKEM_EK_BYTES],
                           uint8_t dk[MLKEM_DK_BYTES]);

MLKEM_API void mlkem_encaps_internal(const uint8_t ek[MLKEM_EK_BYTES], const uint8_t m[32],
                           uint8_t K[MLKEM_SS_BYTES], uint8_t c[MLKEM_CT_BYTES]);

MLKEM_API void mlkem_decaps_internal(const uint8_t dk[MLKEM_DK_BYTES], const uint8_t c[MLKEM_CT_BYTES],
                           uint8_t K[MLKEM_SS_BYTES]);

MLKEM_API int mlkem_check_ek(const uint8_t ek[MLKEM_EK_BYTES]); /* 1 = valid, 0 = reject */
MLKEM_API int mlkem_check_dk(const uint8_t dk[MLKEM_DK_BYTES]); /* 1 = valid, 0 = reject */

#endif
