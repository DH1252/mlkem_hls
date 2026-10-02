/*
 * fips202.h - SHA-3 and SHAKE (FIPS 202), the hash functions ML-KEM uses.
 *
 * ML-KEM names them (FIPS 203, section 4.1):
 *   H   = SHA3-256          sha3_256()
 *   G   = SHA3-512          sha3_512()
 *   J   = SHAKE256, 32 B    shake256()
 *   PRF = SHAKE256          shake256()
 *   XOF = SHAKE128          keccak_* incremental API (used by SampleNTT)
 *
 * Written for high-level synthesis as well as for CPUs: no dynamic memory,
 * no recursion, fixed-size state, byte-at-a-time absorb/squeeze.
 *
 * Hardware structure (see hls.h): keccak_sponge() is the only function that
 * touches a Keccak state and keccak_f1600() is called only from it, so the
 * synthesised design contains exactly one Keccak permutation. All the other
 * functions here are thin wrappers that are inlined into their callers.
 */
#ifndef FIPS202_H
#define FIPS202_H

#include <stdint.h>

#include "hls.h"

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct
{
   uint64_t s[25]; /* the 1600-bit Keccak state, 25 lanes of 64 bits */
   uint32_t pos;   /* bytes of the current block used so far (rate = the
                      block is full; the permutation runs before the next
                      byte is absorbed or squeezed) */
   uint32_t rate;  /* block size in bytes */
} keccak_state;

/* The two leaves: the permutation, and the sponge engine around it.
 * keccak_sponge() modes: */
#define KECCAK_ABSORB 0u  /* XOR len bytes of buf into the state          */
#define KECCAK_SQUEEZE 1u /* copy len bytes of output into buf           */
#define KECCAK_PAD 2u     /* absorb the padding byte buf[0] (len = 1),
                             set the last bit of the block, switch to
                             squeezing                                     */
MLKEM_LEAF void keccak_f1600(uint64_t st[25]);
MLKEM_LEAF void keccak_sponge(keccak_state* ks, uint8_t* buf, uint32_t len, uint32_t mode);

/* Incremental sponge: init -> absorb (any number of times) -> finalize ->
 * squeeze (any number of times). pad is 0x06 for SHA3, 0x1F for SHAKE. */
MLKEM_API void keccak_init(keccak_state* ks, uint32_t rate);
MLKEM_API void keccak_absorb(keccak_state* ks, const uint8_t* in, uint32_t len);
MLKEM_API void keccak_finalize(keccak_state* ks, uint8_t pad);
MLKEM_API void keccak_squeeze(keccak_state* ks, uint8_t* out, uint32_t len);

MLKEM_API void sha3_256(uint8_t out[32], const uint8_t* in, uint32_t len);
MLKEM_API void sha3_512(uint8_t out[64], const uint8_t* in, uint32_t len);
MLKEM_API void shake256(uint8_t* out, uint32_t outlen, const uint8_t* in, uint32_t inlen);

#endif
