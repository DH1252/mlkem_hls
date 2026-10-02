/*
 * hls.h - how the C functions map onto hardware modules.
 *
 * Bambu turns every function that is not inlined into a Verilog module, and
 * it gives each calling module its own instance of it. Instances therefore
 * multiply down the call tree: in the first version of this project the
 * Keccak permutation was reached through 39 different call paths (sha3_256
 * inside mlkem_check_dk, shake256 inside poly_sample_cbd inside kpke_encrypt
 * inside mlkem_encaps_internal, ...) and the design held 39 copies of it,
 * each with a 1600-bit state, far more than the DE10-Nano's FPGA can hold.
 *
 * The fix is a two-level hierarchy:
 *
 *   MLKEM_LEAF    the datapath functions (Keccak, NTT, base multiplication,
 *                 encoding, ...). Never inlined or cloned (a clone would be a
 *                 second module), called only from mlkem_accel() (Keccak's
 *                 permutation only from keccak_sponge), so each one exists
 *                 exactly once in hardware.
 *   MLKEM_API,    everything above them (SHA-3/SHAKE wrappers, sampling,
 *   MLKEM_LOCAL   K-PKE, ML-KEM). Always inlined, so all of it collapses into
 *                 the top function mlkem_accel(): one controller (state
 *                 machine) that calls the leaves, one instance of each.
 *
 * The attributes only take effect when all the code is one translation
 * unit, which is what hls/mlkem_hls.c does for Bambu (it defines
 * MLKEM_HLS_UNITY). For the normal software build the macros are empty and
 * the functions are ordinary external functions.
 */
#ifndef MLKEM_HLS_H
#define MLKEM_HLS_H

#if defined(MLKEM_HLS_UNITY) && defined(__GNUC__)
#define MLKEM_API static inline __attribute__((always_inline))
#define MLKEM_LOCAL static inline __attribute__((always_inline))
#define MLKEM_LEAF static __attribute__((noinline, noclone))
#else
#define MLKEM_API
#define MLKEM_LOCAL static
#define MLKEM_LEAF
#endif

#endif
