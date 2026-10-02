/*
 * mlkem_hls.c - the single file Bambu compiles.
 *
 * It includes all the C sources, so the compiler sees every function body
 * at once, and defines MLKEM_HLS_UNITY, which turns on the inline / noinline
 * attributes in src/hls.h:
 *
 *   - the datapath leaves (keccak_f1600, keccak_sponge, poly_ntt, ...) stay
 *     separate functions -> one hardware module instance each;
 *   - everything else is inlined into mlkem_accel() -> one controller.
 *
 * The software build (tests, ARM program) compiles the .c files separately
 * and is not affected.
 */
#define MLKEM_HLS_UNITY 1

#include "fips202.c"
#include "poly.c"
#include "mlkem.c"
#include "mlkem_accel.c"
