/*
 * tb_accel.c - testbench for Bambu (--generate-tb=hls/tb_accel.c).
 *
 * This main() is ordinary C. During "bambu --simulate" it runs on the host,
 * but every call to mlkem_accel() is executed by the generated Verilog in a
 * simulator, reading and writing this program's mem[] array through the
 * module's RAM ports. So the checks below test the hardware, not the C code.
 *
 * Also works as a plain C program:
 *   gcc -Isrc -Ihls hls/tb_accel.c src/fips202.c src/poly.c src/mlkem.c \
 *       src/mlkem_accel.c && ./a.out
 */
#include <stdio.h>
#include <string.h>

#include "mlkem_accel.h"
#include "tb_vectors.h"

static uint8_t mem[MLKEM_MEM_BYTES];
static int errors = 0;

static void check(int cond, const char* what)
{
   printf("%s %s\n", cond ? "[PASS]" : "[FAIL]", what);
   if(!cond)
      errors++;
}

int main(void)
{
   uint32_t st;
   int n;

   /* 1. KeyGen: (d, z) -> (ek, dk) */
   memset(mem, 0, sizeof mem);
   memcpy(mem + MLKEM_OFF_D, kg_d, 32);
   memcpy(mem + MLKEM_OFF_Z, kg_z, 32);
   st = mlkem_accel(MLKEM_OP_KEYGEN, mem);
   check(st == MLKEM_STATUS_OK && !memcmp(mem + MLKEM_OFF_EK, kg_ek, MLKEM_EK_BYTES) &&
            !memcmp(mem + MLKEM_OFF_DK, kg_dk, MLKEM_DK_BYTES),
         "KeyGen: ek and dk match NIST");

   /* 2. Encaps: (ek, m) -> (K, c) */
   memset(mem, 0, sizeof mem);
   memcpy(mem + MLKEM_OFF_EK, en_ek, MLKEM_EK_BYTES);
   memcpy(mem + MLKEM_OFF_M, en_m, 32);
   st = mlkem_accel(MLKEM_OP_ENCAPS, mem);
   check(st == MLKEM_STATUS_OK && !memcmp(mem + MLKEM_OFF_SS, en_k, 32) &&
            !memcmp(mem + MLKEM_OFF_CT, en_c, MLKEM_CT_BYTES),
         "Encaps: K and c match NIST");

   /* 3. Decaps: a valid ciphertext, then a modified one (implicit rejection) */
   for(n = 0; n < TB_NUM_DECAPS; n++)
   {
      memset(mem, 0, sizeof mem);
      memcpy(mem + MLKEM_OFF_DK, de_dk[n], MLKEM_DK_BYTES);
      memcpy(mem + MLKEM_OFF_CT, de_c[n], MLKEM_CT_BYTES);
      st = mlkem_accel(MLKEM_OP_DECAPS, mem);
      check(st == MLKEM_STATUS_OK && !memcmp(mem + MLKEM_OFF_SS, de_k[n], 32),
            n == 0 ? "Decaps: valid ciphertext, K matches NIST"
                   : "Decaps: modified ciphertext, implicit-rejection K matches NIST");
   }

   /* 4. Input checks */
   memset(mem, 0, sizeof mem);
   memcpy(mem + MLKEM_OFF_EK, bad_ek, MLKEM_EK_BYTES);
   st = mlkem_accel(MLKEM_OP_ENCAPS, mem);
   check(st == MLKEM_STATUS_BAD_KEY, "Encaps rejects an ek that fails the modulus check");

   memset(mem, 0, sizeof mem);
   memcpy(mem + MLKEM_OFF_DK, bad_dk, MLKEM_DK_BYTES);
   st = mlkem_accel(MLKEM_OP_DECAPS, mem);
   check(st == MLKEM_STATUS_BAD_KEY, "Decaps rejects a dk that fails the hash check");

   st = mlkem_accel(7, mem);
   check(st == MLKEM_STATUS_BAD_OP, "unknown operation code is rejected");

   printf("%s: %d error(s)\n", MLKEM_NAME, errors);
   return errors;
}
