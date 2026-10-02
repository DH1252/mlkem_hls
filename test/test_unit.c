/*
 * test_unit.c - exhaustive checks of the arithmetic shortcuts plus randomized
 * KeyGen -> Encaps -> Decaps round trips.
 *
 * The NIST vectors test the whole algorithms; this file tests the tricks the
 * vectors might not hit: mod_q() is checked for every input below 2^24, and
 * Compress/Decompress for every coefficient and every d that ML-KEM uses.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mlkem.h"
#include "poly.h"

static int check_mod_q(void)
{
   uint32_t a;
   for(a = 0; a < (1u << 24); a++)
      if(mod_q(a) != a % MLKEM_Q)
      {
         printf("mod_q(%u) = %u, expected %u\n", a, mod_q(a), a % MLKEM_Q);
         return 0;
      }
   return 1;
}

static int check_compress(void)
{
   static const int ds[] = {1, 4, 5, 10, 11};
   int n, x;
   poly p;
   for(n = 0; n < 5; n++)
   {
      int d = ds[n];
      for(x = 0; x < MLKEM_Q; x++)
      {
         /* exact: round(2^d * x / q) mod 2^d, computed with a real division */
         uint32_t want_c = (uint32_t)((((uint64_t)x << d) * 2 + MLKEM_Q) / (2 * MLKEM_Q)) & ((1u << d) - 1);
         p.c[0] = (uint16_t)x;
         poly_compress(&p, d);
         if(p.c[0] != want_c)
         {
            printf("Compress_%d(%d) = %u, expected %u\n", d, x, p.c[0], want_c);
            return 0;
         }
      }
      for(x = 0; x < (1 << d); x++)
      {
         uint32_t want_d = (uint32_t)(((uint64_t)x * MLKEM_Q * 2 + (1u << d)) / (2u << d));
         p.c[0] = (uint16_t)x;
         poly_decompress(&p, d);
         if(p.c[0] != want_d)
         {
            printf("Decompress_%d(%d) = %u, expected %u\n", d, x, p.c[0], want_d);
            return 0;
         }
      }
   }
   return 1;
}

static void random_bytes(uint8_t* p, int n)
{
   int i;
   for(i = 0; i < n; i++)
      p[i] = (uint8_t)(rand() >> 7);
}

static int check_roundtrips(int iterations)
{
   static uint8_t d[32], z[32], m[32], ek[MLKEM_EK_BYTES], dk[MLKEM_DK_BYTES];
   static uint8_t c[MLKEM_CT_BYTES], k1[32], k2[32], k3[32];
   int it;
   srand(2026);
   for(it = 0; it < iterations; it++)
   {
      random_bytes(d, 32);
      random_bytes(z, 32);
      random_bytes(m, 32);
      mlkem_keygen_internal(d, z, ek, dk);
      if(!mlkem_check_ek(ek) || !mlkem_check_dk(dk))
         return 0;
      mlkem_encaps_internal(ek, m, k1, c);
      mlkem_decaps_internal(dk, c, k2);
      if(memcmp(k1, k2, 32) != 0)
      {
         printf("round trip %d: decapsulated key differs\n", it);
         return 0;
      }
      c[it % MLKEM_CT_BYTES] ^= (uint8_t)(1u << (it % 8)); /* tamper with one bit */
      mlkem_decaps_internal(dk, c, k3);
      if(memcmp(k1, k3, 32) == 0)
      {
         printf("round trip %d: tampered ciphertext was accepted\n", it);
         return 0;
      }
   }
   return 1;
}

int main(void)
{
   int ok = 1;
   int r;
   r = check_mod_q();
   printf("%s mod_q for all 2^24 inputs\n", r ? "[PASS]" : "[FAIL]");
   ok &= r;
   r = check_compress();
   printf("%s Compress_d / Decompress_d for every value, d = 1, 4, 5, 10, 11\n", r ? "[PASS]" : "[FAIL]");
   ok &= r;
   r = check_roundtrips(500);
   printf("%s %s: 500 random KeyGen/Encaps/Decaps round trips + tampered ciphertexts\n",
          r ? "[PASS]" : "[FAIL]", MLKEM_NAME);
   ok &= r;
   return ok ? 0 : 1;
}
