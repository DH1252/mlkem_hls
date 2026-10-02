/*
 * test_acvp.c - checks the C implementation against the NIST ACVP vectors.
 *
 * Build and run for one parameter set (the Makefile does all three):
 *   gcc -O2 -DMLKEM_K=3 -Isrc test/test_acvp.c src/fips202.c src/poly.c src/mlkem.c \
 *       -o build/test_k3
 *   ./build/test_k3 vectors/ML-KEM-768.txt
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mlkem.h"

#define MAXHEX 8192

static int hex2bin(const char* hex, uint8_t* out, size_t expected)
{
   size_t n = strlen(hex), i;
   if(n != 2 * expected)
      return 0;
   for(i = 0; i < expected; i++)
   {
      unsigned v;
      if(sscanf(hex + 2 * i, "%2x", &v) != 1)
         return 0;
      out[i] = (uint8_t)v;
   }
   return 1;
}

static char f1[MAXHEX], f2[MAXHEX], f3[MAXHEX], f4[MAXHEX];

int main(int argc, char** argv)
{
   char kind[16];
   int tc, pass = 0, fail = 0, lineno = 0;
   int counts[5] = {0, 0, 0, 0, 0};
   FILE* fp;

   if(argc != 2)
   {
      fprintf(stderr, "usage: %s vectors/%s.txt\n", argv[0], MLKEM_NAME);
      return 2;
   }
   fp = fopen(argv[1], "r");
   if(!fp)
   {
      perror(argv[1]);
      return 2;
   }

   while(fscanf(fp, "%15s %d", kind, &tc) == 2)
   {
      int ok = 0;
      lineno++;
      if(!strcmp(kind, "keygen"))
      {
         static uint8_t d[32], z[32], ek_exp[MLKEM_EK_BYTES], dk_exp[MLKEM_DK_BYTES];
         static uint8_t ek[MLKEM_EK_BYTES], dk[MLKEM_DK_BYTES];
         if(fscanf(fp, "%s %s %s %s", f1, f2, f3, f4) != 4)
            break;
         ok = hex2bin(f1, d, 32) && hex2bin(f2, z, 32) && hex2bin(f3, ek_exp, sizeof ek_exp) &&
              hex2bin(f4, dk_exp, sizeof dk_exp);
         if(ok)
         {
            mlkem_keygen_internal(d, z, ek, dk);
            ok = !memcmp(ek, ek_exp, sizeof ek) && !memcmp(dk, dk_exp, sizeof dk);
         }
         counts[0]++;
      }
      else if(!strcmp(kind, "encaps"))
      {
         static uint8_t ek[MLKEM_EK_BYTES], m[32], c_exp[MLKEM_CT_BYTES], k_exp[32];
         static uint8_t c[MLKEM_CT_BYTES], k[32];
         if(fscanf(fp, "%s %s %s %s", f1, f2, f3, f4) != 4)
            break;
         ok = hex2bin(f1, ek, sizeof ek) && hex2bin(f2, m, 32) && hex2bin(f3, c_exp, sizeof c_exp) &&
              hex2bin(f4, k_exp, 32);
         if(ok)
         {
            mlkem_encaps_internal(ek, m, k, c);
            ok = !memcmp(c, c_exp, sizeof c) && !memcmp(k, k_exp, 32);
         }
         counts[1]++;
      }
      else if(!strcmp(kind, "decaps"))
      {
         static uint8_t dk[MLKEM_DK_BYTES], c[MLKEM_CT_BYTES], k_exp[32], k[32];
         if(fscanf(fp, "%s %s %s %15s", f1, f2, f3, f4) != 4) /* f4: valid / rejected */
            break;
         ok = hex2bin(f1, dk, sizeof dk) && hex2bin(f2, c, sizeof c) && hex2bin(f3, k_exp, 32);
         if(ok)
         {
            mlkem_decaps_internal(dk, c, k);
            ok = !memcmp(k, k_exp, 32);
         }
         counts[2]++;
      }
      else if(!strcmp(kind, "ekcheck") || !strcmp(kind, "dkcheck"))
      {
         static uint8_t key[MLKEM_DK_BYTES];
         int expected;
         int is_ek = !strcmp(kind, "ekcheck");
         if(fscanf(fp, "%s %d", f1, &expected) != 2)
            break;
         ok = hex2bin(f1, key, is_ek ? MLKEM_EK_BYTES : MLKEM_DK_BYTES);
         if(ok)
            ok = ((is_ek ? mlkem_check_ek(key) : mlkem_check_dk(key)) == expected);
         counts[is_ek ? 3 : 4]++;
      }
      else
      {
         fprintf(stderr, "line %d: unknown test '%s'\n", lineno, kind);
         return 2;
      }

      if(ok)
         pass++;
      else
      {
         fail++;
         printf("FAIL %s tcId=%d\n", kind, tc);
      }
   }
   fclose(fp);

   printf("%s: keygen %d, encaps %d, decaps %d, ek check %d, dk check %d -> %d passed, %d failed\n",
          MLKEM_NAME, counts[0], counts[1], counts[2], counts[3], counts[4], pass, fail);
   return (fail == 0 && pass > 0) ? 0 : 1;
}
