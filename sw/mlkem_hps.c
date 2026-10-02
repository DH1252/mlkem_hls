/*
 * mlkem_hps.c - Linux program for the DE10-Nano's ARM cores (the HPS) that
 * drives the ML-KEM accelerator through the lightweight HPS-to-FPGA bridge
 * and checks it against the same C code running on the ARM.
 *
 *   sudo ./mlkem_hps [-a ADDRESS] [-n ROUNDS]
 *        ./mlkem_hps -s [-n ROUNDS]
 *
 *   -a  physical address of the accelerator. The lightweight bridge starts at
 *       0xFF200000, so a component at base 0x40000 in Platform Designer is at
 *       0xFF240000 (the default).
 *   -n  number of random round trips (default 100)
 *   -s  software only: run the tests on the ARM without touching the FPGA
 *
 * Tests
 *   1. ID and PARAMS registers (a wrong address stops here)
 *   2. NIST ACVP known answers (hls/tb_vectors.h), as in the simulations
 *   3. random seeds from /dev/urandom, given to both the FPGA and the C
 *      reference on the ARM: every ek, dk, ciphertext and shared secret must be
 *      bit-identical, and a ciphertext with one flipped bit must be rejected
 *   4. timing: FPGA core cycles, FPGA time including the mailbox copies, and
 *      the ARM software time
 *
 * Build on the board:   gcc -O2 -I../src -I../hls mlkem_hps.c ../src/fips202.c
 *                           ../src/poly.c ../src/mlkem.c -o mlkem_hps
 * or cross-compile:     make sw-arm   (in the project root)
 *
 * Built with -DMLKEM_EMULATE (make sw-emu) the program runs on a PC: the
 * register accesses go to a software model that calls mlkem_accel(), the C
 * function Bambu compiled. That tests this program without a board.
 *
 * Accessing /dev/mem needs root. If the FPGA is not configured or the
 * bridge is held in reset, an access can hang the ARM: configure the FPGA
 * first (see the guide).
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifndef MLKEM_EMULATE
#include <sys/mman.h>
#endif

#include "mlkem.h"
#include "mlkem_accel.h"
#include "tb_vectors.h"

/* Registers (hw/rtl/mlkem_avalon.v) */
#define REG_CTRL 0x2000u
#define REG_STATUS 0x2004u
#define REG_RESULT 0x2008u
#define REG_CYCLES 0x200Cu
#define REG_ID 0x2010u
#define REG_PARAMS 0x2014u
#define REG_IRQ_EN 0x2018u
#define SPAN 0x4000u
#define ID_VALUE 0x4D4C4B4Du
#define STATUS_DONE 0x2u

#define LW_BRIDGE_BASE 0xFF200000u
#define DEFAULT_ADDRESS (LW_BRIDGE_BASE + 0x40000u)
#define CLOCK_HZ 50000000.0

/* --------------------------------------------------------------------------
 * Register access: the real hardware through /dev/mem, or the emulation
 * -------------------------------------------------------------------------- */
#ifndef MLKEM_EMULATE

static volatile uint32_t* hw;

static int hw_open(uint32_t address)
{
   int fd = open("/dev/mem", O_RDWR | O_SYNC);
   void* p;
   if(fd < 0)
   {
      fprintf(stderr, "cannot open /dev/mem (%s) - run with sudo\n", strerror(errno));
      return -1;
   }
   p = mmap(NULL, SPAN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)address);
   close(fd);
   if(p == MAP_FAILED)
   {
      fprintf(stderr, "mmap of 0x%08X failed (%s)\n", (unsigned)address, strerror(errno));
      return -1;
   }
   hw = (volatile uint32_t*)p;
   return 0;
}

static uint32_t reg_read(uint32_t off)
{
   return hw[off / 4];
}

static void reg_write(uint32_t off, uint32_t value)
{
   hw[off / 4] = value;
}

#else /* MLKEM_EMULATE: a model of hw/rtl/mlkem_avalon.v around mlkem_accel() */

static uint8_t emu_mem[MLKEM_MEM_BYTES];
static uint32_t emu_op, emu_done, emu_result, emu_irq_en;

static int hw_open(uint32_t address)
{
   (void)address;
   return 0;
}

static uint32_t reg_read(uint32_t off)
{
   uint32_t v;
   if(off < MLKEM_MEM_BYTES)
   {
      memcpy(&v, emu_mem + off, 4); /* little endian, like the RTL */
      return v;
   }
   switch(off)
   {
      case REG_CTRL: return emu_op;
      case REG_STATUS: return emu_done ? STATUS_DONE : 0;
      case REG_RESULT: return emu_result;
      case REG_CYCLES: return 0;
      case REG_ID: return ID_VALUE;
      case REG_PARAMS: return MLKEM_K;
      case REG_IRQ_EN: return emu_irq_en;
      default: return 0;
   }
}

static void reg_write(uint32_t off, uint32_t value)
{
   if(off < MLKEM_MEM_BYTES)
   {
      memcpy(emu_mem + off, &value, 4);
      return;
   }
   if(off == REG_CTRL)
   {
      emu_op = value;
      emu_result = mlkem_accel(value, emu_mem); /* runs to completion */
      emu_done = 1;
   }
   else if(off == REG_STATUS && (value & STATUS_DONE))
      emu_done = 0;
   else if(off == REG_IRQ_EN)
      emu_irq_en = value & 1;
}

#endif

/* --------------------------------------------------------------------------
 * Accelerator operations
 * -------------------------------------------------------------------------- */
static void mbox_write(uint32_t off, const uint8_t* src, uint32_t n)
{
   uint32_t i, w;
   for(i = 0; i < n; i += 4)
   {
      memcpy(&w, src + i, 4); /* all sizes are multiples of 4 */
      reg_write(off + i, w);
   }
}

static void mbox_read(uint32_t off, uint8_t* dst, uint32_t n)
{
   uint32_t i, w;
   for(i = 0; i < n; i += 4)
   {
      w = reg_read(off + i);
      memcpy(dst + i, &w, 4);
   }
}

/* Keys and secrets stay in the mailbox RAM after an operation: clear it when
   done, so the next user of the accelerator cannot read them. */
static void mbox_clear(void)
{
   uint32_t off;
   for(off = 0; off < MLKEM_MEM_BYTES; off += 4)
      reg_write(off, 0);
}

static uint32_t last_cycles;

/* Start an operation and wait for DONE. Returns the RESULT register. */
static uint32_t run_op(uint32_t op)
{
   struct timespec t0, t;
   uint32_t result;
   reg_write(REG_CTRL, op);
   clock_gettime(CLOCK_MONOTONIC, &t0);
   while(!(reg_read(REG_STATUS) & STATUS_DONE))
   {
      clock_gettime(CLOCK_MONOTONIC, &t);
      if(t.tv_sec - t0.tv_sec > 2)
      {
         fprintf(stderr, "timeout: operation %u did not finish\n", (unsigned)op);
         exit(2);
      }
   }
   result = reg_read(REG_RESULT);
   last_cycles = reg_read(REG_CYCLES);
   reg_write(REG_STATUS, STATUS_DONE); /* clear DONE */
   return result;
}

static uint32_t hw_keygen(const uint8_t d[32], const uint8_t z[32], uint8_t* ek, uint8_t* dk)
{
   uint32_t r;
   mbox_write(MLKEM_OFF_D, d, 32);
   mbox_write(MLKEM_OFF_Z, z, 32);
   r = run_op(MLKEM_OP_KEYGEN);
   mbox_read(MLKEM_OFF_EK, ek, MLKEM_EK_BYTES);
   mbox_read(MLKEM_OFF_DK, dk, MLKEM_DK_BYTES);
   return r;
}

static uint32_t hw_encaps(const uint8_t* ek, const uint8_t m[32], uint8_t K[32], uint8_t* c)
{
   uint32_t r;
   mbox_write(MLKEM_OFF_EK, ek, MLKEM_EK_BYTES);
   mbox_write(MLKEM_OFF_M, m, 32);
   r = run_op(MLKEM_OP_ENCAPS);
   mbox_read(MLKEM_OFF_CT, c, MLKEM_CT_BYTES);
   mbox_read(MLKEM_OFF_SS, K, 32);
   return r;
}

static uint32_t hw_decaps(const uint8_t* dk, const uint8_t* c, uint8_t K[32])
{
   uint32_t r;
   mbox_write(MLKEM_OFF_DK, dk, MLKEM_DK_BYTES);
   mbox_write(MLKEM_OFF_CT, c, MLKEM_CT_BYTES);
   r = run_op(MLKEM_OP_DECAPS);
   mbox_read(MLKEM_OFF_SS, K, 32);
   return r;
}

/* The same three operations in software, with the same input checks */
static uint32_t sw_keygen(const uint8_t d[32], const uint8_t z[32], uint8_t* ek, uint8_t* dk)
{
   mlkem_keygen_internal(d, z, ek, dk);
   return MLKEM_STATUS_OK;
}

static uint32_t sw_encaps(const uint8_t* ek, const uint8_t m[32], uint8_t K[32], uint8_t* c)
{
   if(!mlkem_check_ek(ek))
      return MLKEM_STATUS_BAD_KEY;
   mlkem_encaps_internal(ek, m, K, c);
   return MLKEM_STATUS_OK;
}

static uint32_t sw_decaps(const uint8_t* dk, const uint8_t* c, uint8_t K[32])
{
   if(!mlkem_check_dk(dk))
   {
      memset(K, 0, 32);
      return MLKEM_STATUS_BAD_KEY;
   }
   mlkem_decaps_internal(dk, c, K);
   return MLKEM_STATUS_OK;
}

typedef struct
{
   uint32_t (*keygen)(const uint8_t*, const uint8_t*, uint8_t*, uint8_t*);
   uint32_t (*encaps)(const uint8_t*, const uint8_t*, uint8_t*, uint8_t*);
   uint32_t (*decaps)(const uint8_t*, const uint8_t*, uint8_t*);
   const char* name;
} engine;

static const engine HW = {hw_keygen, hw_encaps, hw_decaps, "FPGA"};
static const engine SW = {sw_keygen, sw_encaps, sw_decaps, "ARM software"};

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */
static int errors;

static void report(const char* what, int ok)
{
   printf("[%s] %s\n", ok ? "PASS" : "FAIL", what);
   if(!ok)
      errors++;
}

static double now_ms(void)
{
   struct timespec t;
   clock_gettime(CLOCK_MONOTONIC, &t);
   return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

static void random_bytes(uint8_t* out, size_t n)
{
   static FILE* f;
   if(!f && !(f = fopen("/dev/urandom", "rb")))
   {
      perror("/dev/urandom");
      exit(2);
   }
   if(fread(out, 1, n, f) != n)
   {
      fprintf(stderr, "short read from /dev/urandom\n");
      exit(2);
   }
}

/* NIST known answers on one engine */
static void known_answers(const engine* e)
{
   static uint8_t ek[MLKEM_EK_BYTES], dk[MLKEM_DK_BYTES], c[MLKEM_CT_BYTES];
   uint8_t K[32];
   char what[160];
   uint32_t r;

   r = e->keygen(kg_d, kg_z, ek, dk);
   snprintf(what, sizeof what, "%s KeyGen: ek, dk match NIST ACVP", e->name);
   report(what, r == 0 && !memcmp(ek, kg_ek, sizeof ek) && !memcmp(dk, kg_dk, sizeof dk));

   r = e->encaps(en_ek, en_m, K, c);
   snprintf(what, sizeof what, "%s Encaps: ciphertext, shared secret match NIST ACVP", e->name);
   report(what, r == 0 && !memcmp(c, en_c, sizeof c) && !memcmp(K, en_k, 32));

   r = e->decaps(de0_dk, de0_c, K);
   snprintf(what, sizeof what, "%s Decaps (valid ciphertext) matches NIST ACVP", e->name);
   report(what, r == 0 && !memcmp(K, de0_k, 32));

   r = e->decaps(de1_dk, de1_c, K);
   snprintf(what, sizeof what, "%s Decaps (modified ciphertext): implicit-rejection key matches", e->name);
   report(what, r == 0 && !memcmp(K, de1_k, 32));

   r = e->encaps(bad_ek, en_m, K, c);
   snprintf(what, sizeof what, "%s Encaps rejects an ek failing the modulus check", e->name);
   report(what, r == MLKEM_STATUS_BAD_KEY);

   r = e->decaps(bad_dk, de0_c, K);
   snprintf(what, sizeof what, "%s Decaps rejects a dk failing the hash check", e->name);
   report(what, r == MLKEM_STATUS_BAD_KEY);
}

/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */
int main(int argc, char** argv)
{
   static uint8_t ek_h[MLKEM_EK_BYTES], dk_h[MLKEM_DK_BYTES], c_h[MLKEM_CT_BYTES];
   static uint8_t ek_s[MLKEM_EK_BYTES], dk_s[MLKEM_DK_BYTES], c_s[MLKEM_CT_BYTES];
   uint8_t d[32], z[32], m[32], K_h[32], K_s[32], K_d[32], K_x[32];
   uint32_t address = DEFAULT_ADDRESS;
   long rounds = 100, i, same = 0;
   int opt, sw_only = 0;
   double t, hw_ms[3] = {0, 0, 0}, sw_ms[3] = {0, 0, 0};
   double cyc[3] = {0, 0, 0};
   uint32_t id, k;

   while((opt = getopt(argc, argv, "a:n:sh")) != -1)
   {
      switch(opt)
      {
         case 'a': address = (uint32_t)strtoul(optarg, NULL, 0); break;
         case 'n': rounds = strtol(optarg, NULL, 0); break;
         case 's': sw_only = 1; break;
         default:
            fprintf(stderr, "usage: %s [-a address] [-n rounds] [-s]\n", argv[0]);
            return opt == 'h' ? 0 : 2;
      }
   }

   printf("%s, k = %d\n", MLKEM_NAME, MLKEM_K);

   if(sw_only)
   {
      known_answers(&SW);
      for(i = 0; i < rounds; i++)
      {
         random_bytes(d, 32);
         random_bytes(z, 32);
         random_bytes(m, 32);
         t = now_ms();
         sw_keygen(d, z, ek_s, dk_s);
         sw_ms[0] += now_ms() - t;
         t = now_ms();
         sw_encaps(ek_s, m, K_s, c_s);
         sw_ms[1] += now_ms() - t;
         t = now_ms();
         sw_decaps(dk_s, c_s, K_d);
         sw_ms[2] += now_ms() - t;
         c_s[i % MLKEM_CT_BYTES] ^= 1;
         sw_decaps(dk_s, c_s, K_x);
         same += !memcmp(K_s, K_d, 32) && memcmp(K_s, K_x, 32);
      }
      printf("%ld / %ld random round trips agree, tampered ciphertexts rejected\n", same, rounds);
      if(same != rounds)
         errors++;
      if(rounds > 0)
         printf("ARM software, average: KeyGen %.3f ms  Encaps %.3f ms  Decaps %.3f ms\n",
                sw_ms[0] / rounds, sw_ms[1] / rounds, sw_ms[2] / rounds);
      printf("%s\n", errors ? "SOME TESTS FAILED" : "ALL TESTS PASSED");
      return errors ? 1 : 0;
   }

   if(hw_open(address))
      return 2;

   id = reg_read(REG_ID);
   k = reg_read(REG_PARAMS);
   printf("accelerator at 0x%08X: ID 0x%08X, k = %u\n", (unsigned)address, (unsigned)id, (unsigned)k);
   if(id != ID_VALUE || k != MLKEM_K)
   {
      fprintf(stderr, "no ML-KEM accelerator with k = %d at this address (check -a and the FPGA image)\n",
              MLKEM_K);
      return 2;
   }
   reg_write(REG_IRQ_EN, 0); /* this program polls */
   if(reg_read(REG_STATUS) & 1)
   {
      fprintf(stderr, "the accelerator is busy - is another program using it?\n");
      return 2;
   }

   known_answers(&HW);

   for(i = 0; i < rounds; i++)
   {
      int ok = 1;
      random_bytes(d, 32);
      random_bytes(z, 32);
      random_bytes(m, 32);

      t = now_ms();
      ok &= hw_keygen(d, z, ek_h, dk_h) == 0;
      hw_ms[0] += now_ms() - t;
      cyc[0] += last_cycles;
      t = now_ms();
      sw_keygen(d, z, ek_s, dk_s);
      sw_ms[0] += now_ms() - t;
      ok &= !memcmp(ek_h, ek_s, sizeof ek_h) && !memcmp(dk_h, dk_s, sizeof dk_h);

      t = now_ms();
      ok &= hw_encaps(ek_h, m, K_h, c_h) == 0;
      hw_ms[1] += now_ms() - t;
      cyc[1] += last_cycles;
      t = now_ms();
      sw_encaps(ek_s, m, K_s, c_s);
      sw_ms[1] += now_ms() - t;
      ok &= !memcmp(c_h, c_s, sizeof c_h) && !memcmp(K_h, K_s, 32);

      t = now_ms();
      ok &= hw_decaps(dk_h, c_h, K_d) == 0;
      hw_ms[2] += now_ms() - t;
      cyc[2] += last_cycles;
      t = now_ms();
      sw_decaps(dk_s, c_s, K_x);
      sw_ms[2] += now_ms() - t;
      ok &= !memcmp(K_d, K_h, 32) && !memcmp(K_x, K_h, 32);

      /* one flipped ciphertext bit: the FPGA must return the same
         implicit-rejection key as the software, not the real secret */
      c_h[(size_t)(i * 37) % MLKEM_CT_BYTES] ^= 1;
      memcpy(c_s, c_h, sizeof c_s);
      ok &= hw_decaps(dk_h, c_h, K_d) == 0;
      sw_decaps(dk_s, c_s, K_x);
      ok &= !memcmp(K_d, K_x, 32) && memcmp(K_d, K_h, 32);

      same += ok;
      if(!ok)
         fprintf(stderr, "round %ld: FPGA and software differ\n", i);
   }
   printf("%ld / %ld random round trips: FPGA output identical to the ARM software\n", same, rounds);
   if(same != rounds)
      errors++;

   if(rounds > 0)
   {
      static const char* names[3] = {"KeyGen", "Encaps", "Decaps"};
      printf("\naverage over %ld rounds   FPGA core        FPGA + copies   ARM software\n", rounds);
      for(i = 0; i < 3; i++)
         printf("  %-8s %13.0f cyc = %6.3f ms   %8.3f ms   %8.3f ms\n", names[i], cyc[i] / rounds,
                cyc[i] / rounds / CLOCK_HZ * 1e3, hw_ms[i] / rounds, sw_ms[i] / rounds);
   }

   mbox_clear();
   printf("\n%s\n", errors ? "SOME TESTS FAILED" : "ALL TESTS PASSED");
   return errors ? 1 : 0;
}
