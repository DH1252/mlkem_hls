/*
 * mlkem_accel.c - top-level function for high-level synthesis with Bambu.
 *
 * Bambu turns this function into the Verilog module "mlkem_accel" with:
 *   clock, reset, start_port -> done_port     a simple start/done handshake
 *   op[31:0]                                  the operation code
 *   return_port[31:0]                         the status
 *   mem_address0/1, mem_ce0/1, mem_we0/1,     two ports to the 8 KB mailbox
 *   mem_d0/1, mem_q0/1                        (a dual-port block RAM)
 *
 * The inputs are first copied from the mailbox into internal buffers and the
 * outputs copied back at the end. That keeps the interface a plain RAM port
 * and lets the rest of the code be ordinary C that also runs on a CPU.
 *
 * Bambu compiles this file through hls/mlkem_hls.c, which puts all the
 * sources into one translation unit so that everything above the datapath
 * leaves is inlined here (see hls.h): the result is one controller and one
 * instance of each leaf (Keccak, NTT, ...), instead of one copy per call
 * path.
 */
#include "mlkem_accel.h"

#include "mlkem.h"

MLKEM_LOCAL void load(uint8_t* dst, const uint8_t* mem, uint32_t off, uint32_t n)
{
   uint32_t i;
   for(i = 0; i < n; i++)
      dst[i] = mem[off + i];
}

MLKEM_LOCAL void store(uint8_t* mem, uint32_t off, const uint8_t* src, uint32_t n)
{
   uint32_t i;
   for(i = 0; i < n; i++)
      mem[off + i] = src[i];
}

uint32_t mlkem_accel(uint32_t op, uint8_t mem[MLKEM_MEM_BYTES])
{
#pragma HLS interface port=mem mode=array elem_count=8192
   uint8_t seed_d[32], seed_z[32], msg[32], ss[32];
   uint8_t ek[MLKEM_EK_BYTES];
   uint8_t dk[MLKEM_DK_BYTES];
   uint8_t ct[MLKEM_CT_BYTES];
   uint32_t i;

   if(op == MLKEM_OP_KEYGEN)
   {
      load(seed_d, mem, MLKEM_OFF_D, 32);
      load(seed_z, mem, MLKEM_OFF_Z, 32);
      mlkem_keygen_internal(seed_d, seed_z, ek, dk);
      store(mem, MLKEM_OFF_EK, ek, MLKEM_EK_BYTES);
      store(mem, MLKEM_OFF_DK, dk, MLKEM_DK_BYTES);
      return MLKEM_STATUS_OK;
   }

   if(op == MLKEM_OP_ENCAPS)
   {
      load(ek, mem, MLKEM_OFF_EK, MLKEM_EK_BYTES);
      if(!mlkem_check_ek(ek))
         return MLKEM_STATUS_BAD_KEY;
      load(msg, mem, MLKEM_OFF_M, 32);
      mlkem_encaps_internal(ek, msg, ss, ct);
      store(mem, MLKEM_OFF_SS, ss, 32);
      store(mem, MLKEM_OFF_CT, ct, MLKEM_CT_BYTES);
      return MLKEM_STATUS_OK;
   }

   if(op == MLKEM_OP_DECAPS)
   {
      load(dk, mem, MLKEM_OFF_DK, MLKEM_DK_BYTES);
      if(!mlkem_check_dk(dk))
      {
         for(i = 0; i < 32; i++)
            mem[MLKEM_OFF_SS + i] = 0; /* no stale secret left behind */
         return MLKEM_STATUS_BAD_KEY;
      }
      load(ct, mem, MLKEM_OFF_CT, MLKEM_CT_BYTES);
      mlkem_decaps_internal(dk, ct, ss);
      store(mem, MLKEM_OFF_SS, ss, 32);
      return MLKEM_STATUS_OK;
   }

   return MLKEM_STATUS_BAD_OP;
}
