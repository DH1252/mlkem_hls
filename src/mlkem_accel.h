/*
 * mlkem_accel.h - the hardware interface of the ML-KEM accelerator.
 *
 * The accelerator is one C function, mlkem_accel(), that Bambu turns into a
 * Verilog module. It works on a shared 8 KB memory (the "mailbox"): software
 * writes the inputs at the offsets below, starts an operation, waits, and
 * reads the outputs from the same memory.
 *
 * The same offsets are used by the RTL wrapper, the System Console script
 * and the ARM (HPS) driver, so this header is the single source of truth.
 * The layout leaves room for ML-KEM-1024, so it does not change with MLKEM_K.
 */
#ifndef MLKEM_ACCEL_H
#define MLKEM_ACCEL_H

#include <stdint.h>

#include "mlkem_params.h"

/* Operations (argument "op") */
#define MLKEM_OP_KEYGEN 1u /* (d, z)  -> (ek, dk)                        */
#define MLKEM_OP_ENCAPS 2u /* (ek, m) -> (K, c)   after the ek check     */
#define MLKEM_OP_DECAPS 3u /* (dk, c) -> K        after the dk check     */

/* Return values */
#define MLKEM_STATUS_OK 0u
#define MLKEM_STATUS_BAD_KEY 1u /* ek failed the modulus check / dk failed the hash check */
#define MLKEM_STATUS_BAD_OP 2u  /* unknown operation code */

/* Mailbox layout, byte offsets */
#define MLKEM_MEM_BYTES 0x2000u
#define MLKEM_OFF_D 0x0000u  /* 32 B  KeyGen seed d                  (in)  */
#define MLKEM_OFF_Z 0x0020u  /* 32 B  KeyGen seed z                  (in)  */
#define MLKEM_OFF_M 0x0040u  /* 32 B  Encaps randomness m            (in)  */
#define MLKEM_OFF_SS 0x0060u /* 32 B  shared secret K                (out) */
#define MLKEM_OFF_EK 0x0100u /* encapsulation key, up to 1568 B   (in/out) */
#define MLKEM_OFF_DK 0x0800u /* decapsulation key, up to 3168 B   (in/out) */
#define MLKEM_OFF_CT 0x1800u /* ciphertext, up to 1568 B          (in/out) */

uint32_t mlkem_accel(uint32_t op, uint8_t mem[MLKEM_MEM_BYTES]);

#endif
