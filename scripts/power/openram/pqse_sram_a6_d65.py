# PQSE RAM shape a6_d65: 64 words x 65 bits - Keccak state and seed RAMs: 4 instances (2 x Keccak state, 2 x seed registers), 64-bit lane + parity
# (hw/se/pqse_core.v: pqse_ram_1r1w #(.AW(6), .DW(65)))
word_size = 65
num_words = 64

import os
exec(open(os.path.join(os.path.dirname(__file__), 'pqse_sram_common.py')).read())
