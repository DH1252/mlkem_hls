# PQSE RAM shape a10_d25: 1024 words x 25 bits - polynomial RAM: 2 instances (share 0 / share 1), 16 slots x 128 words of two 12-bit coefficients + parity
# (hw/se/pqse_core.v: pqse_ram_1r1w #(.AW(10), .DW(25)))
word_size = 25
num_words = 1024

import os
exec(open(os.path.join(os.path.dirname(__file__), 'pqse_sram_common.py')).read())
