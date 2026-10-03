# PQSE RAM shape a9_d32: 512 words x 32 bits - I/O buffer: 2 instances (low / high 32-bit half of a lane)
# (hw/se/pqse_core.v: pqse_ram_1r1w #(.AW(9), .DW(32)))
word_size = 32
num_words = 512

import os
exec(open(os.path.join(os.path.dirname(__file__), 'pqse_sram_common.py')).read())
