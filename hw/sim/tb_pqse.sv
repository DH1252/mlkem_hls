// -----------------------------------------------------------------------------
// tb_pqse.sv - testbench of the PQSE secure element (hw/se).
//
//   make sim-se            Verilator, NIST ACVP vectors from hw/sim/vectors
//   make sim-se TRACE=1    + every microcode instruction
//
// Drives the Avalon-MM top (pqse_avalon) like the JTAG master would, plus a
// second instance of the chip top (pqse_top) for the SPI and tamper checks.
//   1  ID, version, lifecycle TEST, power-on wipe finished
//   2  KeyGen with injected d, z (fully masked): ek matches NIST
//   3  Encaps with injected m (fully masked): c, K match NIST
//   4  round trip on the KeyGen key: Encaps to its own ek, masked Decaps, same K
//   5  Import a NIST dk + masked Decaps (valid c): K matches NIST, with hiding
//      (shuffled NTT / PWM / Compress / mu / CBD order) on and off
//   6  Import + masked Decaps (modified c): implicit-rejection K matches NIST
//   7  bad ek (modulus check) and bad dk (hash check) are rejected
//   8  PUF (RM(1,5) fuzzy extractor + key check value): enroll, KeyGen + wrap,
//      zeroize, unwrap -> same ek, Decaps works; unwrap after 9.4% of the PUF
//      bits drifted; a very noisy PUF (20% errors per read) needs the
//      majority-vote retry; a wrong check value ends with result 12 after
//      three attempts; a modified blob is rejected
//   9  secure messaging (KMAC256, SP 800-185) with the session key: lengths
//      1..128 (0 and 129 refused), SEAL / OPEN between the initiator (Encaps)
//      and the responder (Decaps); reflected, modified (ciphertext, length,
//      padding) and replayed messages are rejected; messages may arrive out of
//      order inside the 64-message window, an unseen counter more than 63
//      behind is rejected; a rejected forgery does not mark its counter; no
//      session key after ZEROIZE; the sealed messages go to sm_vec.txt for
//      scripts/pqse_sm_check.py
//  10  raw dumps (TEST): PUF response bits (two reads, bit-error rate) and TRNG
//      words -> puf_raw.txt, trng_raw.txt (scripts/pqse_puf_stats.py)
//  11  fault detection: a corrupted program-counter shadow and a corrupted
//      copy of the masked comparison result abort Decaps with R_FAULT, the
//      keys are wiped, the faults are counted; the device still works
//  12  lifecycle USER: import / raw dumps denied, injected seeds ignored, K
//      never readable, SEAL / OPEN with the internal session key
//  13  a double-bit fault in m' (the RAM parity cannot see it) is caught by
//      the second, independent decoding; third fault -> KILLED
//  14  power cycle (lifecycle and fault counter are volatile in this model),
//      then a RAM parity error -> R_FAULT, one fault counted
//  15  SPI (second instance): ID and CONFIG; tamper -> zeroized, KILLED,
//      commands refused
// -----------------------------------------------------------------------------
`timescale 1ns / 1ps

module tb_pqse;
  localparam int EK = 1184, DK = 2400, CT = 1088, HELP = 128, RAWB = 120, BLOB = 112, SM = 192;
  // lane bases (hw/se/pqse_defs.vh) -> word address = 2 * lane
  localparam int B_EKOWN = 0, B_HELP = 148, B_XIN = 164, B_XOUT = 312, B_K = 448,
                 B_INJD = 452, B_INJZ = 456, B_INJM = 460, B_INJH = 464, B_BLOB = 468,
                 B_SM = 484, B_SM_MSG = 488, B_SM_TAG = 504;
  localparam int ID = 'h400, VERSION = 'h401, CTRL = 'h402, STATUS = 'h403, CYCLES = 'h404,
                 LIFECYCLE = 'h405, CONFIG = 'h406;
  localparam int KEYGEN = 1, ENCAPS = 2, DECAPS = 3, IMPORT = 4, ENROLL = 5, KGWRAP = 6,
                 UNWRAP = 7, ZEROIZE = 8, SEAL = 9, OPEN = 10, PUFRAW = 11, TRNGRAW = 12;
  localparam int R_OK = 0, R_BADIN = 1, R_DENIED = 2, R_NOKEY = 3, R_BADBLOB = 4,
                 R_KILLED = 7, R_FAULT = 8, R_BADTAG = 9, R_NOSK = 10, R_REPLAY = 11, R_PUF = 12;
  // microcode addresses used for fault injection (hw/se/pqse_ucode.v, DECAPS at 320)
  localparam logic [9:0] PC_DC_INTT = 10'd366,   // INTT of u_0's share 1 (re-encryption)
                         PC_DC_SEQ  = 10'd341,   // the share-wise compare of the two m' decodings
                         PC_DC_VPWM = 10'd400;   // a PWM in v: after the u comparisons, before OKCHK

  logic        clk = 1'b0;
  logic        reset = 1'b1;
  logic [11:0] address = '0;
  logic        read = 1'b0, write = 1'b0;
  logic [31:0] writedata = '0;
  logic [31:0] readdata;
  logic        irq, tamper = 1'b0;
  wire         trig1;                            // measurement trigger (TEST lifecycle only)

  always #10 clk = ~clk;  // 50 MHz

  pqse_avalon #(.MASKED(1), .PUF_WIN(64), .LC_RESET(2'd0)) dut (
    .clk(clk), .reset(reset), .avs_address(address), .avs_read(read), .avs_write(write),
    .avs_writedata(writedata), .avs_readdata(readdata), .irq(irq), .tamper(tamper), .trig(trig1));

  // measurement trigger pulses (rising edges)
  logic trig_d = 1'b0;
  int   trig_n = 0;
  always @(posedge clk) begin
    trig_d <= trig1;
    if (trig1 && !trig_d) trig_n++;
  end

  // PUF reconstruction attempts (one per PUF instruction started)
  int pf_n = 0;
  always @(posedge clk) if (dut.u_sys.u_core.pf_start) pf_n++;

  // ---- vectors ----
  typedef logic [7:0] bytes_t[DK];
  bytes_t kg_d, kg_z, kg_ek, kg_dk, en_ek, en_m, en_c, en_k;
  bytes_t de0_dk, de0_c, de0_k, de1_dk, de1_c, de1_k, bad_ek, bad_dk;
  bytes_t buffer, ek_a, c_a, k_a, blob, helper, msg, zero, raw_a;
  bytes_t sm_a, sm_b, sm_c, sm_d, sm_e, sm_f, sm_g, sm_x;
  bytes_t msg_a, msg_c, msg_d, msg_e, msg_f;
  int errors = 0;
  int fsm;                      // sm_vec.txt

  // ---- bus ----
  task automatic wr(input int a, input logic [31:0] d);
    @(negedge clk); address = 12'(a); writedata = d; write = 1'b1;
    @(negedge clk); write = 1'b0;
  endtask
  task automatic rd(input int a, output logic [31:0] d);
    @(negedge clk); address = 12'(a); read = 1'b1;
    @(negedge clk); read = 1'b0; d = readdata;
  endtask
  task automatic put(input int lane, ref bytes_t src, input int off, input int n);
    for (int i = 0; i < n; i += 4) begin
      logic [31:0] w = '0;
      for (int b = 0; b < 4 && i + b < n; b++) w[8*b +: 8] = src[off + i + b];
      wr(2 * lane + i / 4, w);
    end
  endtask
  task automatic get(input int lane, input int n);
    for (int i = 0; i < n; i += 4) begin
      logic [31:0] w;
      rd(2 * lane + i / 4, w);
      for (int b = 0; b < 4 && i + b < n; b++) buffer[i + b] = w[8*b +: 8];
    end
  endtask
  task automatic keep(ref bytes_t dst, input int n);
    for (int i = 0; i < n; i++) dst[i] = buffer[i];
  endtask
  function automatic int diff(ref bytes_t a, ref bytes_t b, input int n);
    int bad = 0;
    for (int i = 0; i < n; i++) if (a[i] !== b[i]) bad++;
    return bad;
  endfunction
  function automatic int bitdiff(ref bytes_t a, ref bytes_t b, input int n);
    int bad = 0;
    for (int i = 0; i < n; i++) bad += $countones(a[i] ^ b[i]);
    return bad;
  endfunction
  // a sealed message's header must be {counter (8 bytes LE), length (8 bytes LE), 16 zero bytes}
  function automatic int hdr_bad(ref bytes_t s, input int ctr, input int len);
    int bad = 0;
    for (int i = 0; i < 32; i++)
      bad += int'(s[i] != ((i < 8) ? 8'(ctr >> (8 * i)) : (i < 16) ? 8'(len >> (8 * (i - 8))) : 8'h00));
    return bad;
  endfunction
  function automatic string hexs(ref bytes_t a, input int off, input int n);
    string s = "";
    for (int i = 0; i < n; i++) s = {s, $sformatf("%02x", a[off + i])};
    return s;
  endfunction
  task automatic start(input int c, input bit inj);
    wr(CTRL, {23'd0, inj, 8'(c)});
  endtask
  task automatic finish(output int res, output int cyc);
    logic [31:0] st, cy;
    do rd(STATUS, st); while (!st[1]);
    rd(CYCLES, cy);
    wr(STATUS, 32'h2);
    res = st[15:8];
    cyc = cy;
  endtask
  task automatic run(input int c, input bit inj, output int res, output int cyc);
    start(c, inj);
    finish(res, cyc);
  endtask
  task automatic wait_idle();
    logic [31:0] st;
    do rd(STATUS, st); while (st[0]);
  endtask
  task automatic report(input string what, input int bad);
    if (bad == 0) $display("[PASS] %s", what);
    else begin $display("[FAIL] %s (%0d)", what, bad); errors++; end
  endtask
  // dk = s^ (1152) | ek (1184) | H(ek) (32) | z (32)
  task automatic import_dk(ref bytes_t dk, output int res);
    int cyc;
    put(B_XIN,   dk, 0,    1152);
    put(B_EKOWN, dk, 1152, EK);
    put(B_INJH,  dk, 2336, 32);
    put(B_INJZ,  dk, 2368, 32);
    run(IMPORT, 0, res, cyc);
  endtask
  // a 128-byte test message
  task automatic make_msg(input int seed);
    for (int i = 0; i < 128; i++) msg[i] = 8'((i * 37 + seed * 11 + 5) & 8'hFF);
  endtask
  // SEAL msg with length len (header lane 1); the sealed message (H | C | T) is
  // left in buffer[0 .. 191]
  task automatic seal_n(input int len, output int res, output int cyc);
    put(B_SM_MSG, msg, 0, 128);
    wr(2 * (B_SM + 1), len);
    wr(2 * (B_SM + 1) + 1, 0);
    run(SEAL, 0, res, cyc);
    get(B_SM, SM);
  endtask
  // OPEN a sealed message; the plaintext is left in buffer[0 .. 127]
  task automatic open_sm(ref bytes_t sm, output int res);
    int cyc;
    put(B_SM, sm, 0, SM);
    run(OPEN, 0, res, cyc);
    get(B_SM_MSG, 128);
  endtask
  // one line of sm_vec.txt: dir K H M C T
  task automatic log_sm(input int dir, ref bytes_t sm);
    $fdisplay(fsm, "%0d %s %s %s %s %s", dir, hexs(k_a, 0, 32), hexs(sm, 0, 32), hexs(msg, 0, 128),
              hexs(sm, 32, 128), hexs(sm, 160, 32));
  endtask

  // ---- SPI DUT ----
  logic sck = 1'b0, cs_n = 1'b1, mosi = 1'b0, tamper2 = 1'b0;
  wire  miso, irq2;
  pqse_top #(.MASKED(1), .PUF_WIN(64), .LC_RESET(2'd0)) spi_dut (
    .clk(clk), .rst_n(!reset), .spi_sck(sck), .spi_cs_n(cs_n), .spi_mosi(mosi),
    .spi_miso(miso), .irq(irq2), .tamper(tamper2), .trig());
  task automatic spi_byte(input logic [7:0] o, output logic [7:0] i);
    for (int b = 7; b >= 0; b--) begin
      mosi = o[b];
      repeat (4) @(negedge clk);
      sck = 1'b1; i[b] = miso;
      repeat (4) @(negedge clk);
      sck = 1'b0;
    end
  endtask
  task automatic spi_rd(input int a, output logic [31:0] d);
    logic [7:0] x;
    cs_n = 1'b0; repeat (4) @(negedge clk);
    spi_byte(8'h03, x); spi_byte(8'(a >> 8), x); spi_byte(8'(a), x); spi_byte(8'h00, x);
    for (int k = 0; k < 4; k++) begin spi_byte(8'h00, x); d[8*k +: 8] = x; end
    repeat (4) @(negedge clk); cs_n = 1'b1; repeat (8) @(negedge clk);
  endtask
  task automatic spi_wr(input int a, input logic [31:0] d);
    logic [7:0] x;
    cs_n = 1'b0; repeat (4) @(negedge clk);
    spi_byte(8'h02, x); spi_byte(8'(a >> 8), x); spi_byte(8'(a), x);
    for (int k = 0; k < 4; k++) spi_byte(d[8*k +: 8], x);
    repeat (4) @(negedge clk); cs_n = 1'b1; repeat (8) @(negedge clk);
  endtask

  initial begin
    logic [31:0] r, st, v;
    int res, res2, cyc, bad, fd, nb;
    fd = $fopen("vectors/kg_d.hex", "r");
    if (fd == 0) begin
      $display("ERROR: vectors/kg_d.hex not found (the Makefile copies hw/sim/vectors here)");
      $display("TEST FAILED: no test vectors");
      $finish;
    end
    $fclose(fd);
    $readmemh("vectors/kg_d.hex", kg_d, 0, 31);     $readmemh("vectors/kg_z.hex", kg_z, 0, 31);
    $readmemh("vectors/kg_ek.hex", kg_ek, 0, EK-1); $readmemh("vectors/kg_dk.hex", kg_dk, 0, DK-1);
    $readmemh("vectors/en_ek.hex", en_ek, 0, EK-1); $readmemh("vectors/en_m.hex", en_m, 0, 31);
    $readmemh("vectors/en_c.hex", en_c, 0, CT-1);   $readmemh("vectors/en_k.hex", en_k, 0, 31);
    $readmemh("vectors/de0_dk.hex", de0_dk, 0, DK-1); $readmemh("vectors/de0_c.hex", de0_c, 0, CT-1);
    $readmemh("vectors/de0_k.hex", de0_k, 0, 31);
    $readmemh("vectors/de1_dk.hex", de1_dk, 0, DK-1); $readmemh("vectors/de1_c.hex", de1_c, 0, CT-1);
    $readmemh("vectors/de1_k.hex", de1_k, 0, 31);
    $readmemh("vectors/bad_ek.hex", bad_ek, 0, EK-1); $readmemh("vectors/bad_dk.hex", bad_dk, 0, DK-1);
    for (int i = 0; i < DK; i++) zero[i] = 8'h00;
    fsm = $fopen("sm_vec.txt", "w");

    repeat (5) @(negedge clk);
    reset = 1'b0;
    repeat (4) @(negedge clk);

    // 1 -------------------------------------------------------------------------------
    rd(ID, r); rd(VERSION, v); rd(LIFECYCLE, st);
    bad = int'(r != 32'h50515345) + int'(v != 32'h00040000) + int'(st != 0);
    rd(STATUS, st);
    bad += int'(st[0] != 1'b1);                  // the power-on wipe runs
    wait_idle();
    rd(STATUS, st);
    bad += int'(st[2] != 1'b0) + int'(st[16] != 1'b0) + int'(st[18:17] != 2'd0);
    report("ID, version 4.0, lifecycle TEST, power-on wipe", bad);

    // 2 KeyGen (injected d, z) ---------------------------------------------------------------
    put(B_INJD, kg_d, 0, 32);
    put(B_INJZ, kg_z, 0, 32);
    run(KEYGEN, 1, res, cyc);
    get(B_EKOWN, EK);
    report($sformatf("masked KeyGen: ek matches NIST (%0d cycles)", cyc), diff(buffer, kg_ek, EK) + int'(res != 0));
    keep(ek_a, EK);

    // 3 Encaps (injected m) to the NIST ek ----------------------------------------------------
    put(B_XIN, en_ek, 0, EK);
    put(B_INJM, en_m, 0, 32);
    run(ENCAPS, 1, res, cyc);
    get(B_XOUT, CT); bad = diff(buffer, en_c, CT);
    get(B_K, 32);    bad += diff(buffer, en_k, 32);
    rd(STATUS, st);
    report($sformatf("masked Encaps: c, K match NIST, session key loaded (%0d cycles)", cyc),
           bad + int'(res != 0) + int'(st[16] != 1'b1));

    // 4 round trip on the KeyGen key ---------------------------------------------------------
    put(B_XIN, ek_a, 0, EK);
    put(B_INJM, en_m, 0, 32);
    run(ENCAPS, 1, res, cyc);
    get(B_XOUT, CT); keep(c_a, CT);
    get(B_K, 32);    keep(k_a, 32);
    put(B_XIN, c_a, 0, CT);
    run(DECAPS, 0, res, cyc);
    get(B_K, 32);
    report($sformatf("masked Decaps with the KeyGen key gives the Encaps K (%0d cycles)", cyc),
           diff(buffer, k_a, 32) + int'(res != 0));

    // 5 import NIST dk, decaps valid c --------------------------------------------------------
    import_dk(de0_dk, res);
    report("Import of a NIST dk", int'(res != 0));
    put(B_XIN, de0_c, 0, CT);
    trig_n = 0;
    run(DECAPS, 0, res, cyc);
    get(B_K, 32);
    report($sformatf("masked Decaps (valid c, shuffled): K matches NIST, one trigger pulse (%0d cycles)", cyc),
           diff(buffer, de0_k, 32) + int'(res != 0) + int'(trig_n != 1));
    wr(CONFIG, 0);                               // hiding off: natural order, no dummy clocks
    run(DECAPS, 0, res, cyc);
    get(B_K, 32);
    wr(CONFIG, 1);
    report($sformatf("masked Decaps with hiding off: K matches NIST (%0d cycles)", cyc),
           diff(buffer, de0_k, 32) + int'(res != 0));

    // 6 implicit rejection --------------------------------------------------------------------
    import_dk(de1_dk, res);
    put(B_XIN, de1_c, 0, CT);
    run(DECAPS, 0, res, cyc);
    get(B_K, 32);
    report("masked Decaps (modified c): implicit-rejection K matches NIST",
           diff(buffer, de1_k, 32) + int'(res != 0));

    // 7 input checks -------------------------------------------------------------------------
    put(B_XIN, bad_ek, 0, EK);
    run(ENCAPS, 0, res, cyc);
    report("Encaps rejects an ek with a coefficient >= q (result 1)", int'(res != R_BADIN));
    import_dk(bad_dk, res);
    report("Import rejects a dk whose H(ek) does not match (result 1)", int'(res != R_BADIN));

    // 8 PUF wrap / unwrap ----------------------------------------------------------------------
    run(ENROLL, 0, res, cyc);
    get(B_HELP, HELP); keep(helper, HELP);
    nb = 0;
    for (int i = 120; i < 128; i++) nb += int'(helper[i] != 8'h00);
    report($sformatf("PUF enroll: RM(1,5) helper data + 64-bit key check value (%0d cycles)", cyc),
           int'(res != 0) + int'(nb == 0));
    run(KGWRAP, 0, res, cyc);
    get(B_EKOWN, EK);  keep(ek_a, EK);
    get(B_BLOB, BLOB); keep(blob, BLOB);
    report($sformatf("KeyGen + wrap with the PUF key (%0d cycles)", cyc), int'(res != 0));
    run(ZEROIZE, 0, res, cyc);
    rd(STATUS, st);
    get(B_K, 32);
    report("Zeroize clears the key, the session key and K",
           int'(res != 0) + int'(st[2] != 1'b0) + int'(st[16] != 1'b0) + diff(buffer, zero, 32));
    put(B_BLOB, blob, 0, BLOB);
    put(B_HELP, helper, 0, HELP);
    pf_n = 0;
    run(UNWRAP, 0, res, cyc);
    get(B_EKOWN, EK);
    report($sformatf("Unwrap regenerates the same ek, PUF key right the first time (%0d PUF run(s), %0d cycles)",
                     pf_n, cyc), diff(buffer, ek_a, EK) + int'(res != 0) + int'(pf_n != 1));
    put(B_XIN, ek_a, 0, EK);
    put(B_INJM, en_m, 0, 32);
    run(ENCAPS, 1, res, cyc);
    get(B_XOUT, CT); keep(c_a, CT);
    get(B_K, 32);    keep(k_a, 32);
    put(B_XIN, c_a, 0, CT);
    run(DECAPS, 0, res, cyc);
    get(B_K, 32);
    report("Decaps with the unwrapped key", diff(buffer, k_a, 32) + int'(res != 0));
    // the PUF drifts (temperature / voltage / ageing): 9.4% of the bits flip for good
    dut.u_sys.u_core.u_puf.u_raw.drift = 1'b1;
    run(ZEROIZE, 0, res, cyc);
    pf_n = 0;
    run(UNWRAP, 0, res, cyc);
    get(B_EKOWN, EK);
    report($sformatf("Unwrap after 9.4%% of the PUF bits drifted (error correction, %0d PUF run(s))", pf_n),
           diff(buffer, ek_a, EK) + int'(res != 0));
    dut.u_sys.u_core.u_puf.u_raw.drift = 1'b0;
    // a very noisy device: 20% errors per read; one read per bit no longer decodes
    dut.u_sys.u_core.u_puf.u_raw.noisy = 1'b1;
    run(ZEROIZE, 0, res, cyc);
    pf_n = 0;
    run(UNWRAP, 0, res, cyc);
    get(B_EKOWN, EK);
    report($sformatf("very noisy PUF: check value mismatch, majority-vote retry recovers the key (%0d PUF runs, %0d cycles)",
                     pf_n, cyc), diff(buffer, ek_a, EK) + int'(res != 0) + int'(pf_n < 2));
    dut.u_sys.u_core.u_puf.u_raw.noisy = 1'b0;
    // a wrong check value: all three attempts fail
    for (int i = 0; i < HELP; i++) raw_a[i] = helper[i];
    raw_a[121] = raw_a[121] ^ 8'h10;
    put(B_HELP, raw_a, 0, HELP);
    pf_n = 0;
    run(UNWRAP, 0, res, cyc);
    report($sformatf("Unwrap with a wrong key check value: 1-, 3-, 5-read attempts, then result 12 (%0d PUF runs)", pf_n),
           int'(res != R_PUF) + int'(pf_n != 3));
    put(B_HELP, helper, 0, HELP);
    blob[20] = blob[20] ^ 8'h01;
    put(B_BLOB, blob, 0, BLOB);
    run(UNWRAP, 0, res, cyc);
    report("Unwrap rejects a modified blob (result 4)", int'(res != R_BADBLOB));

    // 9 secure messaging ----------------------------------------------------------------------
    // the device is both sides here: Encaps makes it the initiator, Decaps of
    // the same ciphertext the responder, with the same session key
    import_dk(kg_dk, res);
    put(B_XIN, kg_ek, 0, EK);
    put(B_INJM, en_m, 0, 32);
    run(ENCAPS, 1, res, cyc);                    // initiator, SK = K
    get(B_XOUT, CT); keep(c_a, CT);
    get(B_K, 32);    keep(k_a, 32);
    make_msg(9);
    seal_n(0, res2, cyc);
    seal_n(129, res, cyc);
    report("SEAL refuses a length of 0 or 129 bytes (result 1), no counter used",
           int'(res2 != R_BADIN) + int'(res != R_BADIN));
    make_msg(1);
    seal_n(128, res, cyc);                       // initiator -> responder, counter 0
    keep(sm_a, SM);
    nb = 0;                                      // C must not look like M
    for (int i = 0; i < 128; i++) nb += int'(sm_a[32 + i] == msg[i]);
    log_sm(1, sm_a);
    for (int i = 0; i < 128; i++) msg_a[i] = msg[i];
    report($sformatf("SEAL (initiator): header counter 0, length 128 | ciphertext | KMAC tag (%0d cycles)", cyc),
           int'(res != 0) + int'(nb > 8) + hdr_bad(sm_a, 0, 128));
    make_msg(4);
    seal_n(100, res, cyc);                       // counter 1, 100 bytes
    keep(sm_c, SM);
    log_sm(1, sm_c);
    nb = 0;
    for (int i = 100; i < 128; i++) nb += int'(sm_c[32 + i] != 8'h00);
    for (int i = 0; i < 128; i++) msg_c[i] = (i < 100) ? msg[i] : 8'h00;
    report("SEAL: counter 1, a 100-byte message (ciphertext bytes 100..127 are 0)",
           int'(res != 0) + hdr_bad(sm_c, 1, 100) + nb);
    make_msg(5);
    seal_n(1, res, cyc);                         // counter 2, 1 byte
    keep(sm_d, SM);
    log_sm(1, sm_d);
    for (int i = 0; i < 128; i++) msg_d[i] = (i < 1) ? msg[i] : 8'h00;
    bad = int'(res != 0) + hdr_bad(sm_d, 2, 1);
    make_msg(6);
    seal_n(128, res, cyc);                       // counter 3
    keep(sm_e, SM);
    log_sm(1, sm_e);
    for (int i = 0; i < 128; i++) msg_e[i] = msg[i];
    bad += int'(res != 0) + hdr_bad(sm_e, 3, 128);
    make_msg(7);
    seal_n(128, res, cyc);                       // counter 4 (held back, opened too late below)
    keep(sm_g, SM);
    bad += int'(res != 0) + hdr_bad(sm_g, 4, 128);
    dut.u_sys.u_core.ctr_tx = 64'd70;            // as if 65 more messages had been sent
    make_msg(8);
    seal_n(128, res, cyc);                       // counter 70
    keep(sm_f, SM);
    log_sm(1, sm_f);
    for (int i = 0; i < 128; i++) msg_f[i] = msg[i];
    bad += int'(res != 0) + hdr_bad(sm_f, 70, 128);
    report("SEAL: counters 2, 3, 4 and 70 (1-byte and 128-byte messages)", bad);
    open_sm(sm_a, res);                          // the initiator cannot open its own message
    report("OPEN of a reflected message is rejected (result 9)", int'(res != R_BADTAG));
    put(B_XIN, c_a, 0, CT);
    run(DECAPS, 0, res, cyc);                    // responder, same SK, counters restart
    get(B_K, 32);
    report("Decaps: responder with the same session key", diff(buffer, k_a, 32) + int'(res != 0));
    make_msg(2);
    seal_n(128, res, cyc);                       // responder -> initiator, its own counter 0
    keep(sm_b, SM);
    log_sm(2, sm_b);
    bad = int'(res != 0) + hdr_bad(sm_b, 0, 128);
    open_sm(sm_b, res);
    report("SEAL (responder, counter 0), its own OPEN rejects the reflection (result 9)",
           bad + int'(res != R_BADTAG));
    open_sm(sm_a, res);
    report("OPEN (responder) recovers message 0", diff(buffer, msg_a, 128) + int'(res != 0));
    open_sm(sm_a, res);
    report("OPEN rejects the same message sent again (replay, result 11)", int'(res != R_REPLAY));
    open_sm(sm_e, res);
    report("OPEN: message 3 arrives before 1 and 2 and is accepted",
           diff(buffer, msg_e, 128) + int'(res != 0));
    open_sm(sm_c, res);
    report("OPEN: the late message 1 (inside the window) is accepted: 100 bytes, the rest 0",
           diff(buffer, msg_c, 128) + int'(res != 0));
    open_sm(sm_c, res);
    report("OPEN rejects message 1 a second time (result 11)", int'(res != R_REPLAY));
    for (int i = 0; i < SM; i++) sm_x[i] = sm_d[i];
    sm_x[32] = sm_x[32] ^ 8'h40;                 // a ciphertext bit
    open_sm(sm_x, res);
    bad = int'(res != R_BADTAG) + int'(buffer[0] != sm_x[32]);
    for (int i = 0; i < SM; i++) sm_x[i] = sm_d[i];
    sm_x[8] = 8'd50;                             // another valid length: H is authenticated
    open_sm(sm_x, res);
    bad += int'(res != R_BADTAG);
    sm_x[8] = 8'd200;                            // an impossible length
    open_sm(sm_x, res);
    bad += int'(res != R_BADTAG);
    sm_x[8] = 8'd1;
    sm_x[32 + 7] = sm_x[32 + 7] ^ 8'h01;         // a byte after the message (must stay 0)
    open_sm(sm_x, res);
    bad += int'(res != R_BADTAG);
    report("OPEN rejects a modified ciphertext, length or padding byte (result 9), left encrypted", bad);
    open_sm(sm_d, res);
    report("the forgeries did not mark counter 2: message 2 (1 byte) still opens",
           diff(buffer, msg_d, 128) + int'(res != 0));
    open_sm(sm_f, res);
    report("OPEN: counter 70 accepted, the window moves on", diff(buffer, msg_f, 128) + int'(res != 0));
    open_sm(sm_g, res);
    report("OPEN rejects counter 4: never seen, but more than 63 behind 70 (result 11)",
           int'(res != R_REPLAY));
    $fclose(fsm);
    run(ZEROIZE, 0, res, cyc);
    open_sm(sm_a, res2);
    rd(STATUS, st);
    report("no session key after ZEROIZE: SEAL / OPEN refused (result 10)",
           int'(res2 != R_NOSK) + int'(st[16] != 1'b0));

    // 10 raw dumps (TEST only) ---------------------------------------------------------------
    fd = $fopen("puf_raw.txt", "w");
    run(PUFRAW, 0, res, cyc);
    get(B_XOUT, RAWB); keep(raw_a, RAWB);
    $fdisplay(fd, "%s", hexs(raw_a, 0, RAWB));
    bad = int'(res != 0);
    run(PUFRAW, 0, res, cyc);
    get(B_XOUT, RAWB);
    $fdisplay(fd, "%s", hexs(buffer, 0, RAWB));
    $fclose(fd);
    nb = bitdiff(buffer, raw_a, RAWB);
    report($sformatf("PUFRAW: 960 bits twice, %0d bits differ (%0.1f%%) (%0d cycles)", nb,
                     100.0 * nb / 960.0, cyc), bad + int'(res != 0) + int'(nb > 96));
    run(TRNGRAW, 0, res, cyc);
    get(B_XOUT, CT);
    fd = $fopen("trng_raw.txt", "w");
    $fdisplay(fd, "%s", hexs(buffer, 0, CT));
    $fclose(fd);
    nb = bitdiff(buffer, zero, CT);
    report($sformatf("TRNGRAW: 8704 bits, %0d ones (%0d cycles)", nb, cyc),
           int'(res != 0) + int'(nb < 3900) + int'(nb > 4800));

    // 11 fault detection -----------------------------------------------------------------------
    import_dk(de0_dk, res);
    put(B_XIN, de0_c, 0, CT);
    start(DECAPS, 0);
    wait (dut.u_sys.u_core.pc == PC_DC_INTT);
    @(negedge clk);
    dut.u_sys.u_core.pcn = 10'd0;                // glitch: pc and its complement disagree
    finish(res, cyc);
    rd(STATUS, st);
    get(B_K, 32);
    report("fault: corrupted pc shadow -> R_FAULT, keys wiped, 1 fault counted",
           int'(res != R_FAULT) + int'(st[2] != 1'b0) + int'(st[18:17] != 2'd1) +
           int'(st[7:6] != 2'd0) + diff(buffer, zero, 32));
    import_dk(de0_dk, res);
    put(B_XIN, de0_c, 0, CT);
    start(DECAPS, 0);
    wait (dut.u_sys.u_core.pc == PC_DC_VPWM);
    @(negedge clk);
    dut.u_sys.u_core.u_masked.okb0 = ~dut.u_sys.u_core.u_masked.okb0; // one ok copy hit
    finish(res, cyc);
    rd(STATUS, st);
    report("fault: corrupted comparison result -> R_FAULT, 2 faults counted",
           int'(res != R_FAULT) + int'(st[2] != 1'b0) + int'(st[18:17] != 2'd2));
    import_dk(de0_dk, res);
    put(B_XIN, de0_c, 0, CT);
    run(DECAPS, 0, res, cyc);
    get(B_K, 32);
    report("after the faults the device still works", diff(buffer, de0_k, 32) + int'(res != 0));

    // 12 lifecycle USER ------------------------------------------------------------------------
    wr(LIFECYCLE, 1); wr(LIFECYCLE, 2); rd(LIFECYCLE, st);
    import_dk(de0_dk, res);
    run(PUFRAW, 0, res2, cyc);
    report("USER: lifecycle 2, Import and PUFRAW denied (result 2)",
           int'(st != 2) + int'(res != R_DENIED) + int'(res2 != R_DENIED));
    put(B_INJD, kg_d, 0, 32);
    put(B_INJZ, kg_z, 0, 32);
    run(KEYGEN, 1, res, cyc);
    get(B_EKOWN, EK); keep(ek_a, EK);
    report("USER: injected seeds are ignored (ek differs from the KAT)",
           int'(diff(buffer, kg_ek, EK) == 0) + int'(res != 0));
    put(B_XIN, ek_a, 0, EK);
    run(ENCAPS, 0, res, cyc);
    get(B_XOUT, CT); keep(c_a, CT);
    get(B_K, 32);
    bad = int'(res != 0) + diff(buffer, zero, 32);
    make_msg(3);
    seal_n(128, res, cyc);
    keep(sm_a, SM);
    put(B_XIN, c_a, 0, CT);
    trig_n = 0;
    run(DECAPS, 0, res2, cyc);
    get(B_K, 32);
    bad += int'(res != 0) + int'(res2 != 0) + diff(buffer, zero, 32);
    open_sm(sm_a, res);
    report("USER: K never leaves the chip, SEAL / OPEN with the internal session key, no trigger",
           bad + diff(buffer, msg, 128) + int'(res != 0) + int'(trig_n != 0));
    wr(LIFECYCLE, 0); rd(LIFECYCLE, st);
    report("lifecycle cannot go back", int'(st != 2));

    // 13 third fault -> KILLED: a fault in the first decoding of m' ---------------------------
    // two bits of share 0 of m' (seed entry E_MP = 3, lane 0 = word 12) flip after the first
    // decoding: the RAM parity cannot see a double-bit error, the second decoding can
    put(B_XIN, c_a, 0, CT);
    start(DECAPS, 0);
    wait (dut.u_sys.u_core.pc == PC_DC_SEQ);
    @(negedge clk);
    dut.u_sys.u_core.u_seed0.g_mlab.mem[12] = dut.u_sys.u_core.u_seed0.g_mlab.mem[12] ^ 65'h3;
    finish(res, cyc);
    rd(STATUS, st);
    run(KEYGEN, 0, res2, cyc);
    report("fault: m' corrupted (2 bits, parity-blind) -> the duplicate decoding disagrees, R_FAULT; third fault -> KILLED",
           int'(res != R_FAULT) + int'(st[7:6] != 2'd3) + int'(st[18:17] != 2'd3) +
           int'(st[2] != 1'b0) + int'(res2 != R_KILLED));

    // 14 power cycle, RAM parity ----------------------------------------------------------------
    // (the lifecycle and fault counter are volatile in this model; a chip keeps them in fuses)
    reset = 1'b1;
    repeat (5) @(negedge clk);
    reset = 1'b0;
    repeat (4) @(negedge clk);
    wait_idle();
    rd(LIFECYCLE, st);
    bad = int'(st != 0);
    import_dk(de0_dk, res);
    bad += int'(res != 0);
    // flip one bit of share 0 of s^_0 (RAM 0, slot 0, word 3): parity error on the next read
    dut.u_sys.u_core.u_pmem0.g_def.mem[3] = dut.u_sys.u_core.u_pmem0.g_def.mem[3] ^ 25'd1;
    put(B_XIN, de0_c, 0, CT);
    run(DECAPS, 0, res, cyc);
    rd(STATUS, st);
    report("after a power cycle: RAM parity error -> R_FAULT, keys wiped, 1 fault counted",
           bad + int'(res != R_FAULT) + int'(st[2] != 1'b0) + int'(st[18:17] != 2'd1) +
           int'(st[7:6] != 2'd0));

    // 15 SPI + tamper (second instance) ----------------------------------------------------------
    // consecutive reads of different registers and a write/read of both CONFIG
    // values: a read that returned the previous address's register would fail
    spi_rd(ID, r);
    spi_rd(VERSION, v);
    bad = int'(r != 32'h50515345) + int'(v != 32'h00040000);
    spi_wr(CONFIG, 32'h0);
    spi_rd(CONFIG, st);
    bad += int'(st != 0);
    spi_wr(CONFIG, 32'h1);
    spi_rd(ID, r);
    spi_rd(CONFIG, st);
    bad += int'(r != 32'h50515345) + int'(st != 1);
    spi_wr(CONFIG, 32'h0);
    report("SPI: ID / VERSION reads, CONFIG write/read (0 and 1)", bad);
    do spi_rd(STATUS, st); while (st[0]);
    tamper2 = 1'b1;
    repeat (10) @(negedge clk);
    tamper2 = 1'b0;
    do spi_rd(STATUS, st); while (st[0]);
    spi_rd(LIFECYCLE, r);
    spi_wr(CTRL, 32'd3);                         // DECAPS
    do spi_rd(STATUS, v); while (!v[1]);
    report("tamper (SPI device): zeroized, KILLED, commands refused (result 7)",
           int'(st[5] != 1'b1) + int'(st[2] != 1'b0) + int'(r != 3) + int'(v[15:8] != R_KILLED));

    $display("----------------------------------------------------------------");
    if (errors == 0) $display("TEST PASSED");
    else $display("TEST FAILED: %0d error(s)", errors);
    $finish;
  end

  initial begin
    #20s;                     // v5: the serial Keccak takes ~5x the clocks
    $display("TIMEOUT");
    $finish;
  end
endmodule
