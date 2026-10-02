// -----------------------------------------------------------------------------
// tb_mlkem_avalon.sv - testbench for mlkem_avalon (wrapper + Bambu core), or
// for the hand-written core mlkem_rtl (hw/manual), which has the same ports.
//
// Drives the Avalon-MM slave the way the ARM or the JTAG master will: 32-bit
// writes into the mailbox, a write to CTRL, polling STATUS, then 32-bit reads
// of the results, which are compared with NIST ACVP vectors
// (vectors/*.hex, made by scripts/make_tb_vectors.py).
//
// Run with the Makefile, which uses Verilator:
//   make sim-rtl      Bambu core      (DUT mlkem_avalon, the default)
//   make sim-manual   hand-written    (+define+MLKEM_DUT=mlkem_rtl)
//   make sim-v2       hand-written v2 (+define+MLKEM_DUT=mlkem_rtl2)
//   make sim-v3       hand-written v3 (+define+MLKEM_DUT=mlkem_rtl3)
// -----------------------------------------------------------------------------
`timescale 1ns / 1ps

`ifndef MLKEM_DUT
`define MLKEM_DUT mlkem_avalon
`endif

module tb_mlkem_avalon;

  // ML-KEM-768 sizes and the mailbox layout (src/mlkem_accel.h)
  localparam int EK = 1184, DK = 2400, CT = 1088;
  localparam int OFF_D = 'h0000, OFF_Z = 'h0020, OFF_M = 'h0040, OFF_SS = 'h0060;
  localparam int OFF_EK = 'h0100, OFF_DK = 'h0800, OFF_CT = 'h1800;
  localparam int CTRL = 'h2000, STATUS = 'h2004, RESULT = 'h2008, CYCLES = 'h200C;
  localparam int ID = 'h2010, PARAMS = 'h2014, IRQ_EN = 'h2018;

  logic        clk = 1'b0;
  logic        reset = 1'b1;
  logic [11:0] address = '0;
  logic        read = 1'b0, write = 1'b0;
  logic [31:0] writedata = '0;
  logic [3:0]  byteenable = '0;
  logic [31:0] readdata;
  logic        irq;

  always #10 clk = ~clk;  // 50 MHz

  `MLKEM_DUT #(.MLKEM_K(3)) dut (
    .clk           (clk),
    .reset         (reset),
    .avs_address   (address),
    .avs_read      (read),
    .avs_write     (write),
    .avs_writedata (writedata),
    .avs_byteenable(byteenable),
    .avs_readdata  (readdata),
    .irq           (irq)
  );

  // Test vectors. All arrays have the same (largest) size so one task can
  // take any of them; only the first n bytes are used.
  typedef logic [7:0] bytes_t[DK];
  bytes_t kg_d, kg_z, kg_ek, kg_dk;
  bytes_t en_ek, en_m, en_c, en_k;
  bytes_t de0_dk, de0_c, de0_k;
  bytes_t de1_dk, de1_c, de1_k;
  bytes_t buffer;

  int errors = 0;

  // --- Avalon master tasks. Inputs change on the falling edge; read data is
  //     sampled one clock after the read (read latency 1). -----------------
  task automatic avs_wr(input int byte_addr, input logic [31:0] data, input logic [3:0] be = 4'hF);
    @(negedge clk);
    address    = 12'(byte_addr >> 2);
    writedata  = data;
    byteenable = be;
    write      = 1'b1;
    @(negedge clk);
    write      = 1'b0;
  endtask

  task automatic avs_rd(input int byte_addr, output logic [31:0] data);
    @(negedge clk);
    address = 12'(byte_addr >> 2);
    read    = 1'b1;
    @(negedge clk);
    read = 1'b0;
    data = readdata;
  endtask

  // Copy n bytes into / out of the mailbox, 4 bytes per bus transfer
  task automatic put_bytes(input int off, ref bytes_t src, input int n);
    for (int i = 0; i < n; i += 4) begin
      logic [31:0] w = '0;
      logic [3:0]  be = '0;
      for (int b = 0; b < 4 && i + b < n; b++) begin
        w[8*b +: 8] = src[i + b];
        be[b] = 1'b1;
      end
      avs_wr(off + i, w, be);
    end
  endtask

  task automatic get_bytes(input int off, input int n);
    for (int i = 0; i < n; i += 4) begin
      logic [31:0] w;
      avs_rd(off + i, w);
      for (int b = 0; b < 4 && i + b < n; b++) buffer[i + b] = w[8*b +: 8];
    end
  endtask

  function automatic int compare(ref bytes_t expected, input int n);
    int bad = 0;
    for (int i = 0; i < n; i++) if (buffer[i] !== expected[i]) bad++;
    return bad;
  endfunction

  // Start an operation, wait for DONE, return RESULT and CYCLES
  task automatic run_op(input int op, output logic [31:0] result, output logic [31:0] cycles);
    logic [31:0] st;
    avs_wr(CTRL, op);
    do avs_rd(STATUS, st); while (!st[1]);
    avs_rd(RESULT, result);
    avs_rd(CYCLES, cycles);
    avs_wr(STATUS, 32'h2);  // clear DONE
  endtask

  task automatic report(input string what, input int bad);
    if (bad == 0) $display("[PASS] %s", what);
    else begin
      $display("[FAIL] %s (%0d bytes differ)", what, bad);
      errors++;
    end
  endtask

  initial begin
    logic [31:0] r, cyc, st;
    int bad;
    int fd;

    // The vectors are read relative to the simulator's working directory
    // (the Makefile copies hw/sim/vectors there). Stop at once if they are
    // missing: otherwise every comparison runs against zeros.
    fd = $fopen("vectors/kg_d.hex", "r");
    if (fd == 0) begin
      $display("ERROR: vectors/kg_d.hex not found in the working directory.");
      $display("       Copy hw/sim/vectors next to the simulation binary (the Makefile does this).");
      $display("TEST FAILED: no test vectors");
      $finish;
    end
    $fclose(fd);

    $readmemh("vectors/kg_d.hex", kg_d, 0, 31);
    $readmemh("vectors/kg_z.hex", kg_z, 0, 31);
    $readmemh("vectors/kg_ek.hex", kg_ek, 0, EK-1);
    $readmemh("vectors/kg_dk.hex", kg_dk, 0, DK-1);
    $readmemh("vectors/en_ek.hex", en_ek, 0, EK-1);
    $readmemh("vectors/en_m.hex", en_m, 0, 31);
    $readmemh("vectors/en_c.hex", en_c, 0, CT-1);
    $readmemh("vectors/en_k.hex", en_k, 0, 31);
    $readmemh("vectors/de0_dk.hex", de0_dk, 0, DK-1);
    $readmemh("vectors/de0_c.hex", de0_c, 0, CT-1);
    $readmemh("vectors/de0_k.hex", de0_k, 0, 31);
    $readmemh("vectors/de1_dk.hex", de1_dk, 0, DK-1);
    $readmemh("vectors/de1_c.hex", de1_c, 0, CT-1);
    $readmemh("vectors/de1_k.hex", de1_k, 0, 31);

    repeat (5) @(negedge clk);
    reset = 1'b0;
    repeat (2) @(negedge clk);

    // Identification registers
    avs_rd(ID, r);
    avs_rd(PARAMS, st);
    report("ID = 0x4D4C4B4D (\"MLKM\"), PARAMS = 3 (ML-KEM-768)", int'(r != 32'h4D4C4B4D) + int'(st != 3));

    // Mailbox read-back (bus path only, no core involved)
    avs_wr(OFF_SS, 32'hA1B2C3D4);
    avs_wr(OFF_SS + 4, 32'h55667788, 4'b0101);  // byte enables: bytes 0 and 2 only
    avs_rd(OFF_SS, r);
    avs_rd(OFF_SS + 4, st);
    report("mailbox write/read with byte enables", int'(r != 32'hA1B2C3D4) + int'(st[23:16] != 8'h66 || st[7:0] != 8'h88));

    // 1. KeyGen
    put_bytes(OFF_D, kg_d, 32);
    put_bytes(OFF_Z, kg_z, 32);
    run_op(1, r, cyc);
    get_bytes(OFF_EK, EK);
    bad = compare(kg_ek, EK);
    get_bytes(OFF_DK, DK);
    bad += compare(kg_dk, DK);
    report($sformatf("KeyGen: ek, dk match NIST (%0d cycles)", cyc), bad + int'(r != 0));

    // 2. Encaps
    put_bytes(OFF_EK, en_ek, EK);
    put_bytes(OFF_M, en_m, 32);
    run_op(2, r, cyc);
    get_bytes(OFF_CT, CT);
    bad = compare(en_c, CT);
    get_bytes(OFF_SS, 32);
    bad += compare(en_k, 32);
    report($sformatf("Encaps: c, K match NIST (%0d cycles)", cyc), bad + int'(r != 0));

    // 3. Decaps, valid ciphertext
    put_bytes(OFF_DK, de0_dk, DK);
    put_bytes(OFF_CT, de0_c, CT);
    run_op(3, r, cyc);
    get_bytes(OFF_SS, 32);
    report($sformatf("Decaps (valid): K matches NIST (%0d cycles)", cyc), compare(de0_k, 32) + int'(r != 0));

    // 4. Decaps, modified ciphertext -> implicit rejection key, with interrupt
    avs_wr(IRQ_EN, 32'h1);
    put_bytes(OFF_DK, de1_dk, DK);
    put_bytes(OFF_CT, de1_c, CT);
    avs_wr(CTRL, 3);
    avs_wr(CTRL, 1);  // must be ignored: the core is busy
    wait (irq === 1'b1);
    avs_rd(CTRL, st);
    avs_rd(RESULT, r);
    avs_wr(STATUS, 32'h2);
    get_bytes(OFF_SS, 32);
    report("Decaps (modified c): implicit-rejection K matches NIST, IRQ fired, 2nd start ignored",
           compare(de1_k, 32) + int'(r != 0) + int'(st != 3) + int'(irq !== 1'b0));

    // 5. Unknown operation
    run_op(9, r, cyc);
    report("unknown operation returns status 2", int'(r != 2));

    $display("----------------------------------------------------------------");
    if (errors == 0) $display("TEST PASSED");
    else $display("TEST FAILED: %0d error(s)", errors);
    $finish;
  end

  initial begin
    #200ms;
    $display("TIMEOUT");
    $finish;
  end

endmodule
