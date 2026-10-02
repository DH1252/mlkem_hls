// -----------------------------------------------------------------------------
// tb_pqse_fault.sv - random fault-injection campaign on the secure element
// (make sim-se-fault): how many single-bit faults reach the outside unnoticed.
//
// Every run is a new chip (the persistent store cleared, then a power cycle),
// so runs are independent and the three-strike kill never carries over:
//   +op=decaps (default)  import the NIST dk (de0), masked Decaps of the NIST
//                         ciphertext; expected K = de0_k
//   +op=keygen            masked KeyGen with the injected NIST seeds d, z;
//                         expected ek = kg_ek
// A first run without a fault measures the command's clocks C. Then, per run,
// one bit of one target (a register, or a word of a RAM) is flipped at a
// random clock in [0, C) after the command starts - a single-event upset as a
// laser or a clock / voltage glitch would cause. +n=<runs> (default 200),
// +seed=<n> (default 1). The targets cover the control (program counter and
// its shadow, instruction register, engine state machines, lifecycle), the
// datapath and masked-gadget registers and every RAM (Keccak state, polynomial,
// seed), both shares.
//
// fault_log.txt, one line per run:
//   <run> <target> <bit> <word> <clock> <result> <outcome>
// with outcome "ok" (the output is right), "bad" (KeyGen: a wrong ek), "K=<hex>"
// (Decaps: a different K - scripts/pqse_fault_report.py tells the implicit
// rejection K' = J(z || c), harmless, from any other K, a silent fault) or
// "hang" (no done within 2 C + 20000 clocks). The script summarizes per target.
// -----------------------------------------------------------------------------
`timescale 1ns / 1ps

module tb_pqse_fault;
  localparam int EK = 1184, DK = 2400, CT = 1088;
  localparam int B_EKOWN = 0, B_XIN = 164, B_K = 448, B_INJD = 452, B_INJZ = 456, B_INJH = 464;
  localparam int CTRL = 'h402, STATUS = 'h403, CYCLES = 'h404;
  localparam int KEYGEN = 1, DECAPS = 3, IMPORT = 4;

  logic        clk = 1'b0;
  logic        reset = 1'b1;
  logic [11:0] address = '0;
  logic        read = 1'b0, write = 1'b0;
  logic [31:0] writedata = '0;
  logic [31:0] readdata;
  logic        irq;

  always #10 clk = ~clk;

  pqse_avalon #(.MASKED(1), .PUF_WIN(64), .LC_RESET(2'd0)) dut (
    .clk(clk), .reset(reset), .avs_address(address), .avs_read(read), .avs_write(write),
    .avs_writedata(writedata), .avs_readdata(readdata), .irq(irq), .tamper(1'b0), .trig());

  typedef logic [7:0] bytes_t[DK];
  bytes_t kg_d, kg_z, kg_ek, de_dk, de_c, de_k, buffer;

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
  task automatic wait_idle();
    logic [31:0] st;
    do rd(STATUS, st); while (st[0]);
  endtask

  // ---- fault targets ---------------------------------------------------------------------
  localparam int NT = 37;
  string tname[NT] = '{
    "core.pc", "core.pcn", "core.ins_r", "core.q",
    "keccak.ks", "keccak.rnd_i", "keccak.cx", "keccak.T0", "keccak.T1",
    "keccak.X0r", "keccak.Y0r", "keccak.d00", "keccak.d01", "keccak.C0v", "keccak.C1v",
    "keccak.ram0", "keccak.ram1", "sponge.hs",
    "masked.ok0", "masked.ok1", "masked.okb0", "masked.L0", "masked.acc0", "masked.wr0",
    "mcomp.X0w", "mcomp.A0", "mcomp.C0",
    "poly.wq", "poly.aq", "io.um0",
    "pmem0", "pmem1", "seed0", "seed1",
    "host.lc", "host.fcnt", "nvm.fa"};

`define FLIP(sig) begin k = b % $bits(sig); sig[k] = ~sig[k]; end
`define FLIP1(sig) begin sig = ~sig; end
`define FLIPM(mem, nw) begin k = b % $bits(mem[0]); mem[w % (nw)][k] = ~mem[w % (nw)][k]; end
  task automatic flip(input int unsigned t, input int unsigned b, input int unsigned w);
    int k;
    case (t)
      0:  `FLIP(dut.u_sys.u_core.pc)
      1:  `FLIP(dut.u_sys.u_core.pcn)
      2:  `FLIP(dut.u_sys.u_core.ins_r)
      3:  `FLIP(dut.u_sys.u_core.q)
      4:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.ks)
      5:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.rnd_i)
      6:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.cx)
      7:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.T0)
      8:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.T1)
      9:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.X0r)
      10: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.Y0r)
      11: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.d00)
      12: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.d01)
      13: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.C0v)
      14: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.C1v)
      15: `FLIPM(dut.u_sys.u_core.u_sponge.u_keccak.u_s0.g_def.mem, 64)
      16: `FLIPM(dut.u_sys.u_core.u_sponge.u_keccak.g_s1.u_s1.g_def.mem, 64)
      17: `FLIP(dut.u_sys.u_core.u_sponge.hs)
      18: `FLIP1(dut.u_sys.u_core.u_masked.ok0)
      19: `FLIP1(dut.u_sys.u_core.u_masked.ok1)
      20: `FLIP1(dut.u_sys.u_core.u_masked.okb0)
      21: `FLIP(dut.u_sys.u_core.u_masked.L0)
      22: `FLIP(dut.u_sys.u_core.u_masked.acc0)
      23: `FLIP(dut.u_sys.u_core.u_masked.wr0)
      24: `FLIP(dut.u_sys.u_core.u_masked.u_mc.X0w)
      25: `FLIP(dut.u_sys.u_core.u_masked.u_mc.A0)
      26: `FLIP1(dut.u_sys.u_core.u_masked.u_mc.C0)
      27: `FLIP(dut.u_sys.u_core.u_poly.wq)
      28: `FLIP(dut.u_sys.u_core.u_poly.aq)
      29: `FLIP(dut.u_sys.u_core.u_io.um0)
      30: `FLIPM(dut.u_sys.u_core.u_pmem0.g_def.mem, 1024)
      31: `FLIPM(dut.u_sys.u_core.u_pmem1.g_def.mem, 1024)
      32: `FLIPM(dut.u_sys.u_core.u_seed0.g_mlab.mem, 64)
      33: `FLIPM(dut.u_sys.u_core.u_seed1.g_mlab.mem, 64)
      34: `FLIP(dut.u_sys.u_host.lc)
      35: `FLIP(dut.u_sys.u_host.fcnt)
      36: `FLIP(dut.u_sys.u_host.u_nvm.fa)
      default: ;
    endcase
  endtask

  // new chip + power cycle, then the command's inputs; the caller starts it
  task automatic prepare(input bit kg);
    int res;
    logic [31:0] st;
    dut.u_sys.u_host.u_nvm.fa = '0;            // persistent store blank (simulation only)
    dut.u_sys.u_host.u_nvm.fb = '0;
    dut.u_sys.u_host.u_nvm.pc = '0;
    reset = 1'b1;
    repeat (5) @(negedge clk);
    reset = 1'b0;
    repeat (4) @(negedge clk);
    wait_idle();
    if (kg) begin
      put(B_INJD, kg_d, 0, 32);
      put(B_INJZ, kg_z, 0, 32);
    end else begin
      // dk = s^ (1152) | ek (1184) | H(ek) (32) | z (32)
      put(B_XIN,   de_dk, 0,    1152);
      put(B_EKOWN, de_dk, 1152, EK);
      put(B_INJH,  de_dk, 2336, 32);
      put(B_INJZ,  de_dk, 2368, 32);
      wr(CTRL, IMPORT);
      do rd(STATUS, st); while (!st[1]);
      wr(STATUS, 32'h2);
      if (st[15:8] != 0) begin $display("ERROR: import failed (%0d)", st[15:8]); $finish; end
      put(B_XIN, de_c, 0, CT);
    end
  endtask

  // wait for done (or give up after lim clocks): result, or -1 for a hang
  task automatic finish_to(input int lim, output int res);
    int n = 0;
    while (!irq && n < lim) begin @(posedge clk); n++; end
    if (!irq) begin res = -1; return; end
    begin
      logic [31:0] st;
      rd(STATUS, st);
      wr(STATUS, 32'h2);
      res = st[15:8];
    end
  endtask

  initial begin
    int n, seed, fd, res, cref, nok, ndet, nbad, nhang;
    int unsigned t, b, w, clk_at;
    bit kg;
    string op, oc;
    if (!$value$plusargs("n=%d", n))    n = 200;
    if (!$value$plusargs("seed=%d", seed)) seed = 1;
    if (!$value$plusargs("op=%s", op))  op = "decaps";
    kg = (op == "keygen");
    $readmemh("vectors/kg_d.hex", kg_d, 0, 31);     $readmemh("vectors/kg_z.hex", kg_z, 0, 31);
    $readmemh("vectors/kg_ek.hex", kg_ek, 0, EK-1);
    $readmemh("vectors/de0_dk.hex", de_dk, 0, DK-1); $readmemh("vectors/de0_c.hex", de_c, 0, CT-1);
    $readmemh("vectors/de0_k.hex", de_k, 0, 31);
    void'($urandom(seed));

    // reference run (no fault): the command's length
    prepare(kg);
    wr(CTRL, kg ? (KEYGEN | 32'h100) : DECAPS);
    finish_to(5000000, res);
    begin logic [31:0] cy; rd(CYCLES, cy); cref = cy; end
    if (res != 0) begin $display("ERROR: the reference %s failed (%0d)", op, res); $finish; end
    $display("fault campaign: %s, %0d runs, seed %0d, reference %0d clocks", op, n, seed, cref);

    fd = $fopen("fault_log.txt", "w");
    $fdisplay(fd, "# op %s runs %0d seed %0d clocks %0d", op, n, seed, cref);
    nok = 0; ndet = 0; nbad = 0; nhang = 0;
    for (int i = 0; i < n; i++) begin
      t = $urandom % NT;
      b = $urandom;
      w = $urandom;
      clk_at = $urandom % cref;
      prepare(kg);
      wr(CTRL, kg ? (KEYGEN | 32'h100) : DECAPS);
      repeat (clk_at) @(posedge clk);
      @(negedge clk);
      flip(t, b, w);
      finish_to(2 * cref + 20000, res);
      if (res < 0) begin
        oc = "hang"; nhang++;
      end else if (res != 0) begin
        oc = "-"; ndet++;
      end else if (kg) begin
        int d = 0;
        get(B_EKOWN, EK);
        for (int j = 0; j < EK; j++) if (buffer[j] !== kg_ek[j]) d++;
        oc = (d == 0) ? "ok" : "bad";
        if (d == 0) nok++; else nbad++;
      end else begin
        int d = 0;
        get(B_K, 32);
        for (int j = 0; j < 32; j++) if (buffer[j] !== de_k[j]) d++;
        if (d == 0) begin oc = "ok"; nok++; end
        else begin
          oc = "K=";
          for (int j = 0; j < 32; j++) oc = {oc, $sformatf("%02x", buffer[j])};
          nbad++;
        end
      end
      $fdisplay(fd, "%0d %s %0d %0d %0d %0d %s", i, tname[t], b % 1024, w % 1024, clk_at, res, oc);
      if ((i + 1) % 10 == 0)
        $display("  %0d / %0d runs: %0d unchanged, %0d detected, %0d different output, %0d hangs",
                 i + 1, n, nok, ndet, nbad, nhang);
    end
    $fclose(fd);
    $display("fault campaign done: %0d unchanged, %0d detected (result != 0), %0d different output, %0d hangs",
             nok, ndet, nbad, nhang);
    $display("scripts/pqse_fault_report.py fault_log.txt classifies the different outputs");
    $finish;
  end
endmodule
