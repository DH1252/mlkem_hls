// -----------------------------------------------------------------------------
// tb_pqse_fault.sv - random fault-injection campaign on the secure element
// (make sim-se-fault): how many single-bit faults reach the outside unnoticed.
//
// Every run is a new chip: by default a fresh simulation process per run
// (make sim-se-fault: nothing from an earlier run, not even RAM contents or
// unreset registers, carries over), with the persistent store blank and a power
// cycle; FMODE=chain runs them back to back in one process instead:
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
// "hang" (no done within 2 C + 20000 clocks), and r=1 when the PRNG handed out a
// random word twice in that run (masks reused: the masking weakened, invisible in
// the output). Target "none" flips nothing: the null control - every "none" run
// must come out unchanged, else the harness itself is wrong. The script
// summarizes per target.
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
  localparam int NT = 38;                 // the last one, "none", is the null control
  string tname[NT] = '{
    "core.pc", "core.pcn", "core.ins_r", "core.q",
    "keccak.ks", "keccak.rnd_i", "keccak.cx", "keccak.T0", "keccak.T1",
    "keccak.X0r", "keccak.Y0r", "keccak.d00", "keccak.d01", "keccak.C0v", "keccak.C1v",
    "keccak.ram0", "keccak.ram1", "sponge.hs",
    "masked.ok0", "masked.ok1", "masked.okb0", "masked.L0", "masked.acc0", "masked.wr0",
    "mcomp.X0w", "mcomp.A0", "mcomp.C0",
    "poly.wq", "poly.aq", "io.um0",
    "pmem0", "pmem1", "seed0", "seed1",
    "host.lc", "host.fcnt", "nvm.fa", "none"};

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

  // new chip + power cycle, then the command's inputs; the caller starts it.
  // The store is cleared while the reset is held (the host programs nothing in
  // reset; cleared before it, the host could still write the last run's fault
  // count back in the clocks before its reset takes hold)
  task automatic prepare(input bit kg);
    int res;
    logic [31:0] st;
    reset = 1'b1;
    repeat (4) @(negedge clk);
    dut.u_sys.u_host.u_nvm.fa = '0;            // persistent store blank (simulation only)
    dut.u_sys.u_host.u_nvm.fb = '0;
    dut.u_sys.u_host.u_nvm.pc = '0;
    dut.u_sys.u_core.u_prng.reuse = 1'b0;
    repeat (4) @(negedge clk);
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

  // one run: fault t / bit b / word w at clock clk_at of the command; the
  // outcome string, and the counters
  task automatic one_run(input bit kg, input int cref, input int unsigned t, input int unsigned b,
                         input int unsigned w, input int unsigned clk_at,
                         output int res, output string oc);
    prepare(kg);
    wr(CTRL, kg ? (KEYGEN | 32'h100) : DECAPS);
    repeat (clk_at) @(posedge clk);
    @(negedge clk);
    flip(t, b, w);
    finish_to(2 * cref + 20000, res);
    if (res < 0) oc = "hang";
    else if (res != 0) oc = "-";
    else if (kg) begin
      int d = 0;
      get(B_EKOWN, EK);
      for (int j = 0; j < EK; j++) if (buffer[j] !== kg_ek[j]) d++;
      oc = (d == 0) ? "ok" : "bad";
    end else begin
      int d = 0;
      get(B_K, 32);
      for (int j = 0; j < 32; j++) if (buffer[j] !== de_k[j]) d++;
      if (d == 0) oc = "ok";
      else begin
        oc = "K=";
        for (int j = 0; j < 32; j++) oc = {oc, $sformatf("%02x", buffer[j])};
      end
    end
  endtask

  // Modes:
  //   +ref               reference run only: cref.txt (clocks) and the log header
  //   +one=<i> +cref=<n> run i alone (a fresh process = a cold chip: nothing a
  //                      fault left in RAMs or unreset registers carries over),
  //                      its line in run_<i>.txt (make sim-se-fault, default)
  //   (neither)          +n runs in one process, chip state carried from run to
  //                      run across the power cycles (FMODE=chain: shows faults
  //                      whose effect survives a reset and the power-on wipe)
  initial begin
    int n, seed, fd, res, cref, one, nok, ndet, nbad, nhang;
    int unsigned t, b, w, clk_at;
    bit kg;
    string op, oc;
    if (!$value$plusargs("n=%d", n))    n = 200;
    if (!$value$plusargs("seed=%d", seed)) seed = 1;
    if (!$value$plusargs("op=%s", op))  op = "decaps";
    if (!$value$plusargs("one=%d", one)) one = -1;
    kg = (op == "keygen");
    $readmemh("vectors/kg_d.hex", kg_d, 0, 31);     $readmemh("vectors/kg_z.hex", kg_z, 0, 31);
    $readmemh("vectors/kg_ek.hex", kg_ek, 0, EK-1);
    $readmemh("vectors/de0_dk.hex", de_dk, 0, DK-1); $readmemh("vectors/de0_c.hex", de_c, 0, CT-1);
    $readmemh("vectors/de0_k.hex", de_k, 0, 31);

    if (one >= 0) begin
      // ---- one run in a fresh process ----
      if (!$value$plusargs("cref=%d", cref)) begin $display("ERROR: +one needs +cref"); $finish; end
      void'($urandom(seed * 100003 + one));
      t = $urandom % NT; b = $urandom; w = $urandom; clk_at = $urandom % cref;
      one_run(kg, cref, t, b, w, clk_at, res, oc);
      fd = $fopen($sformatf("run_%0d.txt", one), "w");
      $fdisplay(fd, "%0d %s %0d %0d %0d %0d %s r=%0d", one, tname[t], b % 1024, w % 1024, clk_at, res, oc,
                dut.u_sys.u_core.u_prng.reuse);
      $fclose(fd);
      $display("run %0d: %s bit %0d at clock %0d -> result %0d, %s", one, tname[t], b % 1024, clk_at, res,
               (oc.len() > 12) ? "K differs" : oc);
      if (t == NT - 1 && oc != "ok")
        $display("WARNING: run %0d flipped nothing (null control) and still gave %s, result %0d", one, oc, res);
      $finish;
    end

    // ---- reference run (no fault): the command's length, the expected output ----
    void'($urandom(seed));
    prepare(kg);
    wr(CTRL, kg ? (KEYGEN | 32'h100) : DECAPS);
    finish_to(5000000, res);
    begin logic [31:0] cy; rd(CYCLES, cy); cref = cy; end
    if (res != 0) begin $display("ERROR: the reference %s failed (%0d)", op, res); $finish; end
    begin
      int d = 0;
      if (kg) begin get(B_EKOWN, EK); for (int j = 0; j < EK; j++) if (buffer[j] !== kg_ek[j]) d++; end
      else    begin get(B_K, 32);     for (int j = 0; j < 32; j++) if (buffer[j] !== de_k[j]) d++; end
      if (d != 0) begin
        $display("ERROR: the reference %s (no fault) gives a wrong output (%0d bytes differ)", op, d);
        $finish;
      end
    end
    if ($test$plusargs("ref")) begin
      fd = $fopen("cref.txt", "w"); $fdisplay(fd, "%0d", cref); $fclose(fd);
      fd = $fopen("fault_head.txt", "w");
      $fdisplay(fd, "# op %s runs %0d seed %0d clocks %0d mode fresh", op, n, seed, cref);
      $fclose(fd);
      $display("fault campaign: %s, reference %0d clocks (output checked)", op, cref);
      $finish;
    end
    $display("fault campaign (chained: chip state carried across runs): %s, %0d runs, seed %0d, reference %0d clocks",
             op, n, seed, cref);

    fd = $fopen("fault_log.txt", "w");
    $fdisplay(fd, "# op %s runs %0d seed %0d clocks %0d mode chain", op, n, seed, cref);
    nok = 0; ndet = 0; nbad = 0; nhang = 0;
    for (int i = 0; i < n; i++) begin
      t = $urandom % NT; b = $urandom; w = $urandom; clk_at = $urandom % cref;
      one_run(kg, cref, t, b, w, clk_at, res, oc);
      if (oc == "hang") nhang++;
      else if (oc == "-") ndet++;
      else if (oc == "ok") nok++;
      else nbad++;
      $fdisplay(fd, "%0d %s %0d %0d %0d %0d %s r=%0d", i, tname[t], b % 1024, w % 1024, clk_at, res, oc,
                dut.u_sys.u_core.u_prng.reuse);
      if (t == NT - 1 && oc != "ok")
        $display("WARNING: run %0d flipped nothing (null control) and still gave %s, result %0d", i, oc, res);
      if ((i + 1) % 10 == 0)
        $display("  %0d / %0d runs: %0d unchanged, %0d detected, %0d different output, %0d hangs",
                 i + 1, n, nok, ndet, nbad, nhang);
    end
    $fclose(fd);
    $display("fault campaign done: %0d unchanged, %0d detected (result != 0), %0d different output, %0d hangs",
             nok, ndet, nbad, nhang);
    $finish;
  end
endmodule
