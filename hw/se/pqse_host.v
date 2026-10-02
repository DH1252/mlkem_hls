// -----------------------------------------------------------------------------
// pqse_host.v - host interface, lifecycle, access control and fault response
// of the PQSE secure element. A plain 32-bit register bus (word addresses, read
// latency 1) that the SPI slave (pqse_spi.v, chip pins) or the Avalon-MM
// wrapper (pqse_avalon, FPGA demo) drives.
//
// Word address map
//   0x000 - 0x3FF   I/O buffer (4 KB), word w = half (w & 1) of lane (w >> 1)
//   0x400 ID        "PQSE" = 0x50515345                        RO
//   0x401 VERSION   0x00040000                                  RO
//   0x402 CTRL      [7:0] command, [8] use injected seeds (TEST) WO, starts the command
//   0x403 STATUS    [0] busy [1] done (write 1 to clear) [2] key loaded
//                   [3] TRNG ok [4] TRNG failed [5] tampered [7:6] lifecycle
//                   [15:8] result [16] session key loaded [18:17] faults detected
//   0x404 CYCLES    clocks of the last command                  RO
//   0x405 LIFECYCLE write a later state to move forward (TEST 0 -> PERSO 1 ->
//                   USER 2 -> KILLED 3); KILLED wipes every key
//   0x406 CONFIG    [0] hiding on (shuffling + dummy clocks), default 1   RW
//
// Buffer windows the host may use (everything else reads 0, writes are
// ignored; nothing at all while a command runs):
//   read : own ek, PUF helper (16 lanes: helper data + key check value),
//          ciphertext / raw dumps out, wrapped-key blob,
//          secure message; the shared secret K only in TEST / PERSO
//   write: peer ek / ciphertext in, helper, blob, secure message; in TEST/PERSO
//          also own ek, injected z and H(ek) (key import); in TEST only
//          injected d and m
// Commands
//   IMPORT, ENROLL       TEST / PERSO only
//   PUFRAW, TRNGRAW      TEST only (raw dumps for the entropy assessment)
//   all others           any state but KILLED
// Shared secret policy (kexp to the core): in TEST / PERSO, Encaps and Decaps
// also copy K to the buffer (known-answer tests, personalization); in USER K
// never leaves the chip - it stays inside, masked, as the session key that
// SEAL / OPEN use.
//
// Internal ZEROIZE (busy while it runs, host access blocked):
//   - after reset (power-on): RAM contents from before the reset are wiped
//   - after a detected fault (core result R_FAULT): the engines are reset, the
//     keys wiped, the fault counted, and the command reports R_FAULT; the third
//     fault moves the lifecycle to KILLED
//   - tamper input or LIFECYCLE := KILLED: abort, KILLED, wipe (result R_KILLED)
//   - the security state (lifecycle, fault counter, tampered flag) is held
//     twice, the second copy complemented and written in the same statements;
//     a mismatch (a bit flipped by a laser, a glitch or an upset) is handled
//     like the tamper input, and also sets tampered and saturates the counter
//
// Persistent security state (pqse_nvm, below): the lifecycle, the fault counter
// and the tampered flag survive a reset / power cycle. At reset the registers
// load from it (lifecycle = the later of LC_RESET and the stored one); every
// change is mirrored into it, and after a fault, a kill or a tamper event no
// command is accepted until the new state is programmed (write-ahead: cutting
// the power after a detected fault does not reset the three-strike counter).
// Stored ahead of the registers (they were forced back: a fault, a rolled-back
// register) is handled like the tamper input.
// -----------------------------------------------------------------------------
module pqse_host #(
  parameter [1:0] LC_RESET = 2'd0
) (
  input  wire        clk,
  input  wire        rst,
  // register bus
  input  wire        bus_we,
  input  wire        bus_re,
  input  wire [11:0] bus_addr,
  input  wire [31:0] bus_wdata,
  output reg  [31:0] bus_rdata,
  output wire        irq,
  input  wire        tamper,         // asynchronous, active high
  // core
  output reg         core_rst,
  output reg         cmd_start,
  output reg  [7:0]  cmd,
  output reg         cmd_inj,
  output wire        kexp,
  output reg         hide_en,
  output wire        lc_is_test,     // lifecycle TEST (gates the measurement trigger)
  input  wire        core_busy,
  input  wire        core_done,
  input  wire [7:0]  core_result,
  input  wire        key_valid,
  input  wire        sk_valid,
  input  wire        trng_ok,
  input  wire        trng_fail,
  input  wire [31:0] cycles,
  output wire        h_we,
  output wire        h_re,
  output wire [9:0]  h_addr,
  output wire [31:0] h_wdata,
  input  wire [31:0] h_rdata
);
  `include "pqse_defs.vh"

  localparam [1:0] Z_POR = 2'd0, Z_FAULT = 2'd1, Z_KILL = 2'd2;

  reg  [1:0] lc;
  reg        done_s;
  reg  [7:0] res;
  reg        tampered;
  reg  [2:0] tsync;
  reg        rd_buf, rd_ok;
  reg [31:0] csr_q;
  reg  [1:0] fcnt;           // faults detected (saturates at 3)
  // fault protection of the security state: complemented shadow copies, written
  // in the same statements; a mismatch (a flipped bit in either copy: laser,
  // glitch, upset) is handled like the tamper input - KILLED and wiped
  reg  [1:0] lcn, fcntn;
  reg        tampn;
  wire       sh_bad = (lc != ~lcn) | (fcnt != ~fcntn) | (tampered != ~tampn);
  reg        zpend;          // start an internal ZEROIZE once the core is idle
  reg        zrun;           // internal ZEROIZE running
  reg  [1:0] zkind;          // why: power-on, fault, tamper / kill

  // ---- persistent security state ----
  // bits: [0] PERSO reached [1] USER reached [2] KILLED [3..5] 1st..3rd fault
  // [6] tampered; thermometer codes (only ever set, like OTP fuses), stored
  // twice and OR-combined (reading a programmed bit as 0 takes two faults)
  wire [6:0] nv_q;
  wire       nv_busy;
  wire [1:0] lc_nv = nv_q[2] ? 2'd3 : nv_q[1] ? 2'd2 : nv_q[0] ? 2'd1 : 2'd0;
  wire [1:0] fc_nv = nv_q[5] ? 2'd3 : nv_q[4] ? 2'd2 : nv_q[3] ? 2'd1 : 2'd0;
  wire       tp_nv = nv_q[6];
  wire [1:0] lc_rs = (lc_nv > LC_RESET) ? lc_nv : LC_RESET;     // lifecycle at reset
  wire [6:0] nv_want = {tampered, fcnt == 2'd3, fcnt >= 2'd2, fcnt >= 2'd1,
                        lc == LC_KILLED, lc >= LC_USER, lc >= LC_PERSO};
  wire [6:0] nv_miss = nv_want & ~nv_q;                         // to be programmed
  // fault / kill / tamper bits must be stored before the next command (a
  // lifecycle advance is programmed in the background: it only lowers rights)
  wire       nv_crit = |nv_miss[6:2];
  // stored state ahead of the registers: they were forced back
  wire       nv_bad  = (lc_nv > lc) | (fc_nv > fcnt) | (tp_nv & !tampered);
  pqse_nvm #(.NB(7)) u_nvm (
    .clk(clk), .prog(!rst && (|nv_miss) && !nv_busy), .pmask(nv_want),
    .busy(nv_busy), .q(nv_q));

  assign irq = done_s;

  // ---- buffer windows (lane = word >> 1) ----
  wire [8:0] ln = bus_addr[9:1];
  function in_win(input [8:0] l, input [8:0] base, input [8:0] n);
    in_win = (l >= base) && ({1'b0, l} < {1'b0, base} + {1'b0, n});
  endfunction
  wire test  = (lc == LC_TEST);
  wire perso = (lc == LC_TEST) || (lc == LC_PERSO);
  assign kexp    = perso;
  assign lc_is_test = test;
  // helper window: 15 lanes of helper data + the 64-bit key check value (lane 15)
  wire can_rd = in_win(ln, B_EKOWN, 9'd148) || in_win(ln, B_HELP, 9'd16) ||
                in_win(ln, B_XOUT, 9'd136)  || in_win(ln, B_BLOB, 9'd14) ||
                in_win(ln, B_SM, 9'd24)     || (perso && in_win(ln, B_K, 9'd4));
  wire can_wr = in_win(ln, B_XIN, 9'd148)   || in_win(ln, B_HELP, 9'd16) ||
                in_win(ln, B_BLOB, 9'd14)   || in_win(ln, B_SM, 9'd24) ||
                (perso && (in_win(ln, B_EKOWN, 9'd148) || in_win(ln, B_INJZ, 9'd4) ||
                           in_win(ln, B_INJH, 9'd4))) ||
                (test  && (in_win(ln, B_INJD, 9'd4) || in_win(ln, B_INJM, 9'd4)));
  wire is_buf = !bus_addr[10] && !bus_addr[11];
  wire idle   = !core_busy && !cmd_start && !zpend && !zrun && !nv_crit;

  assign h_we    = bus_we && is_buf && can_wr && idle && (lc != LC_KILLED);
  assign h_re    = bus_re && is_buf && can_rd && idle;
  assign h_addr  = bus_addr[9:0];
  assign h_wdata = bus_wdata;

  // ---- command policy ----
  wire [7:0] wcmd    = bus_wdata[7:0];
  wire       known   = (wcmd >= CMD_KEYGEN) && (wcmd <= CMD_LAST);
  wire       allowed = (lc != LC_KILLED) &&
                       (((wcmd != CMD_IMPORT) && (wcmd != CMD_ENROLL)) || perso) &&
                       (((wcmd != CMD_PUFRAW) && (wcmd != CMD_TRNGRAW)) || test);
  wire       ctrl_wr = bus_we && (bus_addr == 12'h402);
  wire       kill_wr = bus_we && (bus_addr == 12'h405) && (bus_wdata[1:0] == LC_KILLED) &&
                       (lc != LC_KILLED);
  wire       fault_done = core_done && !zrun && (core_result == R_FAULT);

  always @(posedge clk) begin
    if (rst) begin
      begin lc        <= lc_rs; lcn <= ~(lc_rs); end
      done_s    <= 1'b0;
      res       <= 8'd0;
      begin tampered  <= tp_nv; tampn <= ~(tp_nv); end
      tsync     <= 3'd0;
      cmd_start <= 1'b0;
      core_rst  <= 1'b1;
      hide_en   <= 1'b1;
      cmd       <= 8'd0;
      cmd_inj   <= 1'b0;
      begin fcnt      <= fc_nv; fcntn <= ~(fc_nv); end
      zpend     <= 1'b1;            // power-on wipe
      zrun      <= 1'b0;
      zkind     <= Z_POR;
    end else begin
      cmd_start <= 1'b0;
      core_rst  <= 1'b0;
      tsync     <= {tsync[1:0], tamper};
      // ---- CSR writes (before the events below, which take precedence) ----
      if (bus_we && bus_addr == 12'h403 && bus_wdata[1]) done_s <= 1'b0;
      if (bus_we && bus_addr == 12'h405 && bus_wdata[1:0] > lc && bus_wdata[1:0] != LC_KILLED && idle)
        begin lc <= bus_wdata[1:0]; lcn <= ~(bus_wdata[1:0]); end
      if (bus_we && bus_addr == 12'h406) hide_en <= bus_wdata[0];
      // ---- events ----
      if ((tsync[2] && !tampered) || kill_wr || sh_bad || nv_bad) begin
        // tamper / kill / corrupted security state: abort whatever runs, KILLED,
        // then wipe (a corrupted state also counts as tampered, faults saturated:
        // both copies are rewritten consistently, so this fires once)
        if (sh_bad || nv_bad) begin
          begin tampered <= 1'b1; tampn <= ~(1'b1); end
          begin fcnt <= 2'd3; fcntn <= ~(2'd3); end
        end
        if (tsync[2]) begin tampered <= 1'b1; tampn <= ~(1'b1); end
        begin lc       <= LC_KILLED; lcn <= ~(LC_KILLED); end
        zpend    <= 1'b1;
        zrun     <= 1'b0;
        zkind    <= Z_KILL;
        core_rst <= 1'b1;
      end else if (fault_done) begin
        // a fault was detected: reset the engines, count, wipe
        begin fcnt     <= (fcnt == 2'd3) ? 2'd3 : fcnt + 2'd1; fcntn <= ~((fcnt == 2'd3) ? 2'd3 : fcnt + 2'd1); end
        if (fcnt >= 2'd2) begin lc <= LC_KILLED; lcn <= ~(LC_KILLED); end
        zpend    <= 1'b1;
        zkind    <= Z_FAULT;
        core_rst <= 1'b1;
      end else if (core_done && zrun) begin
        // internal wipe finished
        zrun <= 1'b0;
        if (core_result == R_FAULT) begin       // the wipe itself failed: give up
          begin lc     <= LC_KILLED; lcn <= ~(LC_KILLED); end
          res    <= R_FAULT;
          done_s <= 1'b1;
        end else if (zkind != Z_POR) begin
          res    <= (zkind == Z_KILL) ? R_KILLED : R_FAULT;
          done_s <= 1'b1;
        end
      end else if (core_done) begin
        res    <= core_result;
        done_s <= 1'b1;
      end else if (zpend && !core_rst && !core_busy) begin
        zpend     <= 1'b0;
        zrun      <= 1'b1;
        cmd       <= CMD_ZEROIZE;
        cmd_inj   <= 1'b0;
        cmd_start <= 1'b1;
        if (zkind != Z_POR) done_s <= 1'b0;
      end else if (ctrl_wr && idle) begin
        done_s <= 1'b0;
        if (!known) begin
          res    <= R_UNKNOWN;
          done_s <= 1'b1;
        end else if (lc == LC_KILLED) begin
          res    <= R_KILLED;
          done_s <= 1'b1;
        end else if (!allowed) begin
          res    <= R_DENIED;
          done_s <= 1'b1;
        end else begin
          cmd       <= wcmd;
          cmd_inj   <= bus_wdata[8] && test;
          cmd_start <= 1'b1;
        end
      end
    end
  end

  // ---- reads (latency 1) ----
  wire busy_s = core_busy | cmd_start | zpend | zrun | nv_crit;
  always @(posedge clk) begin
    rd_buf <= bus_re && is_buf;
    rd_ok  <= h_re;
    case (bus_addr)
      12'h400: csr_q <= 32'h50515345;
      12'h401: csr_q <= 32'h00040000;
      12'h403: csr_q <= {13'd0, fcnt, sk_valid, res, lc, tampered, trng_fail, trng_ok,
                         key_valid, done_s, busy_s};
      12'h404: csr_q <= cycles;
      12'h405: csr_q <= {30'd0, lc};
      12'h406: csr_q <= {31'd0, hide_en};
      default: csr_q <= 32'd0;
    endcase
  end
  always @* bus_rdata = rd_buf ? (rd_ok ? h_rdata : 32'd0) : csr_q;
endmodule

// -----------------------------------------------------------------------------
// pqse_nvm - persistent storage of the security state: NB bits that can only be
// set (OTP fuse semantics), each stored twice and read as the OR of the copies.
// prog sets the bits of pmask (both copies); busy while programming (PROG_CLK
// clocks, the programming time of a fuse / NVM row); q shows the stored bits.
// Not reset by rst: the contents survive a reset.
//
// This is the behavioural model (simulation; on the FPGA registers that keep
// their value through a reset but not a power-off - a Gowin GW1NR / GW2AR could
// use its user flash). A chip replaces this module, same ports, with the
// wrapper of the PDK's OTP / eFuse macro (program pulses per bit, sense at
// power-up before rst is released).
// -----------------------------------------------------------------------------
module pqse_nvm #(
  parameter       NB       = 7,
  parameter [7:0] PROG_CLK = 8'd32
) (
  input  wire          clk,
  input  wire          prog,
  input  wire [NB-1:0] pmask,
  output wire          busy,
  output wire [NB-1:0] q
);
  reg [NB-1:0] fa = {NB{1'b0}};       // copy A
  reg [NB-1:0] fb = {NB{1'b0}};       // copy B
  reg [NB-1:0] pm = {NB{1'b0}};
  reg [7:0]    pc = 8'd0;             // programming clocks left
  assign busy = (pc != 8'd0);
  assign q    = fa | fb;
  always @(posedge clk) begin
    if (pc != 8'd0) begin
      pc <= pc - 8'd1;
      if (pc == 8'd1) begin           // the fuses blow at the end of the pulse
        fa <= fa | pm;
        fb <= fb | pm;
      end
    end else if (prog) begin
      pm <= pmask;
      pc <= PROG_CLK;
    end
  end
endmodule
