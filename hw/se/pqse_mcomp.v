// -----------------------------------------------------------------------------
// pqse_mcomp.v - first-order masked Compress_d for the PQSE secure element.
//
// Input: a polynomial in two arithmetic shares mod q, x = x0 + x1 (slot0 =
// share 0, slot1 = share 1; with neg1 the share-1 slot holds -x1).
// Output: the d bits of Compress_d(x) for every coefficient,
//   mode 0 (d = 1):  m' bits as Boolean shares into seed entry e     (Decrypt)
//   mode 1 (d = 4, 10): each bit, XORed with the public ciphertext bit, goes
//                    out as nd = NOT(bit XOR c) (Boolean shares) to the ok
//                    accumulators in pqse_masked.v                    (c' == c ?)
//   mode 2 (d = 4, 10): the bits are unmasked (they are ciphertext, public)
//                    and written into buffer lanes from lane ba       (Encaps)
// v5: the buffer and the seed registers are 16-bit word memories; a word's 2d
// ciphertext bits (d = 4: 8 bits at offset 0 / 8, d = 10: 20 bits at offset
// 0, 4, 8, 12) span at most two buffer words, m' bits 2w, 2w + 1 sit in seed
// word w / 8.
//
// Method (per coefficient):
//   1. per share, in its own domain:  y_s = round(x_s * 2^K / q) mod 2^K,
//      K = d + 14, computed as (x_s * M_d + 2^15) >> 16 with M_d =
//      round(2^(K+16) / q); share 0 also adds 2^13.
//      Then (y0 + y1) mod 2^K = 2^K x / q + 2^13 + e with |e| <= 1.05, and
//      Compress_d(x) = bits [K-1:14] of it: the true value never comes closer
//      than 2^14 / 2q = 2.46 to a multiple of 2^14 (q is odd), so e never
//      changes the result. scripts/pqse_model.py checks this numerically.
//   2. refresh into Boolean sharings with fresh R, R' (K bits each):
//      a = (y0 ^ R, R), b = (R', y1 ^ R')
//   3. bit-serial ripple-carry addition a + b, LSB first, two clocks per bit:
//      carry' = a ^ ((a ^ b) & (a ^ carry)) with one DOM-indep AND per bit
//        AND clock       the four partial products, a fresh random bit, all
//                        registered; sum bit = a ^ b ^ carry (per share)
//        compress clock  carry'_s = a_s ^ p_ss ^ p_s(1-s) into the carry
//                        register of share s; the products return to 0
//      The carry shares are registers and the products load every clock (0
//      outside the compress clock, no hold path), so the next AND never sees
//      the cross terms of the previous one (with them, a glitch + transition
//      probe on the next cross term would see both the old cross term and the
//      carry share masked by the same random bit).
//   Robust-probing rules (first order, glitches + transitions; checked by
//   scripts/pqse_probe_verify.py): the two shares of one value meet only in
//   the registered DOM cross terms; the unmasked ciphertext bit of mode 2 is
//   formed from two registers (so0, so1) that only mode 2 loads, so in modes
//   0 and 1 no gate ever computes a bit of m' or of the re-encryption.
//
// Shuffling (shuf = 1, i.e. hiding on): the 128 words (coefficient pairs) are
// processed in a fresh uniformly random order w' = T[w] per operation (the
// Fisher-Yates permutation of pqse_perm.v), so repeated runs on the same input
// do not line up (this is what the published attacks on masked Kyber's message
// decoding average over).
// Every word therefore reads and writes its own place:
//   mode 0: read-modify-write of the m' seed word that holds its 2 bits
//   mode 1: reads the 1-2 ciphertext words that hold its 2d bits
//   mode 2: read-modify-write of the 1-2 ciphertext words
//
// RAM reads: share 0 word (RAM 0), a public word of RAM 0 (S_T word 0), an idle
// clock, share 1 word (RAM 1). The two RAMs' output registers, the read mux
// behind them in pqse_core.v, and the registers loaded from that bus (X0w,
// cleared into Z0 before share 1 arrives; X1w) therefore never hold the two
// shares of one coefficient at the same time or in consecutive clocks (the
// sequencer precharges both RAM outputs at every instruction boundary, and
// the bus registers are cleared while the unit is idle).
// -----------------------------------------------------------------------------
module pqse_mcomp (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [1:0]  mode,      // 0: m' -> seed entry, 1: compare, 2: ciphertext out
  input  wire [3:0]  d,         // 1, 4 or 10
  input  wire [3:0]  slot0,
  input  wire [3:0]  slot1,
  input  wire        neg1,
  input  wire [3:0]  ent,
  input  wire [8:0]  ba,        // modes 1, 2: first buffer lane of the ciphertext part
  input  wire        shuf,      // random word order
  output wire        busy,
  // polynomial RAM (read only)
  output reg         re,
  output reg  [10:0] raddr,
  input  wire [23:0] rdata,
  // buffer: ciphertext in (mode 1) / out (mode 2, unmasked - it is ciphertext)
  output reg         bre,
  output reg  [10:0] braddr,
  input  wire [15:0] brdata,
  output reg         bwe,
  output reg  [10:0] bwaddr,
  output reg  [15:0] bwdata,
  // seed registers (mode 0: m')
  output reg         sre,
  output reg  [7:0]  sraddr,
  input  wire [15:0] srd0,
  input  wire [15:0] srd1,
  output reg         swe,
  output reg  [7:0]  swaddr,
  output reg  [15:0] swd0,
  output reg  [15:0] swd1,
  // compare output, one Boolean-shared bit per clock when nd_valid
  output reg         nd_valid,
  output reg         nd0,
  output reg         nd1,
  // randomness
  input  wire [63:0] rnd,
  output reg         rnd_take,
  output wire        rnd_hi,    // the take uses only rnd[63:32] (AND clock: rb = bit 48)
  // random word order of this instruction (pqse_perm.v): pq_val = T[pq_idx]
  output wire [6:0]  pq_idx,
  input  wire [6:0]  pq_val
);
  `include "pqse_defs.vh"
  `include "pqse_func.vh"

  localparam [3:0] S_IDLE = 4'd0, S_R0 = 4'd1, S_R1 = 4'd2, S_R2 = 4'd3, S_R3 = 4'd4,
                   S_SC = 4'd5, S_RF = 4'd6, S_AD = 4'd7, S_WB0 = 4'd8, S_WB1 = 4'd9,
                   S_AC = 4'd10,   // adder compress clock
                   S_RD1 = 4'd11;  // read the share 1 word (X0w is clear by now)

  reg [3:0]  st;
  reg        idl;        // the idle registers are cleared
  reg [1:0]  md;
  reg        ng, shf;
  reg [8:0]  bar;        // ciphertext base lane
  reg [3:0]  dd, s0, s1, en_;
  reg [6:0]  w;          // word counter
  reg [6:0]  ws;         // the word being processed (shuffled)
  reg        hi;         // coefficient within the word
  reg [4:0]  i;          // adder bit
  reg [4:0]  K;
  reg [28:0] M;
  reg [3:0]  sub;        // bit offset of the word in its first buffer word
  reg [10:0] cwa;        // first buffer word of the word (absolute; its read in S_R0)
  reg [15:0] WL, WH;     // ciphertext window: buffer words cwa, cwa + 1
  reg [15:0] G0, G1;     // m' seed word, share 0 / share 1
  // domain 0 registers (X0w takes the share 0 word off the RAM read bus and
  // hands it to Z0 before the share 1 word arrives: no register whose input
  // is that bus ever holds share 0 while the bus carries share 1)
  reg [23:0] X0w, Z0;
  reg [23:0] y0r;
  reg [23:0] A0, B0;
  reg        ad0, C0, so0;
  // domain 1 registers
  reg [23:0] X1w;
  reg [23:0] y1r;
  reg [23:0] A1, B1;
  reg        ad1, C1, so1;
  // DOM AND partial products (registered)
  reg        p00, p01, p10, p11;
  reg        sov;        // mode 2: so0 / so1 hold a ciphertext bit to place
  reg  [4:0] cpd;        // ... at this window position

  assign busy = start | (st != S_IDLE);
  assign rnd_hi = (st == S_AD);

  // scale: (x * M + 2^15) >> 16, mod 2^K (K <= 24)
  function [23:0] scale(input [11:0] x, input [28:0] sm, input [4:0] sk);
    reg [41:0] p;
    reg [25:0] s;
    begin
      p = x * sm + 42'd32768;
      s = p[41:16];
      scale = s[23:0] & ((24'd1 << sk) - 24'd1);
    end
  endfunction

  // the word to process next, and where its ciphertext bits sit
  wire [6:0]  wsh  = shf ? pq_val : w;                  // T[w]: uniformly random order
  // bit offset of coefficient 2 wsh: 2 wsh d, d = 1, 4 or 10 (shifts and one add)
  wire [11:0] offc = (dd == 4'd10) ? ({1'b0, wsh, 4'd0} + {3'd0, wsh, 2'd0}) :
                     (dd == 4'd4)  ? {2'd0, wsh, 3'd0} : {4'd0, wsh, 1'b0};
  wire [10:0] cba  = {bar, 2'b00};                      // ciphertext base word
  wire [3:0]  dhi  = hi ? dd : 4'd0;

  wire [11:0] x0c = hi ? Z0[23:12] : Z0[11:0];
  wire [11:0] x1r = hi ? X1w[23:12] : X1w[11:0];
  wire [11:0] x1c = ng ? negq(x1r) : x1r;
  wire [23:0] kmask = (24'd1 << K) - 24'd1;

  // adder bit i: carry shares C0, C1 are registers (0 for bit 0, set in S_RF)
  wire a0b = A0[0], a1b = A1[0], b0b = B0[0], b1b = B1[0];
  wire P0 = a0b ^ b0b, P1 = a1b ^ b1b;
  wire Q0 = a0b ^ C0, Q1 = a1b ^ C1;
  wire sum0 = P0 ^ C0, sum1 = P1 ^ C1;
  wire top  = (i >= 5'd14);                              // an output bit
  wire [4:0] j = i - 5'd14;                              // which output bit
  wire rb   = rnd[48];
  // position of output bit j of this coefficient in the ciphertext window / seed word
  wire [4:0] cpos = {1'b0, sub} + {1'b0, dhi} + j;
  wire [31:0] Wn = {WH, WL};
  wire cbit = Wn[cpos];
  wire [3:0] gpos = {ws[2:0], hi};
  // the second ciphertext word is touched only if the word's 2d bits cross into it
  wire [5:0] wend = {2'd0, sub} + {1'b0, dd, 1'b0};
  wire       two  = (wend > 6'd16);
  // the permutation lookup is registered (pqse_perm.v): it gets the next
  // clock's word (w + 1 in the clock that advances w, 0 at the start)
  wire       wadv   = ((st == S_WB0) && !(md == 2'd2 && two)) || (st == S_WB1);
  assign     pq_idx = (st == S_IDLE) ? 7'd0 : wadv ? (w + 7'd1) : w;

  always @* begin
    re = 1'b0; raddr = 11'd0;
    bre = 1'b0; braddr = 11'd0; bwe = 1'b0; bwaddr = 11'd0; bwdata = 16'd0;
    sre = 1'b0; sraddr = 8'd0; swe = 1'b0; swaddr = 8'd0; swd0 = 16'd0; swd1 = 16'd0;
    nd_valid = 1'b0; nd0 = 1'b0; nd1 = 1'b0;
    rnd_take = 1'b0;
    case (st)
      S_R0: begin
        re = 1'b1; raddr = {s0, wsh};                     // share 0 word
        if (md == 2'd0) begin sre = 1'b1; sraddr = {en_, wsh[6:3]}; end
        else begin bre = 1'b1; braddr = cba + {3'd0, offc[11:4]}; end
      end
      S_R1: begin
        re = 1'b1; raddr = {S_T, 7'd0};                   // public word of RAM 0: precharge
        if (md != 2'd0) begin bre = 1'b1; braddr = cwa + 11'd1; end
      end
      S_RD1: begin re = 1'b1; raddr = {s1, ws}; end       // share 1 word
      S_RF: rnd_take = 1'b1;
      S_AD: begin
        rnd_take = 1'b1;
        if (top && md == 2'd1) begin
          nd_valid = 1'b1;
          nd0 = ~(sum0 ^ cbit);
          nd1 = sum1;
        end
      end
      S_WB0: begin
        if (md == 2'd0) begin                             // m' word back, both shares
          swe = 1'b1; swaddr = {en_, ws[6:3]}; swd0 = G0; swd1 = G1;
        end else if (md == 2'd2) begin
          bwe = 1'b1; bwaddr = cwa; bwdata = WL;
        end
      end
      S_WB1: begin bwe = 1'b1; bwaddr = cwa + 11'd1; bwdata = WH; end
      default: ;
    endcase
  end

  always @(posedge clk) begin
    if (rst) begin
      st  <= S_IDLE;
      idl <= 1'b0;
    end else begin
      // DOM partial products: loaded in every clock, 0 except right after the
      // AND clock (no hold path). A held p01 / p10 would sit next to the carry
      // share it was compressed into (C1 holds p10, masked by the same random
      // bit as p01): a glitch on the next AND's cross-term input would see both
      // and unmask the cross term (found by scripts/pqse_probe_verify.py).
      p00 <= 1'b0; p01 <= 1'b0; p10 <= 1'b0; p11 <= 1'b0;
      case (st)
        S_IDLE: if (!start) begin
          // idle: the registers behind the RAM read bus hold nothing (the bus
          // carries other instructions' words, possibly the other share), and
          // no share of m' or of a coefficient stays behind (zeroization).
          // Cleared once on entering idle, then held (low power: the idle
          // unit's clock can be gated; nothing loads them while idle)
          if (!idl) begin
            X0w <= 24'd0; X1w <= 24'd0; Z0 <= 24'd0;
            G0  <= 16'd0; G1  <= 16'd0; y0r <= 24'd0; y1r <= 24'd0;
            A0  <= 24'd0; A1  <= 24'd0; B0  <= 24'd0; B1  <= 24'd0;
            C0  <= 1'b0;  C1  <= 1'b0;  ad0 <= 1'b0;  ad1 <= 1'b0;
            idl <= 1'b1;
          end
        end else begin
          idl <= 1'b0;
          md  <= mode;
          bar <= ba;
          dd  <= d;
          s0  <= slot0;
          s1  <= slot1;
          ng  <= neg1;
          en_ <= ent;
          shf <= shuf;
          K   <= {1'b0, d} + 5'd14;
          M   <= (d == 4'd1) ? 29'd645084 : (d == 4'd4) ? 29'd5160670 : 29'd330282856;
          w   <= 7'd0;
          hi  <= 1'b0;
          sov <= 1'b0;
          so0 <= 1'b0;
          so1 <= 1'b0;
          st  <= S_R0;
        end
        S_R0: begin
          ws   <= wsh;
          sub  <= offc[3:0];
          cwa  <= cba + {3'd0, offc[11:4]};
          st   <= S_R1;
        end
        S_R1: begin
          X0w <= rdata;                                     // share 0 word
          if (md == 2'd0) begin G0 <= srd0; G1 <= srd1; end // m' word (both shares)
          else WL <= brdata;                                // ciphertext word
          st  <= S_R2;
        end
        S_R2: begin
          if (md != 2'd0) WH <= brdata;                     // (rdata = the public precharge word)
          Z0  <= X0w;                                       // share 0 word off the bus register
          X0w <= 24'd0;
          st  <= S_RD1;
        end
        S_RD1: st <= S_R3;                                  // share 1 read issued (X0w is 0)
        S_R3: begin X1w <= rdata; st <= S_SC; end         // share 1 word
        S_SC: begin
          y0r <= (scale(x0c, M, K) + 24'd8192) & kmask;   // domain 0 (+ 2^13)
          y1r <= scale(x1c, M, K);                        // domain 1
          st  <= S_RF;
        end
        S_RF: begin
          A0 <= (y0r ^ rnd[23:0])  & kmask;               // a = (y0 ^ R, R)
          A1 <= rnd[23:0]          & kmask;
          B0 <= rnd[47:24]         & kmask;               // b = (R', y1 ^ R')
          B1 <= (y1r ^ rnd[47:24]) & kmask;
          C0 <= 1'b0;                                     // carry into bit 0
          C1 <= 1'b0;
          i  <= 5'd0;
          st <= S_AD;
        end
        S_AD: begin                                       // AND clock
          // carry for the next bit: DOM AND of P and Q, all four products registered
          p00 <= P0 & Q0;
          p01 <= (P0 & Q1) ^ rb;
          p10 <= (P1 & Q0) ^ rb;
          p11 <= P1 & Q1;
          ad0 <= a0b;
          ad1 <= a1b;
          A0 <= A0 >> 1; A1 <= A1 >> 1;
          B0 <= B0 >> 1; B1 <= B1 >> 1;
          if (top && md == 2'd0) begin                    // d = 1: the m' bit, each share
            G0[gpos] <= sum0;                             // into its own register
            G1[gpos] <= sum1;
          end
          // mode 2 (ciphertext, public): the two shares go into registers that only
          // this mode loads; they are combined in the compress clock
          sov <= top && (md == 2'd2);
          so0 <= top && (md == 2'd2) && sum0;
          so1 <= top && (md == 2'd2) && sum1;
          cpd <= cpos;
          st  <= S_AC;
        end
        S_AC: begin                                       // compress clock
          C0 <= ad0 ^ p00 ^ p01;                          // carry share 0 (domain 0 + masked cross term)
          C1 <= ad1 ^ p11 ^ p10;                          // carry share 1
          if (sov) begin                                  // ciphertext bit: public
            if (cpd[4]) WH[cpd[3:0]] <= so0 ^ so1;
            else        WL[cpd[3:0]] <= so0 ^ so1;
          end
          sov <= 1'b0;
          if (i == K - 5'd1) begin
            i <= 5'd0;
            if (!hi) begin
              hi <= 1'b1;
              st <= S_SC;
            end else begin
              hi <= 1'b0;
              st <= S_WB0;
            end
          end else begin
            i  <= i + 5'd1;
            st <= S_AD;
          end
        end
        S_WB0: begin
          if (md == 2'd2 && two) st <= S_WB1;
          else if (w == 7'd127) st <= S_IDLE;
          else begin w <= w + 7'd1; st <= S_R0; end
        end
        S_WB1: begin
          if (w == 7'd127) st <= S_IDLE;
          else begin w <= w + 7'd1; st <= S_R0; end
        end
        default: st <= S_IDLE;
      endcase
    end
  end
endmodule
