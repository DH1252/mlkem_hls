// -----------------------------------------------------------------------------
// pqse_mcomp.v - first-order masked Compress_d for the PQSE secure element.
//
// Input: a polynomial in two arithmetic shares mod q, x = x0 + x1 (slot0 =
// share 0, slot1 = share 1; with neg1 the share-1 slot holds -x1).
// Output: the d bits of Compress_d(x) for every coefficient,
//   mode 0 (d = 1):  m' bits as Boolean shares into seed entry e     (Decrypt)
//   mode 1 (d = 4, 5, 10, 11): each bit, XORed with the public ciphertext bit, goes
//                    out as nd = NOT(bit XOR c) (Boolean shares) to the ok
//                    accumulators in pqse_masked.v                    (c' == c ?)
//   mode 2 (d = 4, 5, 10, 11): the bits are unmasked (they are ciphertext, public)
//                    and written into buffer lanes from lane ba       (Encaps)
//
// Method (per coefficient):
//   1. per share, in its own domain:  y_s = round(x_s * 2^K / q) mod 2^K,
//      K = d + T, computed as (x_s * M_d + 2^15) >> 16 with M_d =
//      round(2^(K+16) / q); share 0 also adds 2^(T-1). T = 14 extra bits, or
//      T = 13 for d = 11 (ML-KEM-1024's du) so that K stays 24.
//      Then (y0 + y1) mod 2^K = 2^K x / q + 2^(T-1) + e with |e| <= 1.05, and
//      Compress_d(x) = bits [K-1:T] of it: the true value never comes closer
//      than 2^T / 2q (2.46, or 1.23 for T = 13) to a multiple of 2^T (q is
//      odd), so e never changes the result. scripts/pqse_model.py checks d = 1,
//      4, 10; v1.5's d = 5 and 11 were checked the same way, for every
//      coefficient and every split into two shares.
//   2. refresh into Boolean sharings with fresh R, R' (K bits each):
//      a = (y0 ^ R, R), b = (R', y1 ^ R')
//   3. bit-serial ripple-carry addition a + b, LSB first, two clocks per bit
//      (v1.6: the two coefficients of a word in two adders side by side, so a
//      word takes about 2K + 8 clocks instead of 4K + 13):
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
//   Mode 1 (v1.6): the two coefficients' comparison bits e (low) and f (high)
//      are ANDed here first, with one more DOM AND (e, f registered after the
//      adder's AND clock; the four products, registered, with a fresh bit;
//      their compressed shares registered), and the result goes to the ok
//      accumulators, still one bit per two clocks, three clocks later.
//   Randomness (v1.6): from pqse_kprng (320 fresh bits per take): the refresh
//      takes 4 x 24 bits, every AND clock 2 bits, the comparison AND 1 bit.
//   Robust-probing rules (first order, glitches + transitions; checked for
//   the v4 one-coefficient schedule by scripts/pqse_probe_verify.py, not yet
//   for v1.6's two adders and comparison AND): the two shares of one value meet only in
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
//   mode 0: read-modify-write of the m' seed lane that holds its 2 bits
//   mode 1: reads the 1-2 ciphertext lanes that hold its 2d bits
//   mode 2: read-modify-write of the 1-2 ciphertext lanes
//
// RAM reads: share 0 word (RAM 0), a public word of RAM 0 (slot T word 0), an idle
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
  input  wire [3:0]  d,         // 1, 4, 5, 10 or 11
  input  wire [4:0]  slot0,
  input  wire [4:0]  slot1,
  input  wire        neg1,
  input  wire [3:0]  ent,
  input  wire [8:0]  ba,        // modes 1, 2: first buffer lane of the ciphertext part
  input  wire        shuf,      // random word order
  output wire        busy,
  // polynomial RAM (read only)
  output reg         re,
  output reg  [11:0] raddr,
  input  wire [23:0] rdata,
  // buffer: ciphertext in (mode 1) / out (mode 2, unmasked - it is ciphertext)
  output reg         bre,
  output reg  [8:0]  braddr,
  input  wire [63:0] brdata,
  output reg         bwe,
  output reg  [8:0]  bwaddr,
  output reg  [63:0] bwdata,
  // seed registers (mode 0: m')
  output reg         sre,
  output reg  [5:0]  sraddr,
  input  wire [63:0] srd0,
  input  wire [63:0] srd1,
  output reg         swe,
  output reg  [5:0]  swaddr,
  output reg  [63:0] swd0,
  output reg  [63:0] swd1,
  // compare output, one Boolean-shared bit (the AND of a word's two
  // comparison bits) at most every other clock, from registers
  output wire        nd_valid,
  output wire        nd0,
  output wire        nd1,
  // randomness (pqse_kprng: fresh bits on every take)
  input  wire [319:0] krnd,
  output wire        krnd_take,
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
  reg [3:0]  dd, en_;
  reg [4:0]  s0, s1;
  reg [4:0]  TB;         // extra bits: 14, or 13 for d = 11
  reg [6:0]  w;          // word counter
  reg [6:0]  ws;         // the word being processed (shuffled)
  reg [4:0]  i;          // adder bit
  reg [4:0]  K;
  reg [28:0] M;
  reg [5:0]  sub;        // bit offset of the word in its first lane
  reg [5:0]  lane;       // first lane of the word (relative to bar)
  reg [63:0] WL, WH;     // ciphertext window: lanes lane, lane + 1
  reg [63:0] G0, G1;     // m' seed lane, share 0 / share 1
  // domain 0 registers (X0w takes the share 0 word off the RAM read bus and
  // hands it to Z0 before the share 1 word arrives: no register whose input
  // is that bus ever holds share 0 while the bus carries share 1)
  reg [23:0] X0w, Z0;
  // per coefficient c (0: low, 1: high half of the word), domain 0 / domain 1
  reg [23:0] y0l, y0h, y1l, y1h;
  reg [23:0] A0l, A0h, B0l, B0h, A1l, A1h, B1l, B1h;
  reg        ad0l, ad0h, ad1l, ad1h, C0l, C0h, C1l, C1h;
  reg        so0l, so0h, so1l, so1h;
  // domain 1 bus register
  reg [23:0] X1w;
  // DOM AND partial products of the two adders (registered)
  reg        p00l, p01l, p10l, p11l, p00h, p01h, p10h, p11h;
  reg        sov;        // mode 2: so0 / so1 hold the ciphertext bits to place
  reg  [6:0] cpdl, cpdh; // ... at these window positions
  // mode 1: comparison AND of the two coefficients' bits (e: low, f: high)
  reg        ev, e0, e1, f0, f1;          // stage 1: the comparison bits, per share
  reg        pv, q00, q01, q10, q11;      // stage 2: DOM products
  reg        gv, g0, g1;                  // stage 3: compressed shares -> ok accumulators

  assign busy      = start | (st != S_IDLE) | ev | pv | gv;
  assign krnd_take = (st == S_RF) | (st == S_AD) | ev;
  assign nd_valid  = gv;
  assign nd0       = g0;
  assign nd1       = g1;

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
  assign      pq_idx = w;
  wire [6:0]  wsh  = shf ? pq_val : w;                  // T[w]: uniformly random order
  wire [11:0] offc = {4'd0, wsh, 1'b0} * {8'd0, dd};   // bit offset of coefficient 2 wsh

  wire [11:0] x1rl = X1w[11:0], x1rh = X1w[23:12];
  wire [11:0] x1cl = ng ? negq(x1rl) : x1rl;
  wire [11:0] x1ch = ng ? negq(x1rh) : x1rh;
  wire [23:0] kmask = (24'd1 << K) - 24'd1;
  wire [23:0] yoff  = (TB == 5'd13) ? 24'd4096 : 24'd8192;   // 2^(T-1), share 0

  // adder bit i of each coefficient: carry shares are registers (0 for bit 0)
  wire P0l = A0l[0] ^ B0l[0], P1l = A1l[0] ^ B1l[0];
  wire Q0l = A0l[0] ^ C0l,    Q1l = A1l[0] ^ C1l;
  wire P0h = A0h[0] ^ B0h[0], P1h = A1h[0] ^ B1h[0];
  wire Q0h = A0h[0] ^ C0h,    Q1h = A1h[0] ^ C1h;
  wire sum0l = P0l ^ C0l, sum1l = P1l ^ C1l;
  wire sum0h = P0h ^ C0h, sum1h = P1h ^ C1h;
  wire top  = (i >= TB);                                 // an output bit
  wire [4:0] j = i - TB;                                 // which output bit
  wire rbl  = krnd[96], rbh = krnd[97], rbe = krnd[98];
  // position of output bit j of each coefficient in the ciphertext window
  wire [6:0] cposl = {1'b0, sub} + {2'd0, j};
  wire [6:0] cposh = {1'b0, sub} + {3'd0, dd} + {2'd0, j};
  wire [127:0] Wn = {WH, WL};
  wire cbitl = Wn[cposl], cbith = Wn[cposh];
  wire [5:0] gposl = {ws[4:0], 1'b0}, gposh = {ws[4:0], 1'b1};
  // the second ciphertext lane is touched only if the word's 2d bits cross into it
  wire [6:0] wend = {1'b0, sub} + {2'd0, dd, 1'b0};
  wire       two  = (wend > 7'd64);
  wire       cmpbit = (st == S_AD) && top && (md == 2'd1);

  always @* begin
    re = 1'b0; raddr = 12'd0;
    bre = 1'b0; braddr = 9'd0; bwe = 1'b0; bwaddr = 9'd0; bwdata = 64'd0;
    sre = 1'b0; sraddr = 6'd0; swe = 1'b0; swaddr = 6'd0; swd0 = 64'd0; swd1 = 64'd0;
    case (st)
      S_R0: begin
        re = 1'b1; raddr = {s0, wsh};                     // share 0 word
        if (md == 2'd0) begin sre = 1'b1; sraddr = {en_, wsh[6:5]}; end
        else begin bre = 1'b1; braddr = bar + {3'd0, offc[11:6]}; end
      end
      S_R1: begin
        re = 1'b1; raddr = {P_T, 7'd0};                   // public word of RAM 0: precharge
        if (md != 2'd0) begin bre = 1'b1; braddr = bar + {3'd0, lane} + 9'd1; end
      end
      S_RD1: begin re = 1'b1; raddr = {s1, ws}; end       // share 1 word
      S_WB0: begin
        if (md == 2'd0) begin                             // m' lane back, both shares
          swe = 1'b1; swaddr = {en_, ws[6:5]}; swd0 = G0; swd1 = G1;
        end else if (md == 2'd2) begin
          bwe = 1'b1; bwaddr = bar + {3'd0, lane}; bwdata = WL;
        end
      end
      S_WB1: begin bwe = 1'b1; bwaddr = bar + {3'd0, lane} + 9'd1; bwdata = WH; end
      default: ;
    endcase
  end

  // ---- mode 1: the comparison AND (every register loads every clock: 0 except
  // in the clock after its input stage was valid; no hold path) ----
  always @(posedge clk) begin
    if (rst) begin
      ev <= 1'b0; e0 <= 1'b0; e1 <= 1'b0; f0 <= 1'b0; f1 <= 1'b0;
      pv <= 1'b0; q00 <= 1'b0; q01 <= 1'b0; q10 <= 1'b0; q11 <= 1'b0;
      gv <= 1'b0; g0 <= 1'b0; g1 <= 1'b0;
    end else begin
      ev  <= cmpbit;
      e0  <= cmpbit & ~(sum0l ^ cbitl);                  // domain 0
      e1  <= cmpbit & sum1l;                             // domain 1
      f0  <= cmpbit & ~(sum0h ^ cbith);
      f1  <= cmpbit & sum1h;
      pv  <= ev;
      q00 <= e0 & f0;
      q01 <= (e0 & f1) ^ (rbe & ev);
      q10 <= (e1 & f0) ^ (rbe & ev);
      q11 <= e1 & f1;
      gv  <= pv;
      g0  <= q00 ^ q01;                                  // domain 0 + masked cross term
      g1  <= q11 ^ q10;                                  // domain 1 + masked cross term
    end
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
      p00l <= 1'b0; p01l <= 1'b0; p10l <= 1'b0; p11l <= 1'b0;
      p00h <= 1'b0; p01h <= 1'b0; p10h <= 1'b0; p11h <= 1'b0;
      case (st)
        S_IDLE: if (!start) begin
          // idle: the registers behind the RAM read bus hold nothing (the bus
          // carries other instructions' words, possibly the other share), and
          // no share of m' or of a coefficient stays behind (zeroization).
          // Cleared once on entering idle, then held (low power).
          if (!idl) begin
            X0w <= 24'd0; X1w <= 24'd0; Z0 <= 24'd0;
            G0  <= 64'd0; G1  <= 64'd0;
            y0l <= 24'd0; y0h <= 24'd0; y1l <= 24'd0; y1h <= 24'd0;
            A0l <= 24'd0; A0h <= 24'd0; B0l <= 24'd0; B0h <= 24'd0;
            A1l <= 24'd0; A1h <= 24'd0; B1l <= 24'd0; B1h <= 24'd0;
            C0l <= 1'b0;  C0h <= 1'b0;  C1l <= 1'b0;  C1h <= 1'b0;
            ad0l <= 1'b0; ad0h <= 1'b0; ad1l <= 1'b0; ad1h <= 1'b0;
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
          K   <= (d == 4'd11) ? 5'd24 : {1'b0, d} + 5'd14;
          TB  <= (d == 4'd11) ? 5'd13 : 5'd14;
          M   <= (d == 4'd1) ? 29'd645084 : (d == 4'd4) ? 29'd5160670 :
                 (d == 4'd5) ? 29'd10321339 : 29'd330282856;          // d = 10, 11: K = 24
          w   <= 7'd0;
          sov <= 1'b0;
          so0l <= 1'b0; so1l <= 1'b0; so0h <= 1'b0; so1h <= 1'b0;
          st  <= S_R0;
        end
        S_R0: begin
          ws   <= wsh;
          sub  <= offc[5:0];
          lane <= offc[11:6];
          st   <= S_R1;
        end
        S_R1: begin
          X0w <= rdata;                                     // share 0 word
          if (md == 2'd0) begin G0 <= srd0; G1 <= srd1; end // m' lane (both shares)
          else WL <= brdata;                                // ciphertext lane
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
        S_SC: begin                                       // both coefficients, per domain
          y0l <= (scale(Z0[11:0],  M, K) + yoff) & kmask;
          y0h <= (scale(Z0[23:12], M, K) + yoff) & kmask;
          y1l <= scale(x1cl, M, K);
          y1h <= scale(x1ch, M, K);
          st  <= S_RF;
        end
        S_RF: begin                                       // a = (y0 ^ R, R), b = (R', y1 ^ R')
          A0l <= (y0l ^ krnd[23:0])  & kmask;  A1l <= krnd[23:0]  & kmask;
          B0l <= krnd[47:24]         & kmask;  B1l <= (y1l ^ krnd[47:24]) & kmask;
          A0h <= (y0h ^ krnd[71:48]) & kmask;  A1h <= krnd[71:48] & kmask;
          B0h <= krnd[95:72]         & kmask;  B1h <= (y1h ^ krnd[95:72]) & kmask;
          C0l <= 1'b0; C1l <= 1'b0; C0h <= 1'b0; C1h <= 1'b0;
          i  <= 5'd0;
          st <= S_AD;
        end
        S_AD: begin                                       // AND clock, both adders
          p00l <= P0l & Q0l;
          p01l <= (P0l & Q1l) ^ rbl;
          p10l <= (P1l & Q0l) ^ rbl;
          p11l <= P1l & Q1l;
          p00h <= P0h & Q0h;
          p01h <= (P0h & Q1h) ^ rbh;
          p10h <= (P1h & Q0h) ^ rbh;
          p11h <= P1h & Q1h;
          ad0l <= A0l[0]; ad1l <= A1l[0];
          ad0h <= A0h[0]; ad1h <= A1h[0];
          A0l <= A0l >> 1; A1l <= A1l >> 1; B0l <= B0l >> 1; B1l <= B1l >> 1;
          A0h <= A0h >> 1; A1h <= A1h >> 1; B0h <= B0h >> 1; B1h <= B1h >> 1;
          if (top && md == 2'd0) begin                    // d = 1: the m' bits, each share
            G0[gposl] <= sum0l;                           // into its own register
            G1[gposl] <= sum1l;
            G0[gposh] <= sum0h;
            G1[gposh] <= sum1h;
          end
          // mode 2 (ciphertext, public): the shares go into registers that only
          // this mode loads; they are combined in the compress clock
          sov  <= top && (md == 2'd2);
          so0l <= top && (md == 2'd2) && sum0l;
          so1l <= top && (md == 2'd2) && sum1l;
          so0h <= top && (md == 2'd2) && sum0h;
          so1h <= top && (md == 2'd2) && sum1h;
          cpdl <= cposl;
          cpdh <= cposh;
          st   <= S_AC;
        end
        S_AC: begin                                       // compress clock
          C0l <= ad0l ^ p00l ^ p01l;                      // carry share 0 (domain 0 + masked cross term)
          C1l <= ad1l ^ p11l ^ p10l;                      // carry share 1
          C0h <= ad0h ^ p00h ^ p01h;
          C1h <= ad1h ^ p11h ^ p10h;
          if (sov) begin                                  // ciphertext bits: public
            if (cpdl[6]) WH[cpdl[5:0]] <= so0l ^ so1l;
            else         WL[cpdl[5:0]] <= so0l ^ so1l;
            if (cpdh[6]) WH[cpdh[5:0]] <= so0h ^ so1h;
            else         WL[cpdh[5:0]] <= so0h ^ so1h;
          end
          sov  <= 1'b0;
          so0l <= 1'b0; so1l <= 1'b0; so0h <= 1'b0; so1h <= 1'b0;
          if (i == K - 5'd1) begin
            i  <= 5'd0;
            st <= S_WB0;
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
