// -----------------------------------------------------------------------------
// pqse_keccak.v - first-order masked Keccak-f[1600], 16-bit word-serial, state
// in RAM (v5, serial core).
//
// v4 processed whole 64-bit lanes (two 64-bit barrel rotators, 64-bit DOM
// registers); v5 processes one 16-bit word of a lane per clock, ~5x the clocks
// for ~1/4 of the logic. The state lives in two small RAMs, one per Boolean
// share (A0 ^ A1 = state), 256 words x 16 bits each (block RAM), word address
// {lane (6 bits), word k (2 bits)}, word k = lane bits [16k+15:16k]:
//     lanes  0..24  the state A[x + 5y]
//     lanes 25..29  the column parities C[x]
//     lanes 32..56  B = pi(rho(theta(A))), lane B[y + 5((2x + 3y) mod 5)]
//     lanes 58..62  the theta effect D[x] = C[x-1] ^ rol(C[x+1], 1)
// One read and one write per clock (simple dual-port RAM, registered read).
// Both shares run in lockstep through the same addresses, each with its own
// 16-bit data path; they meet only in the registered DOM cross terms of chi.
//
// One round = five passes, ~800 clocks (a permutation ~19,300 clocks):
//   C   100  C[x][k] = A[x][k] ^ A[x+5][k] ^ ... ^ A[x+20][k]
//   D    45  per column: D[x][k] = C[x-1][k] ^ {C[x+1][k][14:0], C[x+1][k-1][15]}
//   T   120  A[x+5y][k] ^= D[x][k] (D word in T, then the 5 lanes of the column)
//   RP  125  per lane, rotation r = 16 q + s: output word k from input words
//            k-q and k-q-1 (mod 4) through a 16-bit funnel shifter, read in the
//            order k-q-1, k-q, ... (5 reads, 4 writes) -> B[pi(lane)]
//   CHI 400  per plane y, word k, lanes in the order 0, 2, 4, 1, 3, 4 clocks each:
//              c0  read B[x+1]
//              c1  X <= ~B[x+1] (NOT on share 0)      read B[x+2]
//              c2  Y <= B[x+2]                       read B[x]
//              c3  DOM AND -> d00 d01 d10 d11 (16 fresh random bits),
//                  X cleared
//              c0' A[x + 5y] <= B[x] ^ d00 ^ d01 (^ iota)  (share 0)
//                               B[x] ^ d11 ^ d10           (share 1)
// DOM AND (Gross et al., "Domain-Oriented Masking", TIS 2016):
//   d00 = X0&Y0   d01 = X0&Y1 ^ r   d10 = X1&Y0 ^ r   d11 = X1&Y1   (registered)
// The chi gadget is the v4 one on 16-bit words instead of 64-bit lanes (each
// bit slice is the same circuit; scripts/pqse_probe_verify.py, gadget "Keccak
// chi, state in RAM"):
//   - each share has its own RAM, so a RAM's output register only ever holds
//     one share; the operand registers take one word each (X from B[x+1], Y
//     from B[x+2]) and are cleared after the AND, so the AND gate never sees
//     share 0 and share 1 of the same word, not even in consecutive clocks
//   - the products load every clock (0 except right after the AND)
//   - the write-back has its own cone (B[x], d00, d01 / d11, d10)
// Theta, rho, pi and iota are linear: each share on its own data path.
//
// Word port (pqse_sponge.v): ax_en / rd_en / go are taken only while rdy is
// high (and only one at a time). An absorb (word ^= {ax_v1, ax_v0}) is a
// read-modify-write, 2 clocks; a read delivers the word on rd_v0 / rd_v1 (the
// RAM output registers) when rdy is high again, held until the next read.
// Wipe: while clr is high and the RAMs are not known to be clean, every word
// of both RAMs is written 0 (256 clocks), then word 0 is read so the RAM output
// registers hold 0, and the lane registers are cleared.
//
// msk = 0 (unmasked job): share 1 stays zero, its RAM is not clocked, r = 0.
// MASKED = 0: the share-1 RAM and data path are not built.
//
// UNTESTED FIRST VERSION (v5) - see hw/se/README.md.
// -----------------------------------------------------------------------------
module pqse_keccak #(
  parameter MASKED   = 1,
  parameter RAMSTYLE = 0          // (kept for the interface: the state RAMs are block RAM)
) (
  input  wire        clk,
  input  wire        rst,
  input  wire        msk,        // this job is masked
  input  wire        clr,        // keep the state zero: wipe it unless already clean (busy meanwhile)
  input  wire        ax_en,      // word ax_k of lane ax_idx ^= {ax_v1, ax_v0} (taken while rdy)
  input  wire [4:0]  ax_idx,
  input  wire [1:0]  ax_k,
  input  wire [15:0] ax_v0,
  input  wire [15:0] ax_v1,
  input  wire        rd_en,      // read word rd_k of lane rd_idx onto rd_v0 / rd_v1 (taken while rdy)
  input  wire [4:0]  rd_idx,
  input  wire [1:0]  rd_k,
  output wire [15:0] rd_v0,
  output wire [15:0] rd_v1,
  input  wire        go,         // start a permutation (taken while rdy)
  output wire        busy,
  output wire        rdy,        // the lane port takes a request this clock
  input  wire [63:0] rnd,
  output wire        rnd_take
);
  localparam M1 = (MASKED != 0);

  // ---- constants -------------------------------------------------------------
  // round constant RC[r]: only bits 0, 1, 3, 7, 15, 31, 63 can be set (FIPS 202
  // Alg. 6: RC[2^j - 1] = rc(j + 7 ir)), so the table holds those 7 bits
  // {b63, b31, b15, b7, b3, b1, b0} instead of 64
  function [6:0] rcb(input [4:0] r);
    case (r)
      5'd0:     rcb = 7'h01; 5'd1:     rcb = 7'h1A; 5'd2:     rcb = 7'h5E; 5'd3:     rcb = 7'h70;
      5'd4:     rcb = 7'h1F; 5'd5:     rcb = 7'h21; 5'd6:     rcb = 7'h79; 5'd7:     rcb = 7'h55;
      5'd8:     rcb = 7'h0E; 5'd9:     rcb = 7'h0C; 5'd10:    rcb = 7'h35; 5'd11:    rcb = 7'h26;
      5'd12:    rcb = 7'h3F; 5'd13:    rcb = 7'h4F; 5'd14:    rcb = 7'h5D; 5'd15:    rcb = 7'h53;
      5'd16:    rcb = 7'h52; 5'd17:    rcb = 7'h48; 5'd18:    rcb = 7'h16; 5'd19:    rcb = 7'h66;
      5'd20:    rcb = 7'h79; 5'd21:    rcb = 7'h58; 5'd22:    rcb = 7'h21; default:  rcb = 7'h74;
    endcase
  endfunction

  function [15:0] rcw(input [4:0] r, input [1:0] k);   // word k of the round constant
    reg [6:0] c;
    begin
      c = rcb(r);
      case (k)
        2'd0:    rcw = {c[4], 7'd0, c[3], 3'd0, c[2], 1'b0, c[1], c[0]};   // bits 15, 7, 3, 1, 0
        2'd1:    rcw = {c[5], 15'd0};                                      // bit 31
        2'd2:    rcw = 16'd0;
        default: rcw = {c[6], 15'd0};                                      // bit 63
      endcase
    end
  endfunction

  // rotation offset of lane i = x + 5y (FIPS 202 Table 2)
  function [5:0] rho(input [4:0] i);
    case (i)
      5'd0:  rho = 6'd0;   5'd1:  rho = 6'd1;   5'd2:  rho = 6'd62;  5'd3:  rho = 6'd28;  5'd4:  rho = 6'd27;
      5'd5:  rho = 6'd36;  5'd6:  rho = 6'd44;  5'd7:  rho = 6'd6;   5'd8:  rho = 6'd55;  5'd9:  rho = 6'd20;
      5'd10: rho = 6'd3;   5'd11: rho = 6'd10;  5'd12: rho = 6'd43;  5'd13: rho = 6'd25;  5'd14: rho = 6'd39;
      5'd15: rho = 6'd41;  5'd16: rho = 6'd45;  5'd17: rho = 6'd15;  5'd18: rho = 6'd21;  5'd19: rho = 6'd8;
      5'd20: rho = 6'd18;  5'd21: rho = 6'd2;   5'd22: rho = 6'd61;  5'd23: rho = 6'd56;  default: rho = 6'd14;
    endcase
  endfunction

  // pi: lane (x, y) = x + 5y goes to (y, 2x + 3y), index y + 5((2x + 3y) mod 5)
  function [4:0] pdst(input [4:0] i);
    case (i)
      5'd0:  pdst = 5'd0;  5'd1:  pdst = 5'd10; 5'd2:  pdst = 5'd20; 5'd3:  pdst = 5'd5;  5'd4:  pdst = 5'd15;
      5'd5:  pdst = 5'd16; 5'd6:  pdst = 5'd1;  5'd7:  pdst = 5'd11; 5'd8:  pdst = 5'd21; 5'd9:  pdst = 5'd6;
      5'd10: pdst = 5'd7;  5'd11: pdst = 5'd17; 5'd12: pdst = 5'd2;  5'd13: pdst = 5'd12; 5'd14: pdst = 5'd22;
      5'd15: pdst = 5'd23; 5'd16: pdst = 5'd8;  5'd17: pdst = 5'd18; 5'd18: pdst = 5'd3;  5'd19: pdst = 5'd13;
      5'd20: pdst = 5'd14; 5'd21: pdst = 5'd24; 5'd22: pdst = 5'd9;  5'd23: pdst = 5'd19; default: pdst = 5'd4;
    endcase
  endfunction

  // funnel shift: bits [31:16] of {cur, prv} << s (word k of a lane rotated by
  // 16 q + s, from input words k - q (cur) and k - q - 1 (prv))
  function [15:0] fsh(input [15:0] cur, input [15:0] prv, input [3:0] s);
    reg [31:0] t;
    begin
      t = {cur, prv};
      if (s[0]) t = t << 1;
      if (s[1]) t = t << 2;
      if (s[2]) t = t << 4;
      if (s[3]) t = t << 8;
      fsh = t[31:16];
    end
  endfunction

  function [2:0] m5(input [3:0] v);     // v mod 5 for v < 10
    m5 = (v >= 4'd5) ? v - 4'd5 : v[2:0];
  endfunction

  function [4:0] lidx(input [2:0] x, input [2:0] y);   // x + 5y
    lidx = {2'b00, x} + {y, 2'b00} + {2'b00, y};
  endfunction

  function [2:0] lo(input [2:0] k);     // chi lane order 0, 2, 4, 1, 3
    lo = m5({k, 1'b0});
  endfunction

  localparam [5:0] LC = 6'd25, LB = 6'd32, LD = 6'd58;    // lane bases (C, B, D)

  // ---- state -----------------------------------------------------------------------
  localparam [3:0] K_IDLE = 4'd0, K_WIPE = 4'd1, K_LA = 4'd2, K_LR = 4'd3,
                   K_C    = 4'd4, K_D    = 4'd5, K_T  = 4'd6, K_RP = 4'd7, K_CHI = 4'd8;
  reg  [3:0]  ks;
  reg  [4:0]  rnd_i;      // round 0..23
  reg         mj;         // latched msk of the running permutation
  reg         clean;      // both RAMs hold only zeros
  reg  [7:0]  wcnt;       // wipe address
  // issue-stage counters
  reg         iss;
  reg  [2:0]  cx, cy, cj;
  reg  [1:0]  ck, cs;
  reg  [3:0]  cm;
  reg  [4:0]  ci;
  reg  [4:0]  lsel;       // word port: the lane
  reg  [1:0]  lk;         // ... and the word
  // data stage (the read issued last clock)
  reg         dv;
  reg  [2:0]  dx, dy;
  reg  [1:0]  dk;
  reg  [3:0]  dm;
  reg  [4:0]  di;
  // per-share registers
  reg  [15:0] T0, T1;              // C parity / rol(C, 1) / D word
  reg         cb0, cb1;            // D: bit 15 of the previous C word
  reg  [15:0] P0, P1;              // RP: the previous input word
  reg  [15:0] X0r, X1r, Y0r, Y1r;  // chi: DOM operands
  reg  [15:0] d00, d01, d10, d11;  // chi: DOM partial products
  reg         wbv;                 // chi: write-back pending (this clock)
  reg  [4:0]  wbl;
  reg  [1:0]  wbk;
  reg  [15:0] apv0, apv1;          // absorb: the word to XOR in

  wire        use1 = M1 && mj;
  wire [15:0] rr   = use1 ? rnd[15:0] : 16'd0;
  wire        dom_now = (ks == K_CHI) && (cs == 2'd3);
  assign rnd_take = dom_now && use1;
  assign rdy  = (ks == K_IDLE) && !wbv && !(clr && !clean);
  assign busy = go | (ks != K_IDLE) | wbv | (clr && !clean);
  assign rd_v0 = q0;
  assign rd_v1 = M1 ? q1 : 16'd0;

  // ---- RAMs: one per share ---------------------------------------------------------
  reg         re, we;
  reg  [7:0]  ra, wa;
  reg  [15:0] wd0, wd1;
  wire [15:0] q0, q1;
  // share 1 is clocked only when it can hold data: lane port / wipe, or a masked
  // permutation (an unmasked one's last write-back lands in K_IDLE: not on share 1)
  wire        en1 = M1 && (mj || (ks == K_WIPE) || (ks == K_LA) || (ks == K_LR));

  pqse_ram_1r1w #(.AW(8), .DW(16), .RAMSTYLE(2)) u_s0 (
    .clk(clk), .we(we), .waddr(wa), .wdata(wd0), .re(re), .raddr(ra), .rdata(q0));
  generate
    if (M1) begin : g_s1
      pqse_ram_1r1w #(.AW(8), .DW(16), .RAMSTYLE(2)) u_s1 (
        .clk(clk), .we(we & en1), .waddr(wa), .wdata(wd1), .re(re & en1), .raddr(ra), .rdata(q1));
    end else begin : g_n1
      assign q1 = 16'd0;
    end
  endgenerate

  // ---- addresses of the passes ------------------------------------------------------
  wire [2:0]  chx  = lo(cj);                          // chi: the lane of this slot
  wire [2:0]  chx1 = m5({1'b0, chx} + 4'd1);
  wire [2:0]  chx2 = m5({1'b0, chx} + 4'd2);
  wire [1:0]  rpq  = rho(ci) >> 4;                    // RP issue: word offset of the rotation
  wire [3:0]  rps  = rho(di);                         // RP data: bit offset (low 4 bits)
  wire [5:0]  rpd  = LB + {1'b0, pdst(di)};           // RP data: destination lane
  wire [15:0] iota = (wbv && wbl == 5'd0) ? rcw(rnd_i, wbk) : 16'd0;
  wire        d_odd = dm[0];
  wire [1:0]  dke  = (dm[2:0] - 3'd2) >> 1;           // D: word of an even data step

  always @* begin
    re = 1'b0; ra = 8'd0; we = 1'b0; wa = 8'd0; wd0 = 16'd0; wd1 = 16'd0;
    // ---- write port (one source per clock) ----
    if (wbv) begin                                      // chi write-back
      we = 1'b1; wa = {1'b0, wbl, wbk};
      wd0 = q0 ^ d00 ^ d01 ^ iota;
      wd1 = q1 ^ d11 ^ d10;
    end else if (ks == K_WIPE) begin                    // zeros
      we = 1'b1; wa = wcnt;
    end else if (dv) begin
      case (ks)
        K_LA: begin                                     // absorb: word ^ v
          we = 1'b1; wa = {1'b0, lsel, lk};
          wd0 = q0 ^ apv0; wd1 = q1 ^ apv1;
        end
        K_C: if (dy == 3'd4) begin                      // C[x][k] = parity ^ A[x + 20][k]
          we = 1'b1; wa = {LC + {3'd0, dx}, dk};
          wd0 = T0 ^ q0; wd1 = T1 ^ q1;
        end
        K_D: if (!d_odd && dm != 4'd0) begin            // D[x][k] = rol(C[x+1],1)[k] ^ C[x-1][k]
          we = 1'b1; wa = {LD + {3'd0, dx}, dke};
          wd0 = T0 ^ q0; wd1 = T1 ^ q1;
        end
        K_T: if (dm != 4'd0) begin                      // A ^= D
          we = 1'b1; wa = {1'b0, lidx(dx, dm[2:0] - 3'd1), dk};
          wd0 = T0 ^ q0; wd1 = T1 ^ q1;
        end
        K_RP: if (dm != 4'd0) begin                     // B[pi] word dm-1 = rotated
          we = 1'b1; wa = {rpd, dm[1:0] - 2'd1};
          wd0 = fsh(q0, P0, rps); wd1 = fsh(q1, P1, rps);
        end
        default: ;
      endcase
    end
    // ---- read port ----
    case (ks)
      K_WIPE:                                           // last clock: word 0 (zero by now) into
        if (wcnt == 8'd255) begin re = 1'b1; ra = 8'd0; end   // the output registers
      K_LA, K_LR:
        if (iss) begin re = 1'b1; ra = {1'b0, lsel, lk}; end
      K_C:
        if (iss) begin re = 1'b1; ra = {1'b0, lidx(cx, cy), ck}; end
      K_D:
        if (iss) begin
          re = 1'b1;
          if (cm == 4'd0)   ra = {LC + {3'd0, m5({1'b0, cx} + 4'd1)}, 2'd3};          // C[x+1][3]
          else if (cm[0])   ra = {LC + {3'd0, m5({1'b0, cx} + 4'd1)}, cm[2:1]};       // C[x+1][k]
          else              ra = {LC + {3'd0, m5({1'b0, cx} + 4'd4)}, cm[2:1] - 2'd1}; // C[x-1][k]
        end
      K_T:
        if (iss) begin
          re = 1'b1;
          ra = (cm == 4'd0) ? {LD + {3'd0, cx}, ck}                                  // D[x][k]
                            : {1'b0, lidx(cx, cm[2:0] - 3'd1), ck};                  // A[x + 5y][k]
        end
      K_RP:
        if (iss) begin re = 1'b1; ra = {1'b0, ci, cm[1:0] - rpq - 2'd1}; end
      K_CHI:
        if (cs != 2'd3) begin
          re = 1'b1;
          ra = {LB + {1'b0, lidx((cs == 2'd0) ? chx1 : (cs == 2'd1) ? chx2 : chx, cy)}, ck};
        end
      default: ;
    endcase
  end

  // ---- control and registers --------------------------------------------------------------
  always @(posedge clk) begin
    if (rst) begin
      ks <= K_IDLE; mj <= 1'b0; clean <= 1'b0; wbv <= 1'b0; dv <= 1'b0; iss <= 1'b0;
      apv0 <= 16'd0; apv1 <= 16'd0;
      T0 <= 16'd0; T1 <= 16'd0; P0 <= 16'd0; P1 <= 16'd0; cb0 <= 1'b0; cb1 <= 1'b0;
      X0r <= 16'd0; X1r <= 16'd0; Y0r <= 16'd0; Y1r <= 16'd0;
      d00 <= 16'd0; d01 <= 16'd0; d10 <= 16'd0; d11 <= 16'd0;
    end else begin
      // chi: Y and the products load every clock (their value in their clock, else 0)
      Y0r <= 16'd0; Y1r <= 16'd0;
      d00 <= 16'd0; d01 <= 16'd0; d10 <= 16'd0; d11 <= 16'd0;
      if (dom_now) begin
        d00 <= X0r & Y0r;
        d01 <= (X0r & Y1r) ^ rr;
        d10 <= (X1r & Y0r) ^ rr;
        d11 <= X1r & Y1r;
      end
      wbv <= 1'b0;

      case (ks)
        K_IDLE: begin
          if (go && rdy) begin
            ks    <= K_C;
            mj    <= msk;
            rnd_i <= 5'd0;
            clean <= 1'b0;
            cx <= 3'd0; cy <= 3'd0; ck <= 2'd0;
            iss <= 1'b1; dv <= 1'b0;
          end else if (ax_en && rdy) begin
            ks    <= K_LA;
            lsel  <= ax_idx;
            lk    <= ax_k;
            apv0  <= ax_v0;
            apv1  <= M1 ? ax_v1 : 16'd0;
            clean <= 1'b0;
            iss <= 1'b1; dv <= 1'b0;
          end else if (rd_en && rdy) begin
            ks    <= K_LR;
            lsel  <= rd_idx;
            lk    <= rd_k;
            iss <= 1'b1; dv <= 1'b0;
          end else if (clr && !clean && !wbv) begin
            ks   <= K_WIPE;
            wcnt <= 8'd0;
          end
        end

        K_WIPE: begin
          wcnt <= wcnt + 8'd1;
          T0 <= 16'd0; T1 <= 16'd0; P0 <= 16'd0; P1 <= 16'd0; cb0 <= 1'b0; cb1 <= 1'b0;
          apv0 <= 16'd0; apv1 <= 16'd0;
          if (wcnt == 8'd255) begin
            ks    <= K_IDLE;
            clean <= 1'b1;
          end
        end

        // ---- word port: an absorb reads the word, then writes it ^ v (2 clocks);
        // a read only reads it (the word is on q0 / q1 from the next clock) ----
        K_LA: begin
          iss <= 1'b0;
          dv  <= iss;
          if (dv) begin                                   // written this clock
            apv0 <= 16'd0; apv1 <= 16'd0;
            ks   <= K_IDLE;
            dv   <= 1'b0;
          end
        end
        K_LR: begin
          iss <= 1'b0;
          ks  <= K_IDLE;
        end

        // ---- theta 1: column parities C[x][k] ----
        K_C: begin
          if (iss) begin
            if (cy == 3'd4) begin
              cy <= 3'd0;
              ck <= ck + 2'd1;
              if (ck == 2'd3 && cx == 3'd4) iss <= 1'b0;
              else if (ck == 2'd3) cx <= cx + 3'd1;
            end else begin
              cy <= cy + 3'd1;
            end
          end
          dv <= iss; dx <= cx; dy <= cy; dk <= ck;
          if (dv) begin
            T0 <= (dy == 3'd0) ? q0 : (T0 ^ q0);
            T1 <= (dy == 3'd0) ? q1 : (T1 ^ q1);
            if (dx == 3'd4 && dk == 2'd3 && dy == 3'd4) begin   // C[4][3] written this clock
              ks <= K_D;
              cx <= 3'd0; cm <= 4'd0;
              iss <= 1'b1; dv <= 1'b0;
            end
          end
        end

        // ---- theta 2: D[x] = C[x-1] ^ rol(C[x+1], 1), 9 reads per column ----
        K_D: begin
          if (iss) begin
            if (cm == 4'd8) begin
              cm <= 4'd0;
              if (cx == 3'd4) iss <= 1'b0; else cx <= cx + 3'd1;
            end else begin
              cm <= cm + 4'd1;
            end
          end
          dv <= iss; dx <= cx; dm <= cm;
          if (dv) begin
            if (dm == 4'd0) begin                         // C[x+1][3]: its top bit
              cb0 <= q0[15]; cb1 <= q1[15];
            end else if (d_odd) begin                     // C[x+1][k]: rol by 1 into T
              T0 <= {q0[14:0], cb0}; T1 <= {q1[14:0], cb1};
              cb0 <= q0[15];         cb1 <= q1[15];
            end
            if (dx == 3'd4 && dm == 4'd8) begin           // D[4][3] written this clock
              ks <= K_T;
              cx <= 3'd0; ck <= 2'd0; cm <= 4'd0;
              iss <= 1'b1; dv <= 1'b0;
            end
          end
        end

        // ---- theta 3: A ^= D, per column and word: D word, then the 5 lanes ----
        K_T: begin
          if (iss) begin
            if (cm == 4'd5) begin
              cm <= 4'd0;
              ck <= ck + 2'd1;
              if (ck == 2'd3 && cx == 3'd4) iss <= 1'b0;
              else if (ck == 2'd3) cx <= cx + 3'd1;
            end else begin
              cm <= cm + 4'd1;
            end
          end
          dv <= iss; dx <= cx; dk <= ck; dm <= cm;
          if (dv) begin
            if (dm == 4'd0) begin T0 <= q0; T1 <= q1; end // the D word
            if (dx == 3'd4 && dk == 2'd3 && dm == 4'd5) begin
              ks <= K_RP;
              ci <= 5'd0; cm <= 4'd0;
              iss <= 1'b1; dv <= 1'b0;
            end
          end
        end

        // ---- rho + pi: per lane 5 reads (words k-q-1 .. k-q+3), 4 writes ----
        K_RP: begin
          if (iss) begin
            if (cm == 4'd4) begin
              cm <= 4'd0;
              if (ci == 5'd24) iss <= 1'b0; else ci <= ci + 5'd1;
            end else begin
              cm <= cm + 4'd1;
            end
          end
          dv <= iss; di <= ci; dm <= cm;
          if (dv) begin
            P0 <= q0; P1 <= q1;                           // the previous input word
            if (di == 5'd24 && dm == 4'd4) begin          // B[pi(24)][3] written this clock
              ks <= K_CHI;
              cy <= 3'd0; ck <= 2'd0; cj <= 3'd0; cs <= 2'd0;
              dv <= 1'b0;
              T0 <= 16'd0; T1 <= 16'd0; P0 <= 16'd0; P1 <= 16'd0;
            end
          end
        end

        // ---- chi + iota: per plane, word, lane slot: 4 clocks ----
        K_CHI: begin
          case (cs)
            2'd0: cs <= 2'd1;
            2'd1: begin                                  // X = ~B[x+1] (NOT on share 0 only)
              X0r <= ~q0;
              X1r <= use1 ? q1 : 16'd0;
              cs  <= 2'd2;
            end
            2'd2: begin                                  // Y = B[x+2]
              Y0r <= q0;
              Y1r <= use1 ? q1 : 16'd0;
              cs  <= 2'd3;
            end
            default: begin                               // the AND (above); write-back next clock
              X0r <= 16'd0;
              X1r <= 16'd0;
              wbv <= 1'b1;
              wbl <= lidx(chx, cy);
              wbk <= ck;
              cs  <= 2'd0;
              if (cj == 3'd4) begin
                cj <= 3'd0;
                ck <= ck + 2'd1;
                if (ck == 2'd3) begin
                  if (cy == 3'd4) begin                  // round complete
                    cy <= 3'd0;
                    if (rnd_i == 5'd23) begin
                      ks <= K_IDLE;
                    end else begin
                      rnd_i <= rnd_i + 5'd1;
                      ks    <= K_C;
                      cx <= 3'd0; ck <= 2'd0;
                      iss <= 1'b1; dv <= 1'b0;
                    end
                  end else begin
                    cy <= cy + 3'd1;
                  end
                end
              end else begin
                cj <= cj + 3'd1;
              end
            end
          endcase
        end

        default: ks <= K_IDLE;
      endcase
    end
  end
endmodule
