// -----------------------------------------------------------------------------
// pqse_poly.v - polynomial unit of the PQSE secure element (v1.5): ONE modular
// multiplier, one butterfly, one RAM read port and one write port.
//
//   op NTT    c          in place, 7 layers x 64 groups; a group = words w and
//                        w + 2^p (2 butterflies), 1 butterfly per clock,
//                        ~138 clocks per layer, ~970 per transform
//   op INTT   c          same, Gentleman-Sande butterflies that halve their
//                        outputs (7 halvings = the 1/128 factor of Alg. 10)
//   op PWM    c a b      c = (acc ? c : 0) + a o b (FIPS 203 Alg. 11/12), one
//                        coefficient pair per 4 clocks, ~524 clocks (v4: 6
//                        clocks, ~780). Karatsuba: 4 multiplications per pair
//                        instead of 5 on the shared multiplier,
//                          m1 = a0 b0, m2 = a1 b1, m3 = (a0 + a1)(b0 + b1),
//                          m5 = m2 gamma
//                          c0' = c0 + m1 + m5,  c1' = c1 + m3 - m1 - m2
//                        so the multiplier is busy in every clock of a pair.
//   op ADD/SUB c a       c = c +/- a, one word per 2 clocks
//   op MSPLIT c a        arithmetic masking: R = random mod q per coefficient,
//                        c := c - R, a := R (one word per 4 clocks; the two
//                        share writes are separated by an idle clock)
//   op ZERO   c          c := 0
//   op ZCHK   c a        FAULT (zfail) unless c + a = 0 mod q for every
//                        coefficient, one word per 2 clocks, nothing written.
//                        The KeyGen duplicate check: with x = (x0, x1) and
//                        y = (y0, y1) two sharings of one polynomial, c holds
//                        y0 - x0 (share 0 only, SUB) and a holds y1 - x1
//                        (share 1 only); if x = y these are r and -r, r = x1 - y1
//                        a difference of fresh masks, so c, a and their sum
//                        carry nothing about the polynomial
//
// Hiding (shuf = 1): the order of the words in PWM / ADD / SUB / MSPLIT is a
// fresh uniformly random permutation T (Fisher-Yates, pqse_perm.v, drawn by
// the sequencer before every instruction). Every NTT / INTT layer runs its 64
// butterfly groups in its own fresh uniformly random order: pqse_perm.v draws
// the next layer's order in the background, and at the end of a layer the
// unit flips to it ("next"), waiting for "ready" if needed. Each layer drains
// before the next starts, so any order is correct.
//
// Low power: every pipeline register is enabled only while its operation
// runs, operands are forced to zero outside their issue clocks, the RAM is
// read only in clocks that need the data.
// -----------------------------------------------------------------------------
module pqse_poly (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [3:0]  op_in,
  input  wire        acc_in,
  input  wire [4:0]  c_in,       // physical slots (pqse_core.v translates the microcode's)
  input  wire [4:0]  a_in,
  input  wire [4:0]  b_in,
  input  wire        shuf_in,
  output wire        busy,
  // polynomial RAM
  output reg         re,
  output reg  [11:0] raddr,      // {slot, word}
  input  wire [23:0] rdata,
  output reg         we,
  output reg  [11:0] waddr,
  output reg  [23:0] wdata,
  // randomness
  input  wire [63:0] rnd,
  output reg         rnd_take,
  // random permutation of this instruction / NTT layer (pqse_perm.v): pq_val = T[pq_idx]
  output wire [6:0]  pq_idx,
  input  wire [6:0]  pq_val,
  output wire        pq_next,   // NTT layer done: switch to the next layer's order
  input  wire        pq_ready,  // the next layer's order is complete
  output reg         zfail      // ZCHK: a word whose sum is not 0 (registered pulse)
);
  `include "pqse_defs.vh"
  `include "pqse_func.vh"

  reg        busy_r;
  reg [3:0]  op;
  reg        acc, shuf;
  reg [4:0]  cs, as_, bs_;
  reg [2:0]  p;          // NTT layer: word distance 2^p
  reg [7:0]  tc;         // clock within the NTT layer
  reg [7:0]  cur;        // word / pair counter (PWM, ADD, SUB, MSPLIT, ZERO)
  reg [2:0]  ph;         // phase within a word / pair
  reg [6:0]  kh1, kh2, kh3; // shuffled indices of the previous 1 / 2 / 3 items

  assign busy = start | busy_r;

  wire is_ntt = (op == P_NTT) || (op == P_INTT);
  wire intt   = (op == P_INTT);

  // ---- NTT addressing ------------------------------------------------------------
  // group g (0..63) -> shuffled g'; w = g' with a 0 inserted at bit p
  function [6:0] w_of(input [5:0] gs, input [2:0] pp);
    reg [7:0] g8, lowm, w8;
    begin
      g8   = {2'b00, gs};
      lowm = (8'd1 << pp) - 8'd1;
      w8   = ((g8 >> pp) << (pp + 3'd1)) | (g8 & lowm);
      w_of = w8[6:0];
    end
  endfunction
  function [11:0] z_of(input [5:0] gs, input [2:0] pp, input inv);
    reg [7:0] blk, zi;
    begin
      blk  = {2'b00, gs} >> pp;
      zi   = inv ? ((8'd2 << (3'd6 - pp)) - 8'd1 - blk) : ((8'd1 << (3'd6 - pp)) + blk);
      z_of = zeta(zi[6:0]);
    end
  endfunction

  // Group order of a layer: this layer's own Fisher-Yates permutation, g' = T[g]
  wire [5:0] g_rd  = shuf ? pq_val[5:0] : tc[6:1];              // group being read (tc < 128)
  // the staged / written groups are the read group 2, 9 and 10 clocks ago:
  // a delay line instead of three more permutation lookups
  reg  [5:0] gd1, gd2, gd3, gd4, gd5, gd6, gd7, gd8, gd9, gd10;
  wire [5:0] g_st  = gd2;                                       // group staged (tc even 2..128)
  wire [5:0] g_w1  = gd9;                                       // group whose word w is written
  wire [5:0] g_w2  = gd10;                                      // group whose word w+2^p is written
  wire [6:0] wr_w  = w_of(g_rd, p);
  wire [6:0] wr_w2 = wr_w | (7'd1 << p);

  // ---- butterfly with the shared multiplier ------------------------------------------
  reg  [23:0] wq;                 // word w (captured)
  reg  [11:0] a0r, a1r, b0r, b1r, zr;
  reg  [11:0] fa, fb, fz;         // butterfly inputs this clock (0 when idle)
  reg  [11:0] ad1, ad2, ad3, ad4; // NTT: a delayed to the product
  reg  [11:0] s1, s2, s3, s4, s5; // INTT: (a+b)/2 delayed
  reg  [11:0] d1, z1;             // INTT: (b-a)/2 and zeta, one clock later
  reg  [11:0] o_add, o_sub;
  reg  [11:0] o0a, o0b, o1b;      // outputs held for the two-word write
  reg  [11:0] ma, mb;             // multiplier inputs
  wire [11:0] mr;
  wire        m_en = busy_r && ((op == P_NTT) || (op == P_INTT) || (op == P_PWM));

  pqse_mulred u_mul (.clk(clk), .en(m_en), .a(ma), .b(mb), .r(mr));

  wire        feed0 = is_ntt && tc[0]  && (tc >= 8'd3) && (tc <= 8'd129);
  wire        feed1 = is_ntt && !tc[0] && (tc >= 8'd4) && (tc <= 8'd130);
  wire [11:0] bf_oa = intt ? s5 : o_add;
  wire [11:0] bf_ob = intt ? mr : o_sub;

  // ---- PWM operand registers ------------------------------------------------------------
  reg  [23:0] aq, bq, cq;
  reg  [11:0] e1, o1;            // PWM pair n-2: c0 + m1, c1 + m3 - m1 - m2
  reg  [11:0] t1, g2;            // PWM: m1 of pair n-2, m2 of pair n-1 / n-2 (see below)
  reg  [11:0] pe1b, po1b;        // PWM pair n-3, waiting for m5 and its write
  reg  [23:0] rsh;               // MSPLIT: share-1 word waiting to be written
  reg  [11:0] R0, R1;
  wire [11:0] rq0, rq1;
  pqse_modq24 u_r0 (.x(rnd[23:0]),  .r(rq0));
  pqse_modq24 u_r1 (.x(rnd[47:24]), .r(rq1));

  wire [6:0]  kcur  = shuf ? pq_val : cur[6:0];                       // word order: T[cur]
  assign pq_idx = is_ntt ? {1'b0, tc[6:1]} : cur[6:0];
  wire        cur_v = (cur < 8'd128);
  wire        prv_v = (cur >= 8'd1) && (cur <= 8'd128);
  wire        pp_v  = (cur >= 8'd2) && (cur <= 8'd129);
  wire        p3_v  = (cur >= 8'd3) && (cur <= 8'd130);
  // gamma of the pair m5 is computed for (PWM: pair cur - 2, index kh2)
  wire [11:0] gz    = zeta({1'b1, kh2[6:1]});
  wire [11:0] gam   = kh2[0] ? negq(gz) : gz;
  // Karatsuba sums of the pair in aq / bq (only fed to the multiplier in its clock)
  wire [11:0] asum  = addq(aq[11:0], aq[23:12]);
  wire [11:0] bsum  = addq(bq[11:0], bq[23:12]);

  wire [2:0] ph_last = (op == P_PWM) ? 3'd3 : (op == P_MSPLIT) ? 3'd3 :
                       ((op == P_ADD) || (op == P_SUB) || (op == P_ZCHK)) ? 3'd1 : 3'd0;
  wire [7:0] cur_last = (op == P_PWM) ? 8'd130 : (op == P_ZERO) ? 8'd127 : 8'd128;
  wire       ntt_last = intt ? (p == 3'd6) : (p == 3'd0);
  // end of a layer: flip to the next layer's order (pqse_perm.v); hold at
  // tc = 136 while it is not complete (that clock only repeats an idempotent write)
  wire       lay_end  = busy_r && is_ntt && (tc == 8'd136) && !ntt_last;
  wire       hold     = lay_end && shuf && !pq_ready;
  assign     pq_next  = lay_end && shuf && pq_ready;

  // ---- combinational: RAM ports, multiplier inputs, butterfly inputs --------------------------
  always @* begin
    re = 1'b0; raddr = 12'd0;
    we = 1'b0; waddr = 12'd0; wdata = 24'd0;
    ma = 12'd0; mb = 12'd0;
    fa = 12'd0; fb = 12'd0; fz = 12'd0;
    rnd_take = 1'b0;                     // (MSPLIT masks below; orders come from pqse_perm.v)
    if (busy_r) begin
      case (op)
        P_NTT, P_INTT: begin
          if (tc < 8'd128) begin
            re    = 1'b1;
            raddr = {cs, tc[0] ? wr_w2 : wr_w};
          end
          if (feed0) begin fa = a0r; fb = b0r; fz = zr; end
          if (feed1) begin fa = a1r; fb = b1r; fz = zr; end
          if (intt) begin ma = z1; mb = d1; end
          else      begin ma = fz; mb = fb; end
          if (tc[0] && tc >= 8'd9 && tc <= 8'd135) begin
            we    = 1'b1;
            waddr = {cs, w_of(g_w1, p)};
            wdata = {bf_oa, o0a};
          end
          if (!tc[0] && tc >= 8'd10 && tc <= 8'd136) begin
            we    = 1'b1;
            waddr = {cs, w_of(g_w2, p) | (7'd1 << p)};
            wdata = {o1b, o0b};
          end
        end
        // PWM, Karatsuba, 4 clocks per pair. In pass (= cur) n:
        //   ph 0  read a_n            multiply m1 = a0 b0      of pair n-1
        //   ph 1  read b_n            multiply m3 = (a0+a1)(b0+b1) of pair n-1
        //   ph 2  read c_(n-1)        multiply m5 = m2 gamma   of pair n-2
        //         write pair n-3: c0' = (c0 + m1 + m5), c1' = (c1 + m3 - m1 - m2)
        //   ph 3                      multiply m2 = a1 b1      of pair n
        // aq / bq hold pair n-1 in ph 0 / ph 1 and pair n from ph 2 / ph 3 on; the
        // multiplier (latency 4) is busy in every clock and returns a product four
        // clocks after it was issued (see the datapath block for the sums).
        P_PWM: begin
          case (ph)
            3'd0: begin
              if (cur_v) begin re = 1'b1; raddr = {as_, kcur}; end
              if (prv_v) begin ma = aq[11:0]; mb = bq[11:0]; end          // m1 (pair n-1)
            end
            3'd1: begin
              if (cur_v) begin re = 1'b1; raddr = {bs_, kcur}; end
              if (prv_v) begin ma = asum; mb = bsum; end                  // m3 (pair n-1)
            end
            3'd2: begin
              if (prv_v && acc) begin re = 1'b1; raddr = {cs, kh1}; end  // c of pair n-1
              if (pp_v) begin ma = g2; mb = gam; end                      // m5 (pair n-2)
              if (p3_v) begin
                we    = 1'b1;
                waddr = {cs, kh3};
                wdata = {po1b, addq(pe1b, mr)};                           // + m5 (pair n-3)
              end
            end
            3'd3: if (cur_v) begin ma = aq[23:12]; mb = bq[23:12]; end    // m2 (pair n)
            default: ;
          endcase
        end
        P_ADD, P_SUB: begin
          if (ph == 3'd0 && cur_v) begin re = 1'b1; raddr = {cs, kcur}; end
          if (ph == 3'd1 && cur_v) begin re = 1'b1; raddr = {as_, kcur}; end
          if (ph == 3'd1 && prv_v) begin we = 1'b1; waddr = {cs, kh1}; wdata = rsh; end
        end
        P_MSPLIT: begin
          if (ph == 3'd0 && cur_v) begin re = 1'b1; raddr = {cs, kcur}; end
          if (ph == 3'd0 && prv_v) begin we = 1'b1; waddr = {as_, kh1}; wdata = rsh; end
          if (ph == 3'd1 && cur_v) rnd_take = 1'b1;
          if (ph == 3'd2 && cur_v) begin
            we    = 1'b1;
            waddr = {cs, kcur};
            wdata = {subq(cq[23:12], R1), subq(cq[11:0], R0)};
          end
        end
        P_ZERO: if (cur_v) begin we = 1'b1; waddr = {cs, cur[6:0]}; wdata = 24'd0; end
        P_ZCHK: begin                    // c word, then a word (the sum one clock later)
          if (ph == 3'd0 && cur_v) begin re = 1'b1; raddr = {cs, kcur}; end
          if (ph == 3'd1 && cur_v) begin re = 1'b1; raddr = {as_, kcur}; end
        end
        default: ;
      endcase
    end
  end

  // ---- control ---------------------------------------------------------------------------
  always @(posedge clk) begin
    if (rst) begin
      busy_r <= 1'b0;
    end else if (start) begin
      op     <= op_in;
      acc    <= acc_in;
      shuf   <= shuf_in;
      cs     <= c_in;
      as_    <= a_in;
      bs_    <= b_in;
      busy_r <= 1'b1;
      tc     <= 8'd0;
      cur    <= 8'd0;
      ph     <= 3'd0;
      p      <= (op_in == P_INTT) ? 3'd0 : 3'd6;
    end else if (busy_r) begin
      if (is_ntt) begin
        if (hold) begin
          // wait for the next layer's order
        end else if (tc == 8'd136) begin
          tc <= 8'd0;
          if (ntt_last) busy_r <= 1'b0;
          else p <= intt ? p + 3'd1 : p - 3'd1;
        end else begin
          tc <= tc + 8'd1;
        end
      end else begin
        if (ph == ph_last) begin
          ph <= 3'd0;
          if (cur == cur_last) busy_r <= 1'b0;
          cur <= cur + 8'd1;
          kh3 <= kh2;
          kh2 <= kh1;
          kh1 <= kcur;
        end else begin
          ph <= ph + 3'd1;
        end
      end
    end
  end

  // ---- datapath registers ---------------------------------------------------------------------
  // Precharge: every value register is cleared when an instruction starts and
  // held at 0 while the unit is idle. Consecutive instructions often work on
  // the two shares of one polynomial (NTT of share 0, then of share 1; PWM
  // with share 0, then with share 1); in random word order the last word of
  // one and the first word of the next can be the same coefficient, and a
  // register going straight from one share to the other would combine them (a
  // transition); and while idle, the registers fed by the RAM read bus would
  // sit next to whatever other engines put on that bus. (The multiplier
  // pipeline gets zero operands in the first clocks of every instruction.)
  // Low power: cleared at a start and once when the unit goes idle (or in
  // reset), then held at 0 - not reloaded every idle clock, so the clock of the
  // idle unit can be gated (nothing loads them while idle).
  // ZCHK: c word (cq) + a word (on rdata, read the clock before) of the previous
  // item; operands 0 outside ZCHK (no adder activity in the other operations)
  wire        zon  = busy_r && (op == P_ZCHK);
  wire [23:0] zc   = cq & {24{zon}};
  wire [23:0] za   = rdata & {24{zon}};
  wire        zne  = (addq(zc[11:0], za[11:0]) != 12'd0) || (addq(zc[23:12], za[23:12]) != 12'd0);
  always @(posedge clk) begin
    if (rst) zfail <= 1'b0;
    else     zfail <= zon && (ph == 3'd0) && prv_v && zne;
  end

  reg        busy_q;
  always @(posedge clk) busy_q <= busy_r;

  wire       clr_v = start || rst || (!busy_r && busy_q);

  // cq (the c word: PWM accumulator input, ADD / SUB / MSPLIT / ZCHK operand) and
  // rsh (the word ADD / SUB / MSPLIT write) in their own blocks, each with one
  // load condition: plain enable flip-flops, clock-gated in every other clock
  // (low power; the same values as before, clock by clock)
  wire        cq_ld = busy_r &&
                      (((op == P_PWM) && (ph == 3'd3) && prv_v) ||       // c of pair n-1
                       (cur_v && ((op == P_ADD) || (op == P_SUB) || (op == P_MSPLIT) || (op == P_ZCHK)) &&
                        (ph == 3'd1)));
  wire        rs_as = busy_r && ((op == P_ADD) || (op == P_SUB)) && (ph == 3'd0) && prv_v;
  wire        rs_ms = busy_r && (op == P_MSPLIT) && (ph == 3'd2) && cur_v;
  always @(posedge clk) begin
    if (clr_v || cq_ld)
      cq <= (clr_v || ((op == P_PWM) && !acc)) ? 24'd0 : rdata;
    if (clr_v || rs_as || rs_ms)                       // ADD / SUB: rdata = a word of the previous item
      rsh <= clr_v ? 24'd0 :
             rs_ms ? {R1, R0} :
             (op == P_SUB) ? {subq(cq[23:12], rdata[23:12]), subq(cq[11:0], rdata[11:0])}
                           : {addq(cq[23:12], rdata[23:12]), addq(cq[11:0], rdata[11:0])};
  end
  always @(posedge clk) begin
    if (clr_v) begin
      wq  <= 24'd0;  a0r <= 12'd0; a1r <= 12'd0; b0r <= 12'd0; b1r <= 12'd0; zr <= 12'd0;
      ad1 <= 12'd0;  ad2 <= 12'd0; ad3 <= 12'd0; ad4 <= 12'd0;
      s1  <= 12'd0;  s2  <= 12'd0; s3  <= 12'd0; s4  <= 12'd0; s5 <= 12'd0;
      d1  <= 12'd0;  z1  <= 12'd0; o_add <= 12'd0; o_sub <= 12'd0;
      o0a <= 12'd0;  o0b <= 12'd0; o1b <= 12'd0;
      aq  <= 24'd0;  bq  <= 24'd0; e1 <= 12'd0; o1 <= 12'd0;
      t1  <= 12'd0;  g2  <= 12'd0; pe1b <= 12'd0; po1b <= 12'd0;
      R0  <= 12'd0;  R1  <= 12'd0;                       // (cq, rsh: above)
    end else begin
    if (busy_r && is_ntt && !hold) begin
      gd1 <= g_rd; gd2 <= gd1; gd3 <= gd2; gd4 <= gd3; gd5 <= gd4;
      gd6 <= gd5;  gd7 <= gd6; gd8 <= gd7; gd9 <= gd8; gd10 <= gd9;
    end
    if (busy_r && is_ntt) begin
      if (tc[0] && tc <= 8'd127) wq <= rdata;
      if (!tc[0] && tc >= 8'd2 && tc <= 8'd128) begin
        a0r <= wq[11:0];     a1r <= wq[23:12];
        b0r <= rdata[11:0];  b1r <= rdata[23:12];
        zr  <= z_of(g_st, p, intt);
      end
      // NTT (CT): a delayed to the product z*b
      ad1 <= fa; ad2 <= ad1; ad3 <= ad2; ad4 <= ad3;
      o_add <= addq(ad4, mr);
      o_sub <= subq(ad4, mr);
      // INTT (GS): (a+b)/2 and (b-a)/2, product z*(b-a)/2 one clock later
      s1 <= halfq(addq(fa, fb));
      d1 <= halfq(subq(fb, fa));
      z1 <= fz;
      s2 <= s1; s3 <= s2; s4 <= s3; s5 <= s4;
      // butterfly 0 output (fed at odd tc, out 5 clocks later at even tc)
      if (!tc[0] && tc >= 8'd8 && tc <= 8'd134) begin
        o0a <= bf_oa;
        o0b <= bf_ob;
      end
      if (tc[0] && tc >= 8'd9 && tc <= 8'd135) o1b <= bf_ob;
    end
    // PWM sums. In pass n the multiplier output mr carries: ph 0 m1 of pair
    // n-2, ph 1 m3 of pair n-2, ph 2 m5 of pair n-3, ph 3 m2 of pair n-1; cq
    // holds c of pair n-2 (0 without acc) until the end of ph 3.
    if (busy_r && op == P_PWM) begin
      case (ph)
        3'd0: if (pp_v) begin
          e1 <= addq(cq[11:0], mr);                      // c0 + m1
          t1 <= mr;                                      // m1
        end
        3'd1: begin
          if (cur_v) aq <= rdata;                        // a_n
          if (pp_v) o1 <= subq(addq(cq[23:12], mr), t1); // c1 + m3 - m1
        end
        3'd2: begin
          if (cur_v) bq <= rdata;                        // b_n
          if (pp_v) o1 <= subq(o1, g2);                  // - m2 (g2: m2 of pair n-2 here)
        end
        3'd3: begin
          if (prv_v) g2 <= mr;                           // m2 of pair n-1
          if (pp_v) begin pe1b <= e1; po1b <= o1; end    // pair n-2 waits for m5
        end
        default: ;
      endcase
    end
    if (busy_r && op == P_MSPLIT && ph == 3'd1 && cur_v) begin
      R0 <= rq0;
      R1 <= rq1;
    end
    end
  end
endmodule
