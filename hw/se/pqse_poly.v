// -----------------------------------------------------------------------------
// pqse_poly.v - polynomial unit of the PQSE secure element: ONE modular
// multiplier, one butterfly, one RAM read port and one write port.
//
//   op NTT    c          in place, 7 layers x 64 groups; a group = words w and
//                        w + 2^p (2 butterflies), 1 butterfly per clock,
//                        ~138 clocks per layer, ~970 per transform
//   op INTT   c          same, Gentleman-Sande butterflies that halve their
//                        outputs (7 halvings = the 1/128 factor of Alg. 10)
//   op PWM    c a b      c = (acc ? c : 0) + a o b (FIPS 203 Alg. 11/12), one
//                        coefficient pair per 6 clocks (5 multiplications on
//                        the shared multiplier), ~780 clocks
//   op ADD/SUB c a       c = c +/- a, one word per 2 clocks
//   op MSPLIT c a        arithmetic masking: R = random mod q per coefficient,
//                        c := c - R, a := R (one word per 4 clocks; the two
//                        share writes are separated by an idle clock)
//   op ZERO   c          c := 0
//
// Hiding (shuf = 1): the order of the words in PWM / ADD / SUB / MSPLIT is a
// fresh uniformly random permutation T (Fisher-Yates, pqse_perm.v, drawn by
// the sequencer before every instruction). Every NTT / INTT layer runs its 64
// butterfly groups in its own fresh uniformly random order: pqse_perm.v draws
// the next layer's order in the background, and at the end of a layer the
// unit flips to it ("next"), waiting for "ready" if needed. Each layer drains
// before the next starts, so any order is correct.
//
// v5 (area): one zeta ROM with a registered read (block RAM / ROM) shared by
// the NTT and PWM, one "+ product" modular adder shared by the NTT's a + zb and
// PWM's four accumulations, and one add-or-subtract unit per coefficient for
// ADD / SUB / MSPLIT (instead of an adder and a subtractor each).
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
  input  wire [3:0]  c_in,
  input  wire [3:0]  a_in,
  input  wire [3:0]  b_in,
  input  wire        shuf_in,
  output wire        busy,
  // polynomial RAM
  output reg         re,
  output reg  [10:0] raddr,
  input  wire [23:0] rdata,
  output reg         we,
  output reg  [10:0] waddr,
  output reg  [23:0] wdata,
  // randomness
  input  wire [63:0] rnd,
  output reg         rnd_take,
  // random permutation of this instruction / NTT layer (pqse_perm.v): pq_val = T[pq_idx]
  output wire [6:0]  pq_idx,
  input  wire [6:0]  pq_val,
  output wire        pq_next,   // NTT layer done: switch to the next layer's order
  input  wire        pq_ready   // the next layer's order is complete
);
  `include "pqse_defs.vh"
  `include "pqse_func.vh"

  reg        busy_r;
  reg [3:0]  op;
  reg        acc, shuf;
  reg [3:0]  cs, as_, bs_;
  reg [2:0]  p;          // NTT layer: word distance 2^p
  reg [7:0]  tc;         // clock within the NTT layer
  reg [7:0]  cur;        // word / pair counter (PWM, ADD, SUB, MSPLIT, ZERO)
  reg [2:0]  ph;         // phase within a word / pair
  reg [6:0]  kh1, kh2;   // shuffled indices of the previous / second previous item

  assign busy = start | busy_r;

  wire is_ntt = (op == P_NTT) || (op == P_INTT);
  wire intt   = (op == P_INTT);

  // ---- NTT addressing ------------------------------------------------------------
  // group g (0..63) -> shuffled g'; w = g' with a 0 inserted at bit p
  // (per bit: below p the group's bit, at p a 0, above p the group's bit below;
  // a 2:1 choice per bit instead of two barrel shifters)
  function [6:0] w_of(input [5:0] gs, input [2:0] pp);
    reg [6:0] gl, gu;
    integer   b;
    begin
      gl = {1'b0, gs};            // bit b of the group
      gu = {gs, 1'b0};            // bit b - 1 of the group
      for (b = 0; b < 7; b = b + 1)
        w_of[b] = (b < pp) ? gl[b] : (b == pp) ? 1'b0 : gu[b];
    end
  endfunction
  function [6:0] zi_of(input [5:0] gs, input [2:0] pp, input inv);   // zeta index of group gs
    reg [7:0] blk, zi;
    begin
      blk   = {2'b00, gs} >> pp;
      zi    = inv ? ((8'd2 << (3'd6 - pp)) - 8'd1 - blk) : ((8'd1 << (3'd6 - pp)) + blk);
      zi_of = zi[6:0];
    end
  endfunction
  // x + y (sb = 0) or x - y (sb = 1) mod q: one adder / subtractor and one correction
  function [11:0] asq(input [11:0] x, input [11:0] y, input sb);
    reg [12:0] s, t;
    begin
      s   = sb ? ({1'b0, x} - {1'b0, y}) : ({1'b0, x} + {1'b0, y});
      t   = sb ? (s + 13'd3329) : (s - 13'd3329);
      asq = sb ? (s[12] ? t[11:0] : s[11:0]) : ((s >= 13'd3329) ? t[11:0] : s[11:0]);
    end
  endfunction

  // Group order of a layer: this layer's own Fisher-Yates permutation, g' = T[g]
  wire [5:0] g_rd  = shuf ? pq_val[5:0] : tc[6:1];              // group being read (tc < 128)
  // the staged / written groups are the read group 2, 9 and 10 clocks ago:
  // a delay line instead of three more permutation lookups
  reg  [5:0] gd1, gd2, gd3, gd4, gd5, gd6, gd7, gd8, gd9;
  reg  [6:0] wa1q;      // word w of the group written last clock (its w + 2^p is written now)
  wire [5:0] g_st  = gd2;                                       // group staged (tc even 2..128)
  // (its zeta is read one clock earlier, from gd1, which becomes gd2)
  wire [5:0] g_w1  = gd9;                                       // group whose word w is written
  wire [6:0] wr_w  = w_of(g_rd, p);
  wire [6:0] wr_w2 = wr_w | (7'd1 << p);

  // ---- butterfly with the shared multiplier ------------------------------------------
  reg  [23:0] wq;                 // word w (captured)
  reg  [11:0] a0r, a1r, b0r, b1r, zr;
  reg  [11:0] fa, fb, fz;         // butterfly inputs this clock (0 when idle)
  // one delay line for both transforms: NTT a (to the product, tap dl4),
  // INTT (a+b)/2 (tap dl5)
  reg  [11:0] dl1, dl2, dl3, dl4, dl5;
  reg  [11:0] d1, z1;             // INTT: (b-a)/2 and zeta, one clock later
  reg  [11:0] o_add, o_sub;
  reg  [11:0] o0a, o0b, o1b;      // outputs held for the two-word write
  reg  [11:0] ma, mb;             // multiplier inputs
  wire [11:0] mr;
  wire        m_en = busy_r && ((op == P_NTT) || (op == P_INTT) || (op == P_PWM));

  pqse_mulred u_mul (.clk(clk), .en(m_en), .a(ma), .b(mb), .r(mr));

  // ---- zeta ROM, registered read: NTT reads the staged group's zeta at odd tc
  // (zr loads it at the next, even tc), PWM reads gamma's zeta in phase 1 ----
  reg         zen;
  reg  [6:0]  zidx;
  reg  [11:0] zq;
  always @(posedge clk) if (zen) zq <= zeta(zidx);

  wire        feed0 = is_ntt && tc[0]  && (tc >= 8'd3) && (tc <= 8'd129);
  wire        feed1 = is_ntt && !tc[0] && (tc >= 8'd4) && (tc <= 8'd130);
  wire [11:0] bf_oa = intt ? dl5 : o_add;
  wire [11:0] bf_ob = intt ? mr : o_sub;

  // ---- PWM operand registers ------------------------------------------------------------
  reg  [23:0] aq, bq, cq;
  reg  [11:0] e1, o1, o2;
  reg  [23:0] rsh;               // MSPLIT: share-1 word waiting to be written
  reg  [11:0] R0, R1;
  wire [11:0] rq0, rq1;
  pqse_modq24 u_r0 (.x(rnd[23:0]),  .r(rq0));
  pqse_modq24 u_r1 (.x(rnd[47:24]), .r(rq1));

  wire [6:0]  kcur  = shuf ? pq_val : cur[6:0];                       // word order: T[cur]
  // the permutation lookup is registered (pqse_perm.v): it gets the index of
  // the next clock (tc / cur as they will be then; 0 for the first)
  wire        cur_v = (cur < 8'd128);
  wire        prv_v = (cur >= 8'd1) && (cur <= 8'd128);
  wire        pp_v  = (cur >= 8'd2) && (cur <= 8'd129);
  wire [11:0] gam   = kh1[0] ? negq(zq) : zq;                     // zq: zeta({1, kh1[6:1]}) (phase 1)

  // shared "+ product" adder: NTT a + z b, PWM c0 + m1, c1 + m3, + m4, + m5
  wire [11:0] msel  = (ph == 3'd0) ? e1 : (ph == 3'd1) ? cq[11:0] :
                      (ph == 3'd3) ? cq[23:12] : o1;
  wire [11:0] madd  = addq(msel, mr);
  // two add-or-subtract units, shared:
  //   NTT        u0 = a + zb, u1 = a - zb               (a = dl4, zb = mr)
  //   INTT       u0 = a + b,  u1 = b - a                (halved into dl1 / d1)
  //   ADD / SUB  c +/- a per coefficient (a = rdata), MSPLIT c - R
  wire        as_sb = (op == P_SUB) || (op == P_MSPLIT);
  wire [23:0] as_y  = (op == P_MSPLIT) ? {R1, R0} : rdata;
  wire [11:0] u0x   = !is_ntt ? cq[11:0]    : intt ? fa : dl4;
  wire [11:0] u0y   = !is_ntt ? as_y[11:0]  : intt ? fb : mr;
  wire [11:0] u1x   = !is_ntt ? cq[23:12]   : intt ? fb : dl4;
  wire [11:0] u1y   = !is_ntt ? as_y[23:12] : intt ? fa : mr;
  wire [11:0] u0    = asq(u0x, u0y, !is_ntt && as_sb);
  wire [11:0] u1    = asq(u1x, u1y, is_ntt || as_sb);
  wire [23:0] asr   = {u1, u0};

  wire [2:0] ph_last = (op == P_PWM) ? 3'd5 : (op == P_MSPLIT) ? 3'd3 :
                       ((op == P_ADD) || (op == P_SUB)) ? 3'd1 : 3'd0;
  wire [7:0] cur_last = (op == P_PWM) ? 8'd129 : (op == P_ZERO) ? 8'd127 : 8'd128;
  wire       ntt_last = intt ? (p == 3'd6) : (p == 3'd0);
  // end of a layer: flip to the next layer's order (pqse_perm.v); hold at
  // tc = 136 while it is not complete (that clock only repeats an idempotent write)
  wire       lay_end  = busy_r && is_ntt && (tc == 8'd136) && !ntt_last;
  wire       hold     = lay_end && shuf && !pq_ready;
  assign     pq_next  = lay_end && shuf && pq_ready;
  wire [7:0] tc_n     = hold ? tc : (tc == 8'd136) ? 8'd0 : tc + 8'd1;
  wire [7:0] cur_n    = (ph == ph_last) ? cur + 8'd1 : cur;
  assign     pq_idx   = (start || !busy_r) ? 7'd0 : is_ntt ? {1'b0, tc_n[6:1]} : cur_n[6:0];

  // ---- combinational: RAM ports, multiplier inputs, butterfly inputs --------------------------
  always @* begin
    re = 1'b0; raddr = 11'd0;
    we = 1'b0; waddr = 11'd0; wdata = 24'd0;
    ma = 12'd0; mb = 12'd0;
    fa = 12'd0; fb = 12'd0; fz = 12'd0;
    rnd_take = 1'b0;                     // (MSPLIT masks below; orders come from pqse_perm.v)
    zen = 1'b0; zidx = 7'd0;
    if (busy_r) begin
      case (op)
        P_NTT, P_INTT: begin
          if (tc < 8'd128) begin
            re    = 1'b1;
            raddr = {cs, tc[0] ? wr_w2 : wr_w};
          end
          if (tc[0] && tc <= 8'd127) begin zen = 1'b1; zidx = zi_of(gd1, p, intt); end
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
            waddr = {cs, wa1q | (7'd1 << p)};
            wdata = {o1b, o0b};
          end
        end
        P_PWM: begin
          case (ph)
            3'd0: begin
              if (cur_v) begin re = 1'b1; raddr = {as_, kcur}; end
              if (prv_v) begin ma = aq[23:12]; mb = bq[11:0]; end         // m4 = a1*b0 (previous)
              if (pp_v) begin
                we    = 1'b1;
                waddr = {cs, kh2};
                wdata = {o2, madd};                                       // e1 + m5 out
              end
            end
            3'd1: begin
              if (cur_v) begin re = 1'b1; raddr = {bs_, kcur}; end
              if (prv_v) begin zen = 1'b1; zidx = {1'b1, kh1[6:1]}; end  // gamma, for m5
            end
            3'd2: begin
              if (cur_v && acc) begin re = 1'b1; raddr = {cs, kcur}; end
              if (prv_v) begin ma = mr; mb = gam; end                     // m5 = (a1*b1)*gamma
            end
            3'd3: if (cur_v) begin ma = aq[11:0];  mb = bq[11:0];  end    // m1 = a0*b0
            3'd4: if (cur_v) begin ma = aq[23:12]; mb = bq[23:12]; end    // m2 = a1*b1
            3'd5: if (cur_v) begin ma = aq[11:0];  mb = bq[23:12]; end    // m3 = a0*b1
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
            wdata = asr;                                                  // c - R
          end
        end
        P_ZERO: if (cur_v) begin we = 1'b1; waddr = {cs, cur[6:0]}; wdata = 24'd0; end
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
  always @(posedge clk) begin
    if (start || !busy_r) begin
      wq  <= 24'd0;  a0r <= 12'd0; a1r <= 12'd0; b0r <= 12'd0; b1r <= 12'd0; zr <= 12'd0;
      dl1 <= 12'd0;  dl2 <= 12'd0; dl3 <= 12'd0; dl4 <= 12'd0; dl5 <= 12'd0;
      d1  <= 12'd0;  z1  <= 12'd0; o_add <= 12'd0; o_sub <= 12'd0;
      o0a <= 12'd0;  o0b <= 12'd0; o1b <= 12'd0;
      aq  <= 24'd0;  bq  <= 24'd0; cq  <= 24'd0; e1 <= 12'd0; o1 <= 12'd0; o2 <= 12'd0;
      rsh <= 24'd0;  R0  <= 12'd0; R1  <= 12'd0;
    end else begin
    if (busy_r && is_ntt && !hold) begin
      gd1 <= g_rd; gd2 <= gd1; gd3 <= gd2; gd4 <= gd3; gd5 <= gd4;
      gd6 <= gd5;  gd7 <= gd6; gd8 <= gd7; gd9 <= gd8;
      wa1q <= w_of(g_w1, p);
    end
    if (busy_r && is_ntt) begin
      if (tc[0] && tc <= 8'd127) wq <= rdata;
      if (!tc[0] && tc >= 8'd2 && tc <= 8'd128) begin
        a0r <= wq[11:0];     a1r <= wq[23:12];
        b0r <= rdata[11:0];  b1r <= rdata[23:12];
        zr  <= zq;                                       // zeta of g_st (read last clock)
      end
      // NTT (CT): a delayed to the product z*b (dl4); INTT (GS): (a+b)/2 and
      // (b-a)/2, product z*(b-a)/2 one clock later, (a+b)/2 delayed to it (dl5)
      dl1 <= intt ? halfq(u0) : fa;
      dl2 <= dl1; dl3 <= dl2; dl4 <= dl3; dl5 <= dl4;
      o_add <= u0;
      o_sub <= u1;
      d1 <= halfq(u1);
      z1 <= fz;
      // butterfly 0 output (fed at odd tc, out 5 clocks later at even tc)
      if (!tc[0] && tc >= 8'd8 && tc <= 8'd134) begin
        o0a <= bf_oa;
        o0b <= bf_ob;
      end
      if (tc[0] && tc >= 8'd9 && tc <= 8'd135) o1b <= bf_ob;
    end
    if (busy_r && op == P_PWM) begin
      case (ph)
        3'd1: begin
          if (cur_v) aq <= rdata;
          if (prv_v) e1 <= madd;                         // c0 + m1
        end
        3'd2: if (cur_v) bq <= rdata;
        3'd3: begin
          if (prv_v) o1 <= madd;                         // c1 + m3 (previous pair's cq)
          if (cur_v) cq <= acc ? rdata : 24'd0;
        end
        3'd4: if (prv_v) o2 <= madd;                     // + m4
        default: ;
      endcase
    end
    if (busy_r && (op == P_ADD || op == P_SUB)) begin
      if (ph == 3'd1 && cur_v) cq <= rdata;              // c word
      if (ph == 3'd0 && prv_v)                          // rdata = a word of the previous item
        rsh <= asr;
    end
    if (busy_r && op == P_MSPLIT) begin
      if (ph == 3'd1 && cur_v) begin
        cq <= rdata;
        R0 <= rq0;
        R1 <= rq1;
      end
      if (ph == 3'd2 && cur_v) rsh <= {R1, R0};
    end
    end
  end
endmodule
