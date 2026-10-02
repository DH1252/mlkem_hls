// -----------------------------------------------------------------------------
// mlkem_rtl_arith.v - modular arithmetic and the polynomial ALU engine of the
// hand-written ML-KEM-768 core.
//
//   mlkem_mulred   a*b mod q, pipelined, latency 4
//   mlkem_bfu      NTT/INTT butterfly, latency 5
//   mlkem_basemul  NTT-domain pair multiply-accumulate (FIPS 203 Alg. 12),
//                  latency 10
//   mlkem_alu      the engine: NTT, INTT, pointwise multiply-accumulate,
//                  add, subtract on the polynomial memory
//
// Coefficients are 12-bit values, always fully reduced to 0 .. q-1
// (q = 3329). A memory word holds two neighbouring coefficients:
// word w = {coefficient 2w+1, coefficient 2w}.
//
// UNTESTED FIRST VERSION - see hw/manual/README.md.
// -----------------------------------------------------------------------------

// a*b mod q for a, b < q. Barrett reduction with 5039 = floor(2^24 / q),
// the same formula as mod_q() in src/poly.c, which test/test_unit.c checks
// for every value below 2^24. One result per clock, latency 4.
module mlkem_mulred (
  input  wire        clk,
  input  wire [11:0] a,
  input  wire [11:0] b,
  output wire [11:0] r
);
  reg  [23:0] p1, p2;
  reg  [12:0] t2, r3;
  reg  [11:0] r4;
  wire [36:0] m1  = p1 * 37'd5039;          // t = floor(p * 5039 / 2^24)
  wire [24:0] tq  = t2 * 25'd3329;
  wire [24:0] dif = {1'b0, p2} - tq;         // p - t*q, in 0 .. 2q-1
  wire [12:0] r3s = r3 - 13'd3329;

  always @(posedge clk) begin
    p1 <= a * b;
    p2 <= p1;
    t2 <= m1[36:24];
    r3 <= dif[12:0];
    r4 <= (r3 >= 13'd3329) ? r3s[11:0] : r3[11:0];
  end

  assign r = r4;
endmodule


// Butterfly for the NTT (FIPS 203 Alg. 9, "CT" form) and the inverse NTT
// (Alg. 10, "GS" form):
//   NTT : oa = a + z*b,        ob = a - z*b
//   INTT: oa = (a + b)/2,      ob = z*(b - a)/2
// The INTT halves every result, so seven layers give the factor 1/128 that
// Alg. 10 applies at the end (no separate scaling pass is needed).
// Inputs a, b, z valid in clock T -> outputs valid in clock T+5.
module mlkem_bfu (
  input  wire        clk,
  input  wire        intt,
  input  wire [11:0] a,
  input  wire [11:0] b,
  input  wire [11:0] z,
  output wire [11:0] oa,
  output wire [11:0] ob
);
  function [11:0] addq(input [11:0] x, input [11:0] y);
    reg [12:0] s, t;
    begin
      s = {1'b0, x} + {1'b0, y};
      t = s - 13'd3329;
      addq = (s >= 13'd3329) ? t[11:0] : s[11:0];
    end
  endfunction

  function [11:0] subq(input [11:0] x, input [11:0] y);   // x - y mod q
    reg [12:0] s, t;
    begin
      s = {1'b0, x} + 13'd3329 - {1'b0, y};
      t = s - 13'd3329;
      subq = (s >= 13'd3329) ? t[11:0] : s[11:0];
    end
  endfunction

  function [11:0] halfq(input [11:0] x);                  // x / 2 mod q
    reg [12:0] s;
    begin
      s = x[0] ? ({1'b0, x} + 13'd3329) : {1'b0, x};
      halfq = s[12:1];
    end
  endfunction

  reg  [11:0] s1, d1, z1;
  reg  [11:0] a1, a2, a3, a4;
  reg  [11:0] s2, s3, s4, s5;
  reg  [11:0] o_add, o_sub;
  wire [11:0] r;

  // NTT: multiplier fed in clock T (z, b), result in T+4.
  // INTT: multiplier fed in clock T+1 (z1, d1), result in T+5.
  mlkem_mulred u_mul (
    .clk(clk),
    .a  (intt ? z1 : z),
    .b  (intt ? d1 : b),
    .r  (r)
  );

  always @(posedge clk) begin
    s1 <= halfq(addq(a, b));
    d1 <= halfq(subq(b, a));
    z1 <= z;
    a1 <= a;  a2 <= a1;  a3 <= a2;  a4 <= a3;
    s2 <= s1; s3 <= s2;  s4 <= s3;  s5 <= s4;
    o_add <= addq(a4, r);
    o_sub <= subq(a4, r);
  end

  assign oa = intt ? s5 : o_add;
  assign ob = intt ? r  : o_sub;
endmodule


// NTT-domain multiply-accumulate of one coefficient pair (FIPS 203 Alg. 12):
//   e = c0 + a0*b0 + (a1*b1)*g
//   o = c1 + a0*b1 + a1*b0
// Inputs valid in clock T -> outputs valid in clock T+10. One pair per clock.
module mlkem_basemul (
  input  wire        clk,
  input  wire [11:0] a0,
  input  wire [11:0] a1,
  input  wire [11:0] b0,
  input  wire [11:0] b1,
  input  wire [11:0] c0,
  input  wire [11:0] c1,
  input  wire [11:0] g,
  output wire [11:0] e,
  output wire [11:0] o
);
  function [11:0] addq(input [11:0] x, input [11:0] y);
    reg [12:0] s, t;
    begin
      s = {1'b0, x} + {1'b0, y};
      t = s - 13'd3329;
      addq = (s >= 13'd3329) ? t[11:0] : s[11:0];
    end
  endfunction

  wire [11:0] m00, m11, m01, m10, mg;
  reg  [11:0] g1, g2, g3, g4;
  reg  [11:0] m00_5, m00_6, m00_7, m00_8;
  reg  [11:0] cr5, cr6, cr7, cr8;
  reg  [11:0] c0d [1:9];
  reg  [11:0] c1d [1:8];
  reg  [11:0] e9, o9, e10, o10;
  integer k;

  mlkem_mulred u00 (.clk(clk), .a(a0),  .b(b0), .r(m00));   // T+4
  mlkem_mulred u11 (.clk(clk), .a(a1),  .b(b1), .r(m11));   // T+4
  mlkem_mulred u01 (.clk(clk), .a(a0),  .b(b1), .r(m01));   // T+4
  mlkem_mulred u10 (.clk(clk), .a(a1),  .b(b0), .r(m10));   // T+4
  mlkem_mulred ug  (.clk(clk), .a(m11), .b(g4), .r(mg));    // T+8

  always @(posedge clk) begin
    g1 <= g;  g2 <= g1;  g3 <= g2;  g4 <= g3;
    m00_5 <= m00; m00_6 <= m00_5; m00_7 <= m00_6; m00_8 <= m00_7;
    cr5 <= addq(m01, m10); cr6 <= cr5; cr7 <= cr6; cr8 <= cr7;
    c0d[1] <= c0;
    c1d[1] <= c1;
    for (k = 2; k <= 9; k = k + 1) c0d[k] <= c0d[k-1];
    for (k = 2; k <= 8; k = k + 1) c1d[k] <= c1d[k-1];
    e9  <= addq(m00_8, mg);          // T+9
    o9  <= addq(cr8, c1d[8]);        // T+9
    e10 <= addq(e9, c0d[9]);         // T+10
    o10 <= o9;                       // T+10
  end

  assign e = e10;
  assign o = o10;
endmodule


// -----------------------------------------------------------------------------
// The ALU engine. One operation at a time on the polynomial memory:
//
//   op 0 NTT  c       in place, 2 butterflies per clock, ~500 clocks
//   op 1 INTT c       in place, includes the 1/128 factor, ~500 clocks
//   op 2 PWM  c a b   c = (acc ? c : 0) + a o b (NTT domain), ~140 clocks
//   op 3 ADD  c a     c = c + a,  4 coefficients per clock, ~67 clocks
//   op 4 SUB  c a     c = c - a
//
// Memory roles: C (read + write both banks), A and B (read). A slot is two
// banks of 64 words; word w is in bank parity(w) at address w[6:1], so the
// two words of every butterfly (w, w + 2^p) sit in different banks and both
// can be read and written in the same clock.
// -----------------------------------------------------------------------------
module mlkem_alu (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [2:0]  op_in,
  input  wire        acc_in,
  input  wire [3:0]  c_in,
  input  wire [3:0]  a_in,
  input  wire [3:0]  b_in,
  output wire        busy,
  output reg  [3:0]  c_slot,
  output reg  [3:0]  a_slot,
  output reg  [3:0]  b_slot,
  output wire        c_act,
  output wire        a_act,
  output wire        b_act,
  output reg  [11:0] c_raddr,     // {bank 1 address, bank 0 address}
  input  wire [47:0] c_rdata,     // {bank 1 word, bank 0 word}
  output reg  [11:0] c_waddr,
  output reg  [47:0] c_wdata,
  output reg  [1:0]  c_wen,
  output reg  [11:0] a_raddr,
  input  wire [47:0] a_rdata,
  output reg  [11:0] b_raddr,
  input  wire [47:0] b_rdata
);
  localparam [2:0] OP_NTT = 3'd0, OP_INTT = 3'd1, OP_PWM = 3'd2,
                   OP_ADD = 3'd3, OP_SUB  = 3'd4;

  // zetas[k] = 17^BitRev7(k) mod q (FIPS 203 Appendix A, src/poly.c)
  function [11:0] zeta(input [6:0] k);
    case (k)
      7'd0:   zeta = 12'd1;    7'd1:   zeta = 12'd1729; 7'd2:   zeta = 12'd2580; 7'd3:   zeta = 12'd3289;
      7'd4:   zeta = 12'd2642; 7'd5:   zeta = 12'd630;  7'd6:   zeta = 12'd1897; 7'd7:   zeta = 12'd848;
      7'd8:   zeta = 12'd1062; 7'd9:   zeta = 12'd1919; 7'd10:  zeta = 12'd193;  7'd11:  zeta = 12'd797;
      7'd12:  zeta = 12'd2786; 7'd13:  zeta = 12'd3260; 7'd14:  zeta = 12'd569;  7'd15:  zeta = 12'd1746;
      7'd16:  zeta = 12'd296;  7'd17:  zeta = 12'd2447; 7'd18:  zeta = 12'd1339; 7'd19:  zeta = 12'd1476;
      7'd20:  zeta = 12'd3046; 7'd21:  zeta = 12'd56;   7'd22:  zeta = 12'd2240; 7'd23:  zeta = 12'd1333;
      7'd24:  zeta = 12'd1426; 7'd25:  zeta = 12'd2094; 7'd26:  zeta = 12'd535;  7'd27:  zeta = 12'd2882;
      7'd28:  zeta = 12'd2393; 7'd29:  zeta = 12'd2879; 7'd30:  zeta = 12'd1974; 7'd31:  zeta = 12'd821;
      7'd32:  zeta = 12'd289;  7'd33:  zeta = 12'd331;  7'd34:  zeta = 12'd3253; 7'd35:  zeta = 12'd1756;
      7'd36:  zeta = 12'd1197; 7'd37:  zeta = 12'd2304; 7'd38:  zeta = 12'd2277; 7'd39:  zeta = 12'd2055;
      7'd40:  zeta = 12'd650;  7'd41:  zeta = 12'd1977; 7'd42:  zeta = 12'd2513; 7'd43:  zeta = 12'd632;
      7'd44:  zeta = 12'd2865; 7'd45:  zeta = 12'd33;   7'd46:  zeta = 12'd1320; 7'd47:  zeta = 12'd1915;
      7'd48:  zeta = 12'd2319; 7'd49:  zeta = 12'd1435; 7'd50:  zeta = 12'd807;  7'd51:  zeta = 12'd452;
      7'd52:  zeta = 12'd1438; 7'd53:  zeta = 12'd2868; 7'd54:  zeta = 12'd1534; 7'd55:  zeta = 12'd2402;
      7'd56:  zeta = 12'd2647; 7'd57:  zeta = 12'd2617; 7'd58:  zeta = 12'd1481; 7'd59:  zeta = 12'd648;
      7'd60:  zeta = 12'd2474; 7'd61:  zeta = 12'd3110; 7'd62:  zeta = 12'd1227; 7'd63:  zeta = 12'd910;
      7'd64:  zeta = 12'd17;   7'd65:  zeta = 12'd2761; 7'd66:  zeta = 12'd583;  7'd67:  zeta = 12'd2649;
      7'd68:  zeta = 12'd1637; 7'd69:  zeta = 12'd723;  7'd70:  zeta = 12'd2288; 7'd71:  zeta = 12'd1100;
      7'd72:  zeta = 12'd1409; 7'd73:  zeta = 12'd2662; 7'd74:  zeta = 12'd3281; 7'd75:  zeta = 12'd233;
      7'd76:  zeta = 12'd756;  7'd77:  zeta = 12'd2156; 7'd78:  zeta = 12'd3015; 7'd79:  zeta = 12'd3050;
      7'd80:  zeta = 12'd1703; 7'd81:  zeta = 12'd1651; 7'd82:  zeta = 12'd2789; 7'd83:  zeta = 12'd1789;
      7'd84:  zeta = 12'd1847; 7'd85:  zeta = 12'd952;  7'd86:  zeta = 12'd1461; 7'd87:  zeta = 12'd2687;
      7'd88:  zeta = 12'd939;  7'd89:  zeta = 12'd2308; 7'd90:  zeta = 12'd2437; 7'd91:  zeta = 12'd2388;
      7'd92:  zeta = 12'd733;  7'd93:  zeta = 12'd2337; 7'd94:  zeta = 12'd268;  7'd95:  zeta = 12'd641;
      7'd96:  zeta = 12'd1584; 7'd97:  zeta = 12'd2298; 7'd98:  zeta = 12'd2037; 7'd99:  zeta = 12'd3220;
      7'd100: zeta = 12'd375;  7'd101: zeta = 12'd2549; 7'd102: zeta = 12'd2090; 7'd103: zeta = 12'd1645;
      7'd104: zeta = 12'd1063; 7'd105: zeta = 12'd319;  7'd106: zeta = 12'd2773; 7'd107: zeta = 12'd757;
      7'd108: zeta = 12'd2099; 7'd109: zeta = 12'd561;  7'd110: zeta = 12'd2466; 7'd111: zeta = 12'd2594;
      7'd112: zeta = 12'd2804; 7'd113: zeta = 12'd1092; 7'd114: zeta = 12'd403;  7'd115: zeta = 12'd1026;
      7'd116: zeta = 12'd1143; 7'd117: zeta = 12'd2150; 7'd118: zeta = 12'd2775; 7'd119: zeta = 12'd886;
      7'd120: zeta = 12'd1722; 7'd121: zeta = 12'd1212; 7'd122: zeta = 12'd1874; 7'd123: zeta = 12'd1029;
      7'd124: zeta = 12'd2110; 7'd125: zeta = 12'd2935; 7'd126: zeta = 12'd885;  default: zeta = 12'd2154;
    endcase
  endfunction

  function [11:0] addq(input [11:0] x, input [11:0] y);
    reg [12:0] s, t;
    begin
      s = {1'b0, x} + {1'b0, y};
      t = s - 13'd3329;
      addq = (s >= 13'd3329) ? t[11:0] : s[11:0];
    end
  endfunction

  function [11:0] subq(input [11:0] x, input [11:0] y);   // x - y mod q
    reg [12:0] s, t;
    begin
      s = {1'b0, x} + 13'd3329 - {1'b0, y};
      t = s - 13'd3329;
      subq = (s >= 13'd3329) ? t[11:0] : s[11:0];
    end
  endfunction

  // --- control ----------------------------------------------------------------
  reg        busy_r;
  reg        run;        // still issuing
  reg        drain;      // NTT/INTT: waiting for the layer to leave the pipeline
  reg  [2:0] op;
  reg        acc;
  reg  [2:0] p;          // NTT layer: butterfly distance 2^p words (len = 2^(p+1))
  reg  [6:0] cnt;        // issue counter within the layer / operation
  reg [11:1] vld;        // issue valid, delayed: vld[k] = issued k clocks ago
  reg        bs  [1:11]; // bank of word w
  reg  [5:0] wa  [1:11]; // address of word w
  reg  [5:0] wb  [1:11]; // address of word w + 2^p (NTT)
  reg [11:0] zg1;        // zeta (NTT/INTT) or gamma (PWM), valid with vld[1]
  integer k;

  wire is_ntt = (op == OP_NTT) || (op == OP_INTT);
  wire iss    = run && !(is_ntt && drain);

  wire pipe_empty = is_ntt          ? (vld[6:1] == 6'd0) :
                    (op == OP_PWM)  ? (vld == 11'd0)     :
                                      (vld[2:1] == 2'd0);

  assign busy  = start | busy_r;
  assign c_act = busy_r;
  assign a_act = busy_r && (op == OP_PWM || op == OP_ADD || op == OP_SUB);
  assign b_act = busy_r && (op == OP_PWM);

  // --- issue addresses ----------------------------------------------------------
  // NTT layer p: word pairs (w, w + 2^p) where bit p of w is 0.
  // w = cnt with a 0 inserted at bit p.
  wire [7:0] cnt8    = {1'b0, cnt};
  wire [7:0] lowmask = (8'd1 << p) - 8'd1;
  wire [7:0] w8      = ((cnt8 >> p) << (p + 3'd1)) | (cnt8 & lowmask);
  wire [6:0] w       = w8[6:0];
  wire [6:0] w2      = w | (7'd1 << p);
  wire       bw      = ^w;
  // zeta index: NTT uses zetas[2^(6-p) + block], INTT zetas[2^(7-p) - 1 - block]
  wire [7:0] blk     = cnt8 >> p;
  wire [7:0] zi_ntt  = (8'd1 << (3'd6 - p)) + blk;
  wire [7:0] zi_intt = (8'd2 << (3'd6 - p)) - 8'd1 - blk;
  wire [11:0] zsel   = (op == OP_INTT) ? zeta(zi_intt[6:0]) : zeta(zi_ntt[6:0]);
  // PWM pair cnt: gamma = zetas[64 + cnt/2], negated for odd cnt
  wire [11:0] gz     = zeta({1'b1, cnt[6:1]});
  wire [11:0] gamma  = cnt[0] ? (12'd3329 - gz) : gz;

  always @* begin
    c_raddr = 12'd0;
    a_raddr = 12'd0;
    b_raddr = 12'd0;
    if (is_ntt) begin
      c_raddr = bw ? {w[6:1], w2[6:1]} : {w2[6:1], w[6:1]};
    end else if (op == OP_PWM) begin
      c_raddr = {cnt[6:1], cnt[6:1]};
      a_raddr = {cnt[6:1], cnt[6:1]};
      b_raddr = {cnt[6:1], cnt[6:1]};
    end else begin
      c_raddr = {cnt[5:0], cnt[5:0]};
      a_raddr = {cnt[5:0], cnt[5:0]};
    end
  end

  // --- control FSM --------------------------------------------------------------
  always @(posedge clk) begin
    if (rst) begin
      busy_r <= 1'b0;
      run    <= 1'b0;
      drain  <= 1'b0;
      vld    <= 11'd0;
    end else begin
      vld <= start ? 11'd0 : {vld[10:1], iss};
      if (start) begin
        op     <= op_in;
        acc    <= acc_in;
        c_slot <= c_in;
        a_slot <= a_in;
        b_slot <= b_in;
        busy_r <= 1'b1;
        run    <= 1'b1;
        drain  <= 1'b0;
        cnt    <= 7'd0;
        p      <= (op_in == OP_INTT) ? 3'd0 : 3'd6;
      end else if (run) begin
        if (is_ntt) begin
          if (!drain) begin
            if (cnt == 7'd63) begin
              cnt   <= 7'd0;
              drain <= 1'b1;
            end else begin
              cnt <= cnt + 7'd1;
            end
          end else if (pipe_empty) begin
            if ((op == OP_NTT && p == 3'd0) || (op == OP_INTT && p == 3'd6)) begin
              run <= 1'b0;
            end else begin
              p     <= (op == OP_NTT) ? (p - 3'd1) : (p + 3'd1);
              drain <= 1'b0;
            end
          end
        end else if (op == OP_PWM) begin
          if (cnt == 7'd127) run <= 1'b0;
          cnt <= cnt + 7'd1;
        end else begin
          if (cnt == 7'd63) run <= 1'b0;
          cnt <= cnt + 7'd1;
        end
      end else if (busy_r && pipe_empty) begin
        busy_r <= 1'b0;
      end
    end
  end

  // --- metadata pipeline ----------------------------------------------------------
  always @(posedge clk) begin
    bs[1] <= (op == OP_PWM) ? (^cnt) : bw;
    wa[1] <= is_ntt ? w[6:1] : ((op == OP_PWM) ? cnt[6:1] : cnt[5:0]);
    wb[1] <= w2[6:1];
    zg1   <= (op == OP_PWM) ? gamma : zsel;
    for (k = 2; k <= 11; k = k + 1) begin
      bs[k] <= bs[k-1];
      wa[k] <= wa[k-1];
      wb[k] <= wb[k-1];
    end
  end

  // --- datapaths (inputs valid in the clock after issue, vld[1]) ------------------
  wire [23:0] c_lo = c_rdata[23:0];
  wire [23:0] c_hi = c_rdata[47:24];
  wire [23:0] nw_a = bs[1] ? c_hi : c_lo;             // word w
  wire [23:0] nw_b = bs[1] ? c_lo : c_hi;             // word w + 2^p
  wire [23:0] pa_w = bs[1] ? a_rdata[47:24] : a_rdata[23:0];
  wire [23:0] pb_w = bs[1] ? b_rdata[47:24] : b_rdata[23:0];
  wire [23:0] pc_w = acc ? (bs[1] ? c_hi : c_lo) : 24'd0;

  wire [11:0] bf0_a, bf0_b, bf1_a, bf1_b;
  mlkem_bfu u_bf0 (.clk(clk), .intt(op == OP_INTT), .a(nw_a[11:0]),  .b(nw_b[11:0]),
                   .z(zg1), .oa(bf0_a), .ob(bf0_b));
  mlkem_bfu u_bf1 (.clk(clk), .intt(op == OP_INTT), .a(nw_a[23:12]), .b(nw_b[23:12]),
                   .z(zg1), .oa(bf1_a), .ob(bf1_b));

  wire [11:0] pm_e, pm_o;
  mlkem_basemul u_bm (
    .clk(clk),
    .a0(pa_w[11:0]), .a1(pa_w[23:12]),
    .b0(pb_w[11:0]), .b1(pb_w[23:12]),
    .c0(pc_w[11:0]), .c1(pc_w[23:12]),
    .g (zg1),
    .e (pm_e), .o(pm_o)
  );

  reg [23:0] ew0, ew1;   // ADD/SUB results, valid with vld[2]
  always @(posedge clk) begin
    if (op == OP_SUB) begin
      ew0 <= {subq(c_lo[23:12], a_rdata[23:12]), subq(c_lo[11:0], a_rdata[11:0])};
      ew1 <= {subq(c_hi[23:12], a_rdata[47:36]), subq(c_hi[11:0], a_rdata[35:24])};
    end else begin
      ew0 <= {addq(c_lo[23:12], a_rdata[23:12]), addq(c_lo[11:0], a_rdata[11:0])};
      ew1 <= {addq(c_hi[23:12], a_rdata[47:36]), addq(c_hi[11:0], a_rdata[35:24])};
    end
  end

  // --- write back -------------------------------------------------------------------
  always @* begin
    c_wen   = 2'b00;
    c_waddr = 12'd0;
    c_wdata = 48'd0;
    if (is_ntt) begin
      if (vld[6]) begin
        c_wen = 2'b11;
        if (bs[6]) begin          // word w in bank 1, word w + 2^p in bank 0
          c_waddr = {wa[6], wb[6]};
          c_wdata = {bf1_a, bf0_a, bf1_b, bf0_b};
        end else begin
          c_waddr = {wb[6], wa[6]};
          c_wdata = {bf1_b, bf0_b, bf1_a, bf0_a};
        end
      end
    end else if (op == OP_PWM) begin
      if (vld[11]) begin
        c_wen   = bs[11] ? 2'b10 : 2'b01;
        c_waddr = {wa[11], wa[11]};
        c_wdata = {pm_o, pm_e, pm_o, pm_e};
      end
    end else begin
      if (vld[2]) begin
        c_wen   = 2'b11;
        c_waddr = {wa[2], wa[2]};
        c_wdata = {ew1, ew0};
      end
    end
  end
endmodule
