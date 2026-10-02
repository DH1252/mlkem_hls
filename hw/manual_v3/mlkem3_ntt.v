// -----------------------------------------------------------------------------
// mlkem3_ntt.v - NTT engine of the v3 core: NTT and INTT, 8 butterflies per
// clock, optionally fused with an add or reverse subtract.
//
//   op 0 NTT   c        [fuse 1: c = NTT(c) + a]
//   op 1 INTT  c        [fuse 1: c = INTT(c) + a, fuse 2: c = a - INTT(c)]
//   ~ 4 x 32 + 13 = 141 clocks (v2: 7 x 39 = 273 with 4 butterflies)
//
// Radix-4 passes. Each clock the engine reads four words (8 coefficients)
// from the four banks, runs them through two butterfly stages (4 butterflies
// each = two NTT layers), and writes them back 12 clocks later. The seven
// layers are done in four passes of 32 groups:
//   NTT  (hi,lo) = (6,5) (4,3) (2,1), then the single layer 0
//   INTT the single layer 0, then (2,1) (4,3) (6,5)
// (bit p = word distance 2^p = coefficient distance 2^(p+1)). A group is the
// four words w, w^2^lo, w^2^hi, w^2^lo^2^hi (labels W0..W3); for the single
// layer it is the aligned group 4a..4a+3 (lo = 0, hi = 1) and stage 2 is
// bypassed by a 5-clock delay line. With the v3 bank mapping
// (mlkem3_mem.v) the four words are always in four different banks.
//
// Stage 1: NTT radix-4 passes pair across hi (layer hi first, as FIPS 203
//          Alg. 9 goes from long to short distances); otherwise across lo.
// Stage 2: NTT pairs across lo, INTT across hi (Alg. 10 goes short to long).
//
// No drain between passes. The group order inside each pass (base_of below)
// is chosen so that every group of pass k+1 only reads words that pass k
// wrote at least 2 clocks earlier: with issue-to-write latency L = 12, the
// worst case over all groups is max(rank_k - rank_k+1) = 17 < 32 - L - 1.
// The next pass therefore starts the clock after the last group of the
// previous one. PASS_GAP inserts idle clocks between passes if the pipeline
// is ever made longer. Simulation with MLKEM_SIM_CHECK defined checks every
// read against the writes still in flight and prints "NTT CHECK FAIL".
//
// Pipeline (k = clocks after the group is issued):
//   0  read the 4 words (one per bank)
//   1  RAM data -> input register cq; stage-1 zetas looked up
//   2  stage-1 butterflies start (latency 5)
//   6  stage-2 zetas looked up
//   7  stage-2 butterflies start, or the delay line (single layer)
//   10 fused op: read the 4 words of a
//   11 a's words -> register aq
//   12 write back (with the fused add / subtract)
//
// Low power: every register loads only for the item that uses it
// (valid-gated), the RAM banks are read only in issue clocks, stage 2 is
// idle during the single-layer pass, and a is only read for fused writes.
//
// UNTESTED FIRST VERSION of v3 - see hw/manual_v3/README.md.
// -----------------------------------------------------------------------------
module mlkem3_ntt #(
  parameter PASS_GAP = 0
) (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire        op_in,      // 0 NTT, 1 INTT
  input  wire [1:0]  fuse_in,    // 0 none, 1 c = X(c) + a, 2 c = a - X(c)
  input  wire [3:0]  c_in,
  input  wire [3:0]  a_in,
  output wire        busy,
  // polynomial memory, role N (c)
  output reg  [3:0]  n_slot,
  output reg  [3:0]  n_re,
  output reg  [19:0] n_raddr,
  input  wire [95:0] n_rdata,
  output reg  [3:0]  n_we,
  output reg  [19:0] n_waddr,
  output reg  [95:0] n_wdata,
  // role NA (a, fused operand)
  output reg  [3:0]  na_slot,
  output reg  [3:0]  na_re,
  output reg  [19:0] na_raddr,
  input  wire [95:0] na_rdata
);
  // zetas[k] = 17^BitRev7(k) mod q (FIPS 203 Appendix A)
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

  // fused write: f = 1: x + y, f = 2: y - x (both coefficients of a word)
  function [23:0] fuse_w(input [23:0] x, input [23:0] y, input [1:0] f);
    fuse_w = (f == 2'd1) ? {addq(x[23:12], y[23:12]), addq(x[11:0], y[11:0])}
                         : {subq(y[23:12], x[23:12]), subq(y[11:0], x[11:0])};
  endfunction

  // v3 bank of word w: {odd-bit parity, even-bit parity} (mlkem3_mem.v)
  function [1:0] bank_of(input [6:0] w);
    bank_of = {^(w & 7'b0101010), ^(w & 7'b1010101)};
  endfunction

  // lower bit of the pass's bit pair (hi = lo + 1)
  function [2:0] lo_of(input intt, input [1:0] ps);
    case ({intt, ps})
      3'b000: lo_of = 3'd5;   3'b001: lo_of = 3'd3;
      3'b010: lo_of = 3'd1;   3'b011: lo_of = 3'd0;    // NTT single layer
      3'b100: lo_of = 3'd0;                            // INTT single layer
      3'b101: lo_of = 3'd1;   3'b110: lo_of = 3'd3;
      default: lo_of = 3'd5;
    endcase
  endfunction

  // group base word W0 (bits hi and lo zero) from the counter g. The bit
  // order sets the issue order that makes the passes chain without a drain
  // (counter weights per pass chosen so that the slack stays <= 17):
  function [6:0] base_of(input intt, input [1:0] ps, input [4:0] g);
    case ({intt, ps})
      //                    w6    w5    w4    w3    w2    w1    w0
      3'b000: base_of = {1'b0, 1'b0, g[1], g[0], g[4], g[3], g[2]};  // NTT (6,5)
      3'b001: base_of = {g[3], g[2], 1'b0, 1'b0, g[4], g[0], g[1]};  // NTT (4,3)
      3'b010: base_of = {g[4], g[3], g[1], g[0], 1'b0, 1'b0, g[2]};  // NTT (2,1)
      3'b011: base_of = {g, 2'b00};                                  // NTT layer 0
      3'b100: base_of = {g, 2'b00};                                  // INTT layer 0
      3'b101: base_of = {g[4], g[3], g[1], g[0], 1'b0, 1'b0, g[2]};  // INTT (2,1)
      3'b110: base_of = {g[4], g[0], 1'b0, 1'b0, g[3], g[2], g[1]};  // INTT (4,3)
      default: base_of = {1'b0, 1'b0, g[1], g[0], g[4], g[3], g[2]}; // INTT (6,5)
    endcase
  endfunction

  // the four words of group (ps, g): {W3, W2, W1, W0}
  function [27:0] words_of(input intt, input [1:0] ps, input [4:0] g);
    reg [6:0] w, bl, bh;
    reg [2:0] lo;
    begin
      lo = lo_of(intt, ps);
      w  = base_of(intt, ps, g);
      bl = 7'd1 << lo;
      bh = 7'd1 << (lo + 3'd1);
      words_of = {w | bl | bh, w | bh, w | bl, w};
    end
  endfunction

  // zeta index of the butterflies across bit b whose first word is u
  //   NTT  zetas[2^(6-b) + (u >> (b+1))]
  //   INTT zetas[2^(7-b) - 1 - (u >> (b+1))]
  function [6:0] zidx(input intt, input [2:0] b, input [6:0] u);
    reg [7:0] blk, base;
    begin
      blk = {1'b0, u} >> (b + 3'd1);
      if (intt) begin
        base = (8'd2 << (3'd6 - b)) - 8'd1;
        zidx = base - blk;
      end else begin
        base = 8'd1 << (3'd6 - b);
        zidx = base + blk;
      end
    end
  endfunction

  // pass properties
  function lone_of(input intt, input [1:0] ps);          // single-layer pass
    lone_of = intt ? (ps == 2'd0) : (ps == 2'd3);
  endfunction
  function s1hi_of(input intt, input [1:0] ps);          // stage 1 pairs across hi
    s1hi_of = !intt && (ps != 2'd3);
  endfunction

  // --- control ----------------------------------------------------------------
  reg        run, intt;
  reg  [1:0] fuse;
  reg  [1:0] ps;
  reg  [4:0] cnt;
  reg  [3:0] gap;
  reg [12:1] vld;           // vld[k]: a group issued k clocks ago
  reg  [6:0] md [1:12];     // {ps, g} of that group
  integer    k, j0, j1, j2, j3;

  wire       iss = run && (gap == 4'd0);
  wire [6:0] md0 = {ps, cnt};

  assign busy = start | run | (vld != 12'd0);

  always @(posedge clk) begin
    if (rst) begin
      run <= 1'b0;
      vld <= 12'd0;
      gap <= 4'd0;
    end else begin
      vld <= start ? 12'd0 : {vld[11:1], iss};
      if (start) begin
        intt    <= op_in;
        fuse    <= fuse_in;
        n_slot  <= c_in;
        na_slot <= a_in;
        run     <= 1'b1;
        ps      <= 2'd0;
        cnt     <= 5'd0;
        gap     <= 4'd0;
      end else if (run) begin
        if (gap != 4'd0) begin
          gap <= gap - 4'd1;
        end else begin
          cnt <= cnt + 5'd1;
          if (cnt == 5'd31) begin
            if (ps == 2'd3) begin
              run <= 1'b0;
            end else begin
              ps  <= ps + 2'd1;
              gap <= PASS_GAP;
            end
          end
        end
      end
    end
  end

  always @(posedge clk) begin
    if (iss) md[1] <= md0;
    for (k = 2; k <= 12; k = k + 1)
      if (vld[k-1]) md[k] <= md[k-1];
  end

  // plain wires for the stages used below
  wire [6:0] md1 = md[1], md2 = md[2], md6 = md[6], md7 = md[7], md8 = md[8];
  wire [6:0] md9 = md[9], md10 = md[10], md11 = md[11], md12 = md[12];

  wire [27:0] w0q  = words_of(intt, ps, cnt);
  wire [27:0] w1q  = words_of(intt, md1[6:5],  md1[4:0]);
  wire [27:0] w2q  = words_of(intt, md2[6:5],  md2[4:0]);
  wire [27:0] w6q  = words_of(intt, md6[6:5],  md6[4:0]);
  wire [27:0] w10q = words_of(intt, md10[6:5], md10[4:0]);
  wire [27:0] w12q = words_of(intt, md12[6:5], md12[4:0]);

  // --- stage 0: read the group ---------------------------------------------------
  always @* begin
    n_re    = 4'b0000;
    n_raddr = 20'd0;
    if (iss) begin
      n_re = 4'b1111;
      for (j0 = 0; j0 < 4; j0 = j0 + 1)
        n_raddr[5*bank_of(w0q[7*j0 +: 7]) +: 5] = w0q[7*j0 + 2 +: 5];
    end
  end

  // --- stage 1: input register, stage-1 zetas ----------------------------------------
  reg  [95:0] cq;
  reg  [11:0] zs1_0, zs1_1, zs2_0, zs2_1;
  wire        s1hi_1 = s1hi_of(intt, md1[6:5]);
  wire [2:0]  lo_1   = lo_of(intt, md1[6:5]);
  wire [2:0]  b1_1   = s1hi_1 ? (lo_1 + 3'd1) : lo_1;

  always @(posedge clk) begin
    if (vld[1]) begin
      cq    <= n_rdata;
      zs1_0 <= zeta(zidx(intt, b1_1, w1q[6:0]));
      zs1_1 <= zeta(zidx(intt, b1_1, s1hi_1 ? w1q[13:7] : w1q[20:14]));
    end
  end

  // --- stage 2: stage-1 butterflies ----------------------------------------------------
  wire        s1hi_2 = s1hi_of(intt, md2[6:5]);
  wire [23:0] x0 = cq[24*bank_of(w2q[6:0])   +: 24];
  wire [23:0] x1 = cq[24*bank_of(w2q[13:7])  +: 24];
  wire [23:0] x2 = cq[24*bank_of(w2q[20:14]) +: 24];
  wire [23:0] x3 = cq[24*bank_of(w2q[27:21]) +: 24];
  // pairs: across hi (W0,W2) (W1,W3); across lo (W0,W1) (W2,W3)
  wire [23:0] p0a = x0;
  wire [23:0] p0b = s1hi_2 ? x2 : x1;
  wire [23:0] p1a = s1hi_2 ? x1 : x2;
  wire [23:0] p1b = x3;
  wire        en1 = vld[2];
  wire [11:0] o1a0, o1b0, o1a1, o1b1, o1a2, o1b2, o1a3, o1b3;

  mlkem3_bfu u_s1_0 (.clk(clk), .en(en1), .intt(intt), .a(p0a[11:0]),  .b(p0b[11:0]),  .z(zs1_0), .oa(o1a0), .ob(o1b0));
  mlkem3_bfu u_s1_1 (.clk(clk), .en(en1), .intt(intt), .a(p0a[23:12]), .b(p0b[23:12]), .z(zs1_0), .oa(o1a1), .ob(o1b1));
  mlkem3_bfu u_s1_2 (.clk(clk), .en(en1), .intt(intt), .a(p1a[11:0]),  .b(p1b[11:0]),  .z(zs1_1), .oa(o1a2), .ob(o1b2));
  mlkem3_bfu u_s1_3 (.clk(clk), .en(en1), .intt(intt), .a(p1a[23:12]), .b(p1b[23:12]), .z(zs1_1), .oa(o1a3), .ob(o1b3));

  // --- stage 6: stage-2 zetas --------------------------------------------------------------
  wire [2:0]  lo_6 = lo_of(intt, md6[6:5]);
  wire [2:0]  b2_6 = intt ? (lo_6 + 3'd1) : lo_6;         // stage 2: INTT across hi, NTT across lo
  always @(posedge clk) begin
    if (vld[6] && !lone_of(intt, md6[6:5])) begin
      zs2_0 <= zeta(zidx(intt, b2_6, w6q[6:0]));
      zs2_1 <= zeta(zidx(intt, b2_6, intt ? w6q[13:7] : w6q[20:14]));
    end
  end

  // --- stage 7: stage-1 results, stage-2 butterflies or the delay line -----------------
  wire        s1hi_7 = s1hi_of(intt, md7[6:5]);
  wire        lone_7 = lone_of(intt, md7[6:5]);
  wire [23:0] r0a = {o1a1, o1a0};   // pair 0, first word
  wire [23:0] r0b = {o1b1, o1b0};   // pair 0, second word
  wire [23:0] r1a = {o1a3, o1a2};
  wire [23:0] r1b = {o1b3, o1b2};
  wire [23:0] y0 = r0a;
  wire [23:0] y1 = s1hi_7 ? r1a : r0b;
  wire [23:0] y2 = s1hi_7 ? r0b : r1a;
  wire [23:0] y3 = r1b;
  wire [23:0] q0a = y0;
  wire [23:0] q0b = intt ? y2 : y1;
  wire [23:0] q1a = intt ? y1 : y2;
  wire [23:0] q1b = y3;
  wire        en2 = vld[7] && !lone_7;
  wire [11:0] o2a0, o2b0, o2a1, o2b1, o2a2, o2b2, o2a3, o2b3;

  mlkem3_bfu u_s2_0 (.clk(clk), .en(en2), .intt(intt), .a(q0a[11:0]),  .b(q0b[11:0]),  .z(zs2_0), .oa(o2a0), .ob(o2b0));
  mlkem3_bfu u_s2_1 (.clk(clk), .en(en2), .intt(intt), .a(q0a[23:12]), .b(q0b[23:12]), .z(zs2_0), .oa(o2a1), .ob(o2b1));
  mlkem3_bfu u_s2_2 (.clk(clk), .en(en2), .intt(intt), .a(q1a[11:0]),  .b(q1b[11:0]),  .z(zs2_1), .oa(o2a2), .ob(o2b2));
  mlkem3_bfu u_s2_3 (.clk(clk), .en(en2), .intt(intt), .a(q1a[23:12]), .b(q1b[23:12]), .z(zs2_1), .oa(o2a3), .ob(o2b3));

  // single-layer pass: stage 2 is skipped, the words wait 5 clocks
  reg [95:0] dl1, dl2, dl3, dl4, dl5;
  always @(posedge clk) begin
    if (vld[7]  && lone_7)                          dl1 <= {y3, y2, y1, y0};
    if (vld[8]  && lone_of(intt, md8[6:5]))         dl2 <= dl1;
    if (vld[9]  && lone_of(intt, md9[6:5]))         dl3 <= dl2;
    if (vld[10] && lone_of(intt, md10[6:5]))        dl4 <= dl3;
    if (vld[11] && lone_of(intt, md11[6:5]))        dl5 <= dl4;
  end

  // --- stages 10, 11: fused operand -------------------------------------------------------
  wire fz_10 = (fuse != 2'd0) && (md10[6:5] == 2'd3);   // last pass of a fused op
  wire fz_11 = (fuse != 2'd0) && (md11[6:5] == 2'd3);
  wire fz_12 = (fuse != 2'd0) && (md12[6:5] == 2'd3);

  always @* begin
    na_re    = 4'b0000;
    na_raddr = 20'd0;
    if (vld[10] && fz_10) begin
      na_re = 4'b1111;
      for (j1 = 0; j1 < 4; j1 = j1 + 1)
        na_raddr[5*bank_of(w10q[7*j1 +: 7]) +: 5] = w10q[7*j1 + 2 +: 5];
    end
  end

  reg [95:0] aq;                 // a's words in bank order
  always @(posedge clk)
    if (vld[11] && fz_11) aq <= na_rdata;

  // --- stage 12: results, write back -----------------------------------------------------
  wire        lone_12 = lone_of(intt, md12[6:5]);
  wire [23:0] t0a = {o2a1, o2a0};
  wire [23:0] t0b = {o2b1, o2b0};
  wire [23:0] t1a = {o2a3, o2a2};
  wire [23:0] t1b = {o2b3, o2b2};
  wire [95:0] zw = lone_12 ? dl5 :
                   intt    ? {t1b, t0b, t1a, t0a}      // across hi: W0 W1 W2 W3 = t0a t1a t0b t1b
                           : {t1b, t1a, t0b, t0a};     // across lo: W0 W1 W2 W3 = t0a t0b t1a t1b

  reg [1:0] bk;
  always @* begin
    n_we    = 4'b0000;
    n_waddr = 20'd0;
    n_wdata = 96'd0;
    bk      = 2'd0;
    if (vld[12]) begin
      n_we = 4'b1111;
      for (j2 = 0; j2 < 4; j2 = j2 + 1) begin
        bk = bank_of(w12q[7*j2 +: 7]);
        n_waddr[5*bk +: 5]  = w12q[7*j2 + 2 +: 5];
        n_wdata[24*bk +: 24] = fz_12 ? fuse_w(zw[24*j2 +: 24], aq[24*bk +: 24], fuse)
                                     : zw[24*j2 +: 24];
      end
    end
  end

`ifdef MLKEM_SIM_CHECK
  // synthesis translate_off
  // Every word read must not have a write still in flight (the no-drain
  // pass order above relies on it).
  reg [127:0] pend;
  always @(posedge clk) begin
    if (rst || start) begin
      pend <= 128'd0;
    end else begin
      if (vld[12])
        for (j3 = 0; j3 < 4; j3 = j3 + 1)
          pend[w12q[7*j3 +: 7]] <= 1'b0;
      if (iss)
        for (j3 = 0; j3 < 4; j3 = j3 + 1) begin
          if (pend[w0q[7*j3 +: 7]])
            $display("%0t NTT CHECK FAIL: %s pass %0d group %0d reads word %0d before it is written",
                     $time, intt ? "INTT" : "NTT", ps, cnt, w0q[7*j3 +: 7]);
          pend[w0q[7*j3 +: 7]] <= 1'b1;
        end
    end
  end
  // synthesis translate_on
`endif
endmodule
