// -----------------------------------------------------------------------------
// mlkem2_alu.v - polynomial ALU of the v2 core.
//
//   op 0 NTT   c          4 butterflies/clock, 7 x (32 + 8) = ~280 clocks
//   op 1 INTT  c [fuse]   same; fuse 1: c = INTT(c) + a, fuse 2: c = a - INTT(c)
//                         (the add/subtract is done in the last layer's
//                          write-back: no separate pass, no extra RAM traffic)
//   op 2 PWM   c a b      c = (acc ? c : 0) + a o b, 2 words/clock, ~77 clocks
//   op 3 ADD   c a        c = c + a, 4 words/clock, ~36 clocks
//   op 4 SUB   c a        c = c - a
//
// Memory: 4 banks per slot, word w in bank {w[0], ^w} at address w[6:2]
// (mlkem2_mem.v). NTT layer p pairs words (w, w + 2^p); each clock handles
// two such pairs, (w00, w10) and (w01, w11) = (w, w ^ 2^p) and the same
// XOR 2^q, with q = 0 (q = 1 for p = 0). The four words always sit in four
// different banks.
//
// Low power: RAM banks are read only in issue clocks (PWM reads C only when
// accumulating), all pipelines are valid-gated, the metadata pipeline only
// shifts valid entries.
//
// UNTESTED FIRST VERSION - see hw/manual_v2/README.md.
// -----------------------------------------------------------------------------
module mlkem2_alu (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [2:0]  op_in,
  input  wire        acc_in,
  input  wire [1:0]  fuse_in,
  input  wire [3:0]  c_in,
  input  wire [3:0]  a_in,
  input  wire [3:0]  b_in,
  output wire        busy,
  output reg  [3:0]  c_slot,
  output reg  [3:0]  a_slot,
  output reg  [3:0]  b_slot,
  output reg  [3:0]  c_re,
  output reg  [19:0] c_raddr,
  input  wire [95:0] c_rdata,
  output reg  [3:0]  c_we,
  output reg  [19:0] c_waddr,
  output reg  [95:0] c_wdata,
  output reg  [3:0]  a_re,
  output reg  [19:0] a_raddr,
  input  wire [95:0] a_rdata,
  output reg  [3:0]  b_re,
  output reg  [19:0] b_raddr,
  input  wire [95:0] b_rdata
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

  function [23:0] addw(input [23:0] x, input [23:0] y);    // two coefficients
    addw = {addq(x[23:12], y[23:12]), addq(x[11:0], y[11:0])};
  endfunction

  function [23:0] subw(input [23:0] x, input [23:0] y);
    subw = {subq(x[23:12], y[23:12]), subq(x[11:0], y[11:0])};
  endfunction

  function [1:0] bank_of(input [6:0] w);                  // {w[0], parity}
    bank_of = {w[0], ^w};
  endfunction

  // --- control --------------------------------------------------------------
  reg        busy_r, run, drain;
  reg  [2:0] op;
  reg        acc;
  reg  [1:0] fuse;
  reg  [2:0] p;             // NTT layer: distance 2^p words
  reg  [5:0] cnt;
  reg [12:1] vld;           // vld[k]: an item issued k clocks ago
  integer    k, k2, k3, k4; // one loop variable per always block

  wire is_ntt = (op == OP_NTT) || (op == OP_INTT);
  wire iss    = run && !(is_ntt && drain);
  wire fz     = (op == OP_INTT) && (fuse != 2'd0) && (p == 3'd6);   // fused last layer

  // Pipeline (k = clocks after issue):
  //   0 RAM read   1 read data -> input registers cq/aq/bq   2 arithmetic starts
  //   NTT/INTT: butterflies 2..7, write at 7     PWM: base-case 2..12, write at 12
  //   ADD/SUB:  add at 2 (-> ew), write at 3
  wire pipe_empty = is_ntt         ? (vld[7:1] == 7'd0) :
                    (op == OP_PWM) ? (vld == 12'd0)     :
                                     (vld[3:1] == 3'd0);

  assign busy = start | busy_r;

  always @(posedge clk) begin
    if (rst) begin
      busy_r <= 1'b0;
      run    <= 1'b0;
      drain  <= 1'b0;
      vld    <= 12'd0;
    end else begin
      vld <= start ? 12'd0 : {vld[11:1], iss};
      if (start) begin
        op     <= op_in;
        acc    <= acc_in;
        fuse   <= fuse_in;
        c_slot <= c_in;
        a_slot <= a_in;
        b_slot <= b_in;
        busy_r <= 1'b1;
        run    <= 1'b1;
        drain  <= 1'b0;
        cnt    <= 6'd0;
        p      <= (op_in == OP_INTT) ? 3'd0 : 3'd6;
      end else if (run) begin
        if (is_ntt) begin
          if (!drain) begin
            if (cnt == 6'd31) begin
              cnt   <= 6'd0;
              drain <= 1'b1;
            end else begin
              cnt <= cnt + 6'd1;
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
          if (cnt == 6'd63) run <= 1'b0;
          cnt <= cnt + 6'd1;
        end else begin
          if (cnt == 6'd31) run <= 1'b0;
          cnt <= cnt + 6'd1;
        end
      end else if (busy_r && pipe_empty) begin
        busy_r <= 1'b0;
      end
    end
  end

  // --- NTT/INTT word selection ----------------------------------------------
  wire [7:0] x8   = {2'b00, cnt[4:0], 1'b0};
  wire [7:0] lowm = (8'd1 << p) - 8'd1;
  wire [7:0] ins8 = ((x8 >> p) << (p + 3'd1)) | (x8 & lowm);
  wire [6:0] w00  = (p == 3'd0) ? {cnt[4:0], 2'b00} : ins8[6:0];
  wire [6:0] bp   = 7'd1 << p;
  wire [6:0] bq   = (p == 3'd0) ? 7'd2 : 7'd1;
  wire [6:0] w10  = w00 | bp;
  wire [6:0] w01  = w00 | bq;
  wire [6:0] w11  = w10 | bq;

  // zeta index: NTT zetas[2^(6-p) + block], INTT zetas[2^(7-p) - 1 - block],
  // block = w >> (p+1); the two pairs differ in block only for p = 0
  wire [7:0] blk0 = {1'b0, w00} >> (p + 3'd1);
  wire [7:0] blk1 = {1'b0, w01} >> (p + 3'd1);
  wire [7:0] zb_n = 8'd1 << (3'd6 - p);
  wire [7:0] zb_i = (8'd2 << (3'd6 - p)) - 8'd1;
  wire [7:0] zi0  = (op == OP_INTT) ? (zb_i - blk0) : (zb_n + blk0);
  wire [7:0] zi1  = (op == OP_INTT) ? (zb_i - blk1) : (zb_n + blk1);

  // PWM: words 2j and 2j+1 (j = cnt), gamma = +/- zetas[64 + j]
  wire [1:0] pk_a = {1'b0, ^cnt[5:0]};          // bank of word 2j
  wire [1:0] pk_b = {1'b1, ~(^cnt[5:0])};       // bank of word 2j+1
  wire [11:0] gz  = zeta({1'b1, cnt[5:0]});

  // metadata of an issued item: {k11,k01,k10,k00 banks, a11,a01,a10,a00 addrs}
  // (PWM: k00/k10 = banks of words 2j/2j+1, a00 = address; ADD/SUB: a00)
  wire [27:0] md0 = is_ntt ? {w11[6:2], w01[6:2], w10[6:2], w00[6:2],
                              bank_of(w11), bank_of(w01), bank_of(w10), bank_of(w00)} :
                    (op == OP_PWM) ? {15'd0, cnt[5:1], 2'd0, 2'd0, pk_b, pk_a} :
                                     {15'd0, cnt[4:0], 8'd0};
  reg [27:0] md [1:12];
  reg [11:0] z0r, z1r;          // zetas (NTT) or gamma (PWM, z0r), with md[1]
  reg [11:0] z0q, z1q;          // the same, one stage later (with md[2])

  always @(posedge clk) begin
    if (iss) begin
      md[1] <= md0;
      z0r   <= (op == OP_PWM) ? gz : zeta(zi0[6:0]);
      z1r   <= zeta(zi1[6:0]);
    end
    if (vld[1]) begin
      z0q <= z0r;
      z1q <= z1r;
    end
    for (k = 2; k <= 12; k = k + 1)
      if (vld[k-1]) md[k] <= md[k-1];
  end

  // plain wires for the stages used in combinational blocks
  wire [27:0] md2  = md[2];
  wire [27:0] md3  = md[3];
  wire [27:0] md5  = md[5];
  wire [27:0] md7  = md[7];
  wire [27:0] md12 = md[12];

  // field access helpers
  function [1:0] mk(input [27:0] m, input [1:0] i);        // bank of word i
    mk = m[2*i +: 2];
  endfunction
  function [4:0] ma(input [27:0] m, input [1:0] i);        // address of word i
    ma = m[8 + 5*i +: 5];
  endfunction

  // --- read ports -----------------------------------------------------------------
  always @* begin
    c_re = 4'b0000;  c_raddr = 20'd0;
    a_re = 4'b0000;  a_raddr = 20'd0;
    b_re = 4'b0000;  b_raddr = 20'd0;
    if (iss) begin
      if (is_ntt) begin
        c_re = 4'b1111;
        c_raddr[5*bank_of(w00) +: 5] = w00[6:2];
        c_raddr[5*bank_of(w10) +: 5] = w10[6:2];
        c_raddr[5*bank_of(w01) +: 5] = w01[6:2];
        c_raddr[5*bank_of(w11) +: 5] = w11[6:2];
      end else if (op == OP_PWM) begin
        c_re = acc ? ((4'b0001 << pk_a) | (4'b0001 << pk_b)) : 4'b0000;
        a_re = (4'b0001 << pk_a) | (4'b0001 << pk_b);
        b_re = a_re;
        c_raddr = {4{cnt[5:1]}};
        a_raddr = {4{cnt[5:1]}};
        b_raddr = {4{cnt[5:1]}};
      end else begin
        c_re = 4'b1111;
        a_re = 4'b1111;
        c_raddr = {4{cnt[4:0]}};
        a_raddr = {4{cnt[4:0]}};
      end
    end
    // fused INTT: read a's four words at vld[5]; they land in aq at vld[6]
    // and are ready, from a register, with the butterfly results at vld[7]
    if (fz && vld[5]) begin
      a_re = 4'b1111;
      for (k3 = 0; k3 < 4; k3 = k3 + 1)
        a_raddr[5*mk(md5, k3) +: 5] = ma(md5, k3);
    end
  end

  // --- input registers ------------------------------------------------------------
  // The RAM data (after the 12-slot mux in mlkem2_polymem) is registered here,
  // before any arithmetic: no path runs from a RAM output through an adder or
  // multiplier in one clock (Quartus: "Long Combinational Path" / "Chained
  // Adders" from polymem to mlkem2_bfu). Loaded only when the data is used.
  reg  [95:0] cq, aq, bq;
  wire        c_ld = vld[1] && !(op == OP_PWM && !acc);
  wire        a_ld = is_ntt ? (fz && vld[6]) : vld[1];
  wire        b_ld = vld[1] && (op == OP_PWM);
  always @(posedge clk) begin
    if (c_ld) cq <= c_rdata;
    if (a_ld) aq <= a_rdata;
    if (b_ld) bq <= b_rdata;
  end

  // --- butterflies (inputs at vld[2], outputs 5 clocks later at vld[7]) -----------
  wire [23:0] d00 = cq[24*mk(md2, 2'd0) +: 24];
  wire [23:0] d10 = cq[24*mk(md2, 2'd1) +: 24];
  wire [23:0] d01 = cq[24*mk(md2, 2'd2) +: 24];
  wire [23:0] d11 = cq[24*mk(md2, 2'd3) +: 24];
  wire        ben = vld[2] && is_ntt;
  wire        intt = (op == OP_INTT);
  wire [11:0] o0a, o0b, o1a, o1b, o2a, o2b, o3a, o3b;

  mlkem2_bfu u_bf0 (.clk(clk), .en(ben), .intt(intt), .a(d00[11:0]),  .b(d10[11:0]),  .z(z0q), .oa(o0a), .ob(o0b));
  mlkem2_bfu u_bf1 (.clk(clk), .en(ben), .intt(intt), .a(d00[23:12]), .b(d10[23:12]), .z(z0q), .oa(o1a), .ob(o1b));
  mlkem2_bfu u_bf2 (.clk(clk), .en(ben), .intt(intt), .a(d01[11:0]),  .b(d11[11:0]),  .z(z1q), .oa(o2a), .ob(o2b));
  mlkem2_bfu u_bf3 (.clk(clk), .en(ben), .intt(intt), .a(d01[23:12]), .b(d11[23:12]), .z(z1q), .oa(o3a), .ob(o3b));

  // results for words w00, w10, w01, w11 (valid with vld[7])
  wire [23:0] r00 = {o1a, o0a};
  wire [23:0] r10 = {o1b, o0b};
  wire [23:0] r01 = {o3a, o2a};
  wire [23:0] r11 = {o3b, o2b};

  // --- base-case multipliers (PWM, inputs at vld[2], outputs at vld[12]) ----------
  wire [1:0]  qa  = mk(md2, 2'd0);             // bank of word 2j
  wire [1:0]  qb  = mk(md2, 2'd1);             // bank of word 2j+1
  wire [23:0] pa0 = aq[24*qa +: 24];
  wire [23:0] pb0 = bq[24*qa +: 24];
  wire [23:0] pc0 = acc ? cq[24*qa +: 24] : 24'd0;
  wire [23:0] pa1 = aq[24*qb +: 24];
  wire [23:0] pb1 = bq[24*qb +: 24];
  wire [23:0] pc1 = acc ? cq[24*qb +: 24] : 24'd0;
  wire        men = vld[2] && (op == OP_PWM);
  wire [11:0] ge  = z0q;                        // +zeta for the even word
  wire [11:0] go  = 12'd3329 - z0q;             // -zeta for the odd word
  wire [11:0] pe0, po0, pe1, po1;

  mlkem2_basemul u_bm0 (.clk(clk), .en(men),
                        .a0(pa0[11:0]), .a1(pa0[23:12]), .b0(pb0[11:0]), .b1(pb0[23:12]),
                        .c0(pc0[11:0]), .c1(pc0[23:12]), .g(ge), .e(pe0), .o(po0));
  mlkem2_basemul u_bm1 (.clk(clk), .en(men),
                        .a0(pa1[11:0]), .a1(pa1[23:12]), .b0(pb1[11:0]), .b1(pb1[23:12]),
                        .c0(pc1[11:0]), .c1(pc1[23:12]), .g(go), .e(pe1), .o(po1));

  // --- ADD/SUB (element-wise over the 4 banks; add at vld[2], write at vld[3]) ------
  reg [95:0] ew;
  always @(posedge clk) begin
    if (vld[2] && (op == OP_ADD || op == OP_SUB))
      for (k2 = 0; k2 < 4; k2 = k2 + 1)
        ew[24*k2 +: 24] <= (op == OP_SUB) ? subw(cq[24*k2 +: 24], aq[24*k2 +: 24])
                                          : addw(cq[24*k2 +: 24], aq[24*k2 +: 24]);
  end

  // --- write back ----------------------------------------------------------------------
  // fused last INTT layer: combine a result x with a's word y (from aq)
  function [23:0] fuse_w(input [23:0] x, input [23:0] y, input [1:0] f);
    fuse_w = (f == 2'd1) ? addw(x, y) : subw(y, x);
  endfunction

  reg [95:0] rw;    // butterfly results placed in their banks
  always @* begin
    c_we    = 4'b0000;
    c_waddr = 20'd0;
    c_wdata = 96'd0;
    rw      = 96'd0;
    if (is_ntt) begin
      if (vld[7]) begin
        c_we = 4'b1111;
        c_waddr[5*mk(md7, 2'd0) +: 5] = ma(md7, 2'd0);
        c_waddr[5*mk(md7, 2'd1) +: 5] = ma(md7, 2'd1);
        c_waddr[5*mk(md7, 2'd2) +: 5] = ma(md7, 2'd2);
        c_waddr[5*mk(md7, 2'd3) +: 5] = ma(md7, 2'd3);
        rw[24*mk(md7, 2'd0) +: 24] = r00;
        rw[24*mk(md7, 2'd1) +: 24] = r10;
        rw[24*mk(md7, 2'd2) +: 24] = r01;
        rw[24*mk(md7, 2'd3) +: 24] = r11;
        for (k4 = 0; k4 < 4; k4 = k4 + 1)
          c_wdata[24*k4 +: 24] = fz ? fuse_w(rw[24*k4 +: 24], aq[24*k4 +: 24], fuse)
                                    : rw[24*k4 +: 24];
      end
    end else if (op == OP_PWM) begin
      if (vld[12]) begin
        c_we = (4'b0001 << mk(md12, 2'd0)) | (4'b0001 << mk(md12, 2'd1));
        c_waddr = {4{ma(md12, 2'd0)}};
        c_wdata[24*mk(md12, 2'd0) +: 24] = {po0, pe0};
        c_wdata[24*mk(md12, 2'd1) +: 24] = {po1, pe1};
      end
    end else begin
      if (vld[3]) begin
        c_we    = 4'b1111;
        c_waddr = {4{ma(md3, 2'd0)}};
        c_wdata = ew;
      end
    end
  end
endmodule
