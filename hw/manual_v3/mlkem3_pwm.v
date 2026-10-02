// -----------------------------------------------------------------------------
// mlkem3_pwm.v - pointwise engine of the v3 core. It runs next to the NTT
// engine (v2 had one ALU doing everything in turn).
//
//   op 2 PWM   c a b   c = (acc ? c : 0) + a o b   (FIPS 203 MultiplyNTTs)
//   op 3 ADD   c a     c = c + a
//   op 4 SUB   c a     c = c - a
//
// One aligned group (words 4a..4a+3, all at bank address a) per clock:
// PWM uses four base-case multipliers (v2: two), 32 + 12 = 44 clocks;
// ADD/SUB take 32 + 3 = 35 clocks.
// Word w holds the base-case pair (coefficients 2w, 2w+1); its gamma is
// zetas[64 + (w >> 1)], negated for odd w (as v2).
//
// Pipeline: 0 read, 1 input registers (+ gammas), 2 multipliers / adders
// start, PWM writes at 12, ADD/SUB at 3.
// Low power: c is only read when accumulating, b only for PWM; registers
// load only for valid items; the multipliers are idle during ADD/SUB.
//
// UNTESTED FIRST VERSION of v3 - see hw/manual_v3/README.md.
// -----------------------------------------------------------------------------
module mlkem3_pwm (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [2:0]  op_in,
  input  wire        acc_in,
  input  wire [3:0]  c_in,
  input  wire [3:0]  a_in,
  input  wire [3:0]  b_in,
  output wire        busy,
  // role P (c)
  output reg  [3:0]  p_slot,
  output reg  [3:0]  p_re,
  output reg  [19:0] p_raddr,
  input  wire [95:0] p_rdata,
  output reg  [3:0]  p_we,
  output reg  [19:0] p_waddr,
  output reg  [95:0] p_wdata,
  // role PA (a)
  output reg  [3:0]  pa_slot,
  output reg  [3:0]  pa_re,
  output reg  [19:0] pa_raddr,
  input  wire [95:0] pa_rdata,
  // role PB (b)
  output reg  [3:0]  pb_slot,
  output reg  [3:0]  pb_re,
  output reg  [19:0] pb_raddr,
  input  wire [95:0] pb_rdata
);
  localparam [2:0] OP_PWM = 3'd2, OP_ADD = 3'd3, OP_SUB = 3'd4;

  // zetas[64 + i], i = 0..63 (FIPS 203 Appendix A), the base-case gammas
  function [11:0] zg(input [5:0] i);
    case (i)
      6'd0:  zg = 12'd17;   6'd1:  zg = 12'd2761; 6'd2:  zg = 12'd583;  6'd3:  zg = 12'd2649;
      6'd4:  zg = 12'd1637; 6'd5:  zg = 12'd723;  6'd6:  zg = 12'd2288; 6'd7:  zg = 12'd1100;
      6'd8:  zg = 12'd1409; 6'd9:  zg = 12'd2662; 6'd10: zg = 12'd3281; 6'd11: zg = 12'd233;
      6'd12: zg = 12'd756;  6'd13: zg = 12'd2156; 6'd14: zg = 12'd3015; 6'd15: zg = 12'd3050;
      6'd16: zg = 12'd1703; 6'd17: zg = 12'd1651; 6'd18: zg = 12'd2789; 6'd19: zg = 12'd1789;
      6'd20: zg = 12'd1847; 6'd21: zg = 12'd952;  6'd22: zg = 12'd1461; 6'd23: zg = 12'd2687;
      6'd24: zg = 12'd939;  6'd25: zg = 12'd2308; 6'd26: zg = 12'd2437; 6'd27: zg = 12'd2388;
      6'd28: zg = 12'd733;  6'd29: zg = 12'd2337; 6'd30: zg = 12'd268;  6'd31: zg = 12'd641;
      6'd32: zg = 12'd1584; 6'd33: zg = 12'd2298; 6'd34: zg = 12'd2037; 6'd35: zg = 12'd3220;
      6'd36: zg = 12'd375;  6'd37: zg = 12'd2549; 6'd38: zg = 12'd2090; 6'd39: zg = 12'd1645;
      6'd40: zg = 12'd1063; 6'd41: zg = 12'd319;  6'd42: zg = 12'd2773; 6'd43: zg = 12'd757;
      6'd44: zg = 12'd2099; 6'd45: zg = 12'd561;  6'd46: zg = 12'd2466; 6'd47: zg = 12'd2594;
      6'd48: zg = 12'd2804; 6'd49: zg = 12'd1092; 6'd50: zg = 12'd403;  6'd51: zg = 12'd1026;
      6'd52: zg = 12'd1143; 6'd53: zg = 12'd2150; 6'd54: zg = 12'd2775; 6'd55: zg = 12'd886;
      6'd56: zg = 12'd1722; 6'd57: zg = 12'd1212; 6'd58: zg = 12'd1874; 6'd59: zg = 12'd1029;
      6'd60: zg = 12'd2110; 6'd61: zg = 12'd2935; 6'd62: zg = 12'd885;  default: zg = 12'd2154;
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

  function [1:0] bank_of(input [6:0] w);
    bank_of = {^(w & 7'b0101010), ^(w & 7'b1010101)};
  endfunction

  // --- control --------------------------------------------------------------
  reg        busy_r, run;
  reg  [2:0] op;
  reg        acc;
  reg  [4:0] cnt;
  reg [12:1] vld;
  reg  [4:0] md [1:12];     // group index a of the item at each stage
  integer    k, j0, j1, j2;

  wire is_pwm = (op == OP_PWM);
  wire iss    = run;
  wire pipe_empty = is_pwm ? (vld == 12'd0) : (vld[3:1] == 3'd0);

  assign busy = start | busy_r;

  always @(posedge clk) begin
    if (rst) begin
      busy_r <= 1'b0;
      run    <= 1'b0;
      vld    <= 12'd0;
    end else begin
      vld <= start ? 12'd0 : {vld[11:1], iss};
      if (start) begin
        op      <= op_in;
        acc     <= acc_in;
        p_slot  <= c_in;
        pa_slot <= a_in;
        pb_slot <= b_in;
        busy_r  <= 1'b1;
        run     <= 1'b1;
        cnt     <= 5'd0;
      end else if (run) begin
        cnt <= cnt + 5'd1;
        if (cnt == 5'd31) run <= 1'b0;
      end else if (busy_r && pipe_empty) begin
        busy_r <= 1'b0;
      end
    end
  end

  always @(posedge clk) begin
    if (iss) md[1] <= cnt;
    for (k = 2; k <= 12; k = k + 1)
      if (vld[k-1]) md[k] <= md[k-1];
  end

  wire [4:0] md1 = md[1], md2 = md[2], md3 = md[3], md12 = md[12];

  // --- stage 0: reads (one aligned group, same address in all banks) --------
  always @* begin
    p_re  = 4'b0000;  p_raddr  = {4{cnt}};
    pa_re = 4'b0000;  pa_raddr = {4{cnt}};
    pb_re = 4'b0000;  pb_raddr = {4{cnt}};
    if (iss) begin
      p_re  = (is_pwm && !acc) ? 4'b0000 : 4'b1111;
      pa_re = 4'b1111;
      pb_re = is_pwm ? 4'b1111 : 4'b0000;
    end
  end

  // --- stage 1: input registers and gammas ----------------------------------
  reg [95:0] cq, aq, bq;
  reg [11:0] zq0, zq1;          // zetas[64 + 2a], zetas[64 + 2a + 1]
  always @(posedge clk) begin
    if (vld[1]) begin
      if (!is_pwm || acc) cq <= p_rdata;
      aq <= pa_rdata;
      if (is_pwm) begin
        bq  <= pb_rdata;
        zq0 <= zg({md1, 1'b0});
        zq1 <= zg({md1, 1'b1});
      end
    end
  end

  // --- stage 2: base-case multipliers (outputs at stage 12) -------------------
  wire        men = vld[2] && is_pwm;
  wire [47:0] pe_all, po_all;   // results of word 4a + j at [12*j +: 12]

  genvar j;
  generate
    for (j = 0; j < 4; j = j + 1) begin : g_bm
      wire [1:0]  bk = bank_of({md2, 2'b00} | j);        // word 4a + j
      wire [23:0] wa = aq[24*bk +: 24];
      wire [23:0] wb = bq[24*bk +: 24];
      wire [23:0] wc = acc ? cq[24*bk +: 24] : 24'd0;
      wire [11:0] z  = (j >= 2) ? zq1 : zq0;              // words 4a, 4a+1: 2a; 4a+2, 4a+3: 2a+1
      wire [11:0] gm = (j % 2 == 1) ? (12'd3329 - z) : z; // odd word: -zeta
      mlkem3_basemul u_bm (
        .clk(clk), .en(men),
        .a0(wa[11:0]), .a1(wa[23:12]), .b0(wb[11:0]), .b1(wb[23:12]),
        .c0(wc[11:0]), .c1(wc[23:12]), .g(gm), .e(pe_all[12*j +: 12]), .o(po_all[12*j +: 12])
      );
    end
  endgenerate

  // --- ADD/SUB: element-wise in bank order, add at stage 2, write at 3 ---------
  reg [95:0] ew;
  always @(posedge clk) begin
    if (vld[2] && !is_pwm)
      for (j0 = 0; j0 < 4; j0 = j0 + 1)
        ew[24*j0 +: 24] <= (op == OP_SUB)
          ? {subq(cq[24*j0 + 12 +: 12], aq[24*j0 + 12 +: 12]), subq(cq[24*j0 +: 12], aq[24*j0 +: 12])}
          : {addq(cq[24*j0 + 12 +: 12], aq[24*j0 + 12 +: 12]), addq(cq[24*j0 +: 12], aq[24*j0 +: 12])};
  end

  // --- write back ----------------------------------------------------------------
  reg [1:0] wbk;
  always @* begin
    p_we    = 4'b0000;
    p_waddr = 20'd0;
    p_wdata = 96'd0;
    wbk     = 2'd0;
    if (is_pwm) begin
      if (vld[12]) begin
        p_we    = 4'b1111;
        p_waddr = {4{md12}};
        for (j1 = 0; j1 < 4; j1 = j1 + 1) begin
          wbk = bank_of({md12, 2'b00} | j1);
          p_wdata[24*wbk +: 24] = {po_all[12*j1 +: 12], pe_all[12*j1 +: 12]};
        end
      end
    end else if (vld[3]) begin
      p_we    = 4'b1111;
      p_waddr = {4{md3}};
      p_wdata = ew;
    end
  end
endmodule
