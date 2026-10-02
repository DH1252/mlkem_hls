// -----------------------------------------------------------------------------
// mlkem2_hash.v - Keccak engine of the v2 core.
//
//   mlkem2_keccak_round  one Keccak-f[1600] round, combinational (as v1)
//   mlkem2_hash          sponge engine: absorb from the mailbox (64-bit lanes)
//                        or seed registers, pad, squeeze into seed registers
//                        or into the samplers (mlkem2_sample.v)
//
// Speed changes against v1:
//   - KR rounds per clock (parameter, 1 or 2): permutation in 24/KR clocks
//   - mailbox input is one 64-bit lane per clock (v1: one per two clocks),
//     so H(ek) and J(z||c) absorb twice as fast
//   - SampleNTT consumes 6 bytes/clock, CBD writes 4 words/clock
// Power: the 1600-bit state only loads while absorbing, padding or
// permuting; mailbox reads are strobed; KR = 1 halves the combinational
// depth (less glitching) for lowest-power builds.
//
// UNTESTED FIRST VERSION - see hw/manual_v2/README.md.
// -----------------------------------------------------------------------------

module mlkem2_keccak_round (
  input  wire [1599:0] si,
  input  wire [63:0]   rc,
  output reg  [1599:0] so
);
  function integer rho(input integer i);
    case (i)
      0:  rho = 0;   1:  rho = 1;   2:  rho = 62;  3:  rho = 28;  4:  rho = 27;
      5:  rho = 36;  6:  rho = 44;  7:  rho = 6;   8:  rho = 55;  9:  rho = 20;
      10: rho = 3;   11: rho = 10;  12: rho = 43;  13: rho = 25;  14: rho = 39;
      15: rho = 41;  16: rho = 45;  17: rho = 15;  18: rho = 21;  19: rho = 8;
      20: rho = 18;  21: rho = 2;   22: rho = 61;  23: rho = 56;  default: rho = 14;
    endcase
  endfunction

  function [63:0] rol(input [63:0] v, input integer n);
    rol = (n == 0) ? v : ((v << n) | (v >> (64 - n)));
  endfunction

  reg [63:0] a  [0:24];
  reg [63:0] t  [0:24];
  reg [63:0] b  [0:24];
  reg [63:0] cc [0:4];
  reg [63:0] dd [0:4];
  integer i, x, y;

  always @* begin
    for (i = 0; i < 25; i = i + 1)
      a[i] = si[64*i +: 64];
    for (x = 0; x < 5; x = x + 1)
      cc[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20];
    for (x = 0; x < 5; x = x + 1)
      dd[x] = cc[(x+4) % 5] ^ rol(cc[(x+1) % 5], 1);
    for (i = 0; i < 25; i = i + 1)
      t[i] = a[i] ^ dd[i % 5];
    for (x = 0; x < 5; x = x + 1)
      for (y = 0; y < 5; y = y + 1)
        b[y + 5*((2*x + 3*y) % 5)] = rol(t[x + 5*y], rho(x + 5*y));
    for (x = 0; x < 5; x = x + 1)
      for (y = 0; y < 5; y = y + 1)
        so[64*(x + 5*y) +: 64] = b[x + 5*y] ^ (~b[(x+1) % 5 + 5*y] & b[(x+2) % 5 + 5*y])
                                 ^ ((x == 0 && y == 0) ? rc : 64'd0);
  end
endmodule


module mlkem2_hash #(
  parameter KR = 2              // Keccak rounds per clock: 1 or 2
) (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [1:0]  rate_in,     // 0: 168 bytes, 1: 136, 2: 72
  input  wire        shake_in,
  input  wire        p1s_in,      // part 1 from a seed register
  input  wire [9:0]  p1a_in,      // mailbox lane address or seed entry
  input  wire [7:0]  p1n_in,      // lanes
  input  wire        p2s_in,
  input  wire [9:0]  p2a_in,
  input  wire [7:0]  p2n_in,      // 0: no part 2
  input  wire [1:0]  sfn_in,      // suffix bytes
  input  wire [15:0] sfx_in,      // suffix (first byte in [7:0])
  input  wire [1:0]  om_in,       // 0 seed, 1 CBD, 2 SampleNTT
  input  wire [2:0]  oe0_in,
  input  wire [2:0]  oe1_in,
  input  wire [3:0]  on_in,       // lanes out (seed mode)
  input  wire [3:0]  oslot_in,
  output wire        busy,
  // mailbox port B: 64-bit lane reads
  output wire        mb_active,
  output wire        mb_re,
  output wire [9:0]  mb_laddr,
  input  wire [63:0] mb_rdata,
  // seed registers
  output wire [2:0]  sr_ent,
  output wire [1:0]  sr_lane,
  input  wire [63:0] sr_data,
  output wire        sw_we,
  output wire [2:0]  sw_ent,
  output wire [1:0]  sw_lane,
  output wire [63:0] sw_data,
  // polynomial memory, role S
  output wire [3:0]  s_slot,
  output wire [3:0]  s_we,
  output wire [19:0] s_waddr,
  output wire [95:0] s_wdata
);
  localparam [2:0] HS_IDLE = 3'd0, HS_ABS = 3'd1, HS_FIN = 3'd2,
                   HS_SQZ  = 3'd3, HS_PERM = 3'd4, HS_WAIT = 3'd5;
  localparam [1:0] OM_SEED = 2'd0, OM_CBD = 2'd1, OM_SAMP = 2'd2;
  localparam [4:0] RSTEP = KR;
  localparam [4:0] RLAST = 5'd24 - KR;

  function [63:0] rc_of(input [4:0] r);
    case (r)
      5'd0:  rc_of = 64'h0000000000000001; 5'd1:  rc_of = 64'h0000000000008082;
      5'd2:  rc_of = 64'h800000000000808A; 5'd3:  rc_of = 64'h8000000080008000;
      5'd4:  rc_of = 64'h000000000000808B; 5'd5:  rc_of = 64'h0000000080000001;
      5'd6:  rc_of = 64'h8000000080008081; 5'd7:  rc_of = 64'h8000000000008009;
      5'd8:  rc_of = 64'h000000000000008A; 5'd9:  rc_of = 64'h0000000000000088;
      5'd10: rc_of = 64'h0000000080008009; 5'd11: rc_of = 64'h000000008000000A;
      5'd12: rc_of = 64'h000000008000808B; 5'd13: rc_of = 64'h800000000000008B;
      5'd14: rc_of = 64'h8000000000008089; 5'd15: rc_of = 64'h8000000000008003;
      5'd16: rc_of = 64'h8000000000008002; 5'd17: rc_of = 64'h8000000000000080;
      5'd18: rc_of = 64'h000000000000800A; 5'd19: rc_of = 64'h800000008000000A;
      5'd20: rc_of = 64'h8000000080008081; 5'd21: rc_of = 64'h8000000000008080;
      5'd22: rc_of = 64'h0000000080000001; default: rc_of = 64'h8000000080008008;
    endcase
  endfunction

  reg  [2:0]    hs, hret;
  reg  [1599:0] st;
  reg  [4:0]    rl, pos, rnd;
  reg           part;
  reg  [7:0]    lcnt;
  reg  [3:0]    ocnt;
  reg           shake, p1s, p2s;
  reg  [9:0]    p1a, p2a;
  reg  [7:0]    p1n, p2n;
  reg  [1:0]    sfn, om;
  reg  [15:0]   sfx;
  reg  [2:0]    oe0, oe1;
  reg  [3:0]    onum, oslot;

  wire idle_start = start && (hs == HS_IDLE);
  assign busy = start | (hs != HS_IDLE);

  wire       cur_seed = part ? p2s : p1s;
  wire [9:0] cur_addr = part ? p2a : p1a;
  wire [7:0] cur_n    = part ? p2n : p1n;

  // --- input lanes ------------------------------------------------------------
  wire        rs_valid, rs_active;
  wire [63:0] rs_data;
  wire        in_abs    = (hs == HS_ABS);
  wire        lane_ok   = cur_seed ? 1'b1 : rs_valid;
  wire        absorb    = in_abs && (pos != rl) && lane_ok;
  wire        part_last = (lcnt == cur_n - 8'd1);
  wire        p2_go     = absorb && part_last && !part && (p2n != 8'd0) && !p2s;
  wire        rs_ready  = absorb && !cur_seed;
  wire        rs_start  = (idle_start && !p1s_in) || p2_go;
  wire [9:0]  rs_base   = idle_start ? p1a_in : p2a;
  wire [11:0] rs_count  = idle_start ? {4'd0, p1n_in} : {4'd0, p2n};

  mlkem2_rd_stream #(.DW(64), .AW(10)) u_rs (
    .clk      (clk),
    .rst      (rst),
    .start    (rs_start),
    .base     (rs_base),
    .count    (rs_count),
    .ram_re   (mb_re),
    .ram_addr (mb_laddr),
    .ram_rdata(mb_rdata),
    .active   (rs_active),
    .out_valid(rs_valid),
    .out_data (rs_data),
    .out_ready(rs_ready)
  );
  assign mb_active = rs_active;

  assign sr_ent  = cur_addr[2:0];
  assign sr_lane = lcnt[1:0];
  wire [63:0] lane_in = cur_seed ? sr_data : rs_data;

  // --- padding ------------------------------------------------------------------
  wire [7:0]  pad      = shake ? 8'h1F : 8'h06;
  wire [63:0] sfx_l    = (sfn == 2'd2) ? {48'd0, sfx} :
                         (sfn == 2'd1) ? {56'd0, sfx[7:0]} : 64'd0;
  wire [63:0] fin_lane = sfx_l | ({56'd0, pad} << {sfn, 3'b000});
  wire        fin_now  = (hs == HS_FIN) && (pos != rl);

  // --- squeeze --------------------------------------------------------------------
  wire [63:0] sq_lane = st[64*pos +: 64];
  wire        samp_ready, samp_done, cbd_ready, cbd_done;
  wire        sq_avail = (hs == HS_SQZ) && (pos != rl) && !(om == OM_SAMP && samp_done);
  wire        sq_take  = sq_avail && ((om == OM_SEED) ? 1'b1 :
                                      (om == OM_CBD)  ? cbd_ready : samp_ready);

  assign sw_we   = sq_take && (om == OM_SEED);
  assign sw_ent  = (ocnt < 4'd4) ? oe0 : oe1;
  assign sw_lane = ocnt[1:0];
  assign sw_data = sq_lane;

  wire [19:0] sp_waddr, cb_waddr;
  wire [95:0] sp_wdata, cb_wdata;
  wire [3:0]  sp_wen,   cb_wen;

  mlkem2_parse u_parse (
    .clk(clk), .rst(rst),
    .start   (idle_start && (om_in == OM_SAMP)),
    .in_valid(sq_avail && (om == OM_SAMP)),
    .in_lane (sq_lane),
    .in_ready(samp_ready),
    .done    (samp_done),
    .waddr(sp_waddr), .wdata(sp_wdata), .wen(sp_wen)
  );

  mlkem2_cbd u_cbd (
    .clk(clk), .rst(rst),
    .start   (idle_start && (om_in == OM_CBD)),
    .in_valid(sq_avail && (om == OM_CBD)),
    .in_lane (sq_lane),
    .in_ready(cbd_ready),
    .done    (cbd_done),
    .waddr(cb_waddr), .wdata(cb_wdata), .wen(cb_wen)
  );

  assign s_slot  = oslot;
  assign s_waddr = (om == OM_CBD) ? cb_waddr : sp_waddr;
  assign s_wdata = (om == OM_CBD) ? cb_wdata : sp_wdata;
  assign s_we    = (om == OM_CBD) ? cb_wen : ((om == OM_SAMP) ? sp_wen : 4'b0000);

  // --- permutation: KR rounds per clock ---------------------------------------------
  wire [1600*(KR+1)-1:0] rchain;
  assign rchain[1599:0] = st;
  genvar g;
  generate
    for (g = 0; g < KR; g = g + 1) begin : g_round
      mlkem2_keccak_round u_round (
        .si(rchain[1600*g +: 1600]),
        .rc(rc_of(rnd + g)),
        .so(rchain[1600*(g+1) +: 1600])
      );
    end
  endgenerate

  integer x;
  always @(posedge clk) begin
    if (idle_start) begin
      st <= 1600'd0;
    end else if (hs == HS_PERM) begin
      st <= rchain[1600*KR +: 1600];
    end else if (absorb) begin
      for (x = 0; x < 25; x = x + 1)
        if (pos == x) st[64*x +: 64] <= st[64*x +: 64] ^ lane_in;
    end else if (fin_now) begin
      for (x = 0; x < 25; x = x + 1)
        st[64*x +: 64] <= st[64*x +: 64]
                        ^ ((pos == x)    ? fin_lane : 64'd0)
                        ^ ((rl == x + 1) ? 64'h8000000000000000 : 64'd0);
    end
  end

  // --- control --------------------------------------------------------------------------
  always @(posedge clk) begin
    if (rst) begin
      hs <= HS_IDLE;
    end else begin
      case (hs)
        HS_IDLE: if (start) begin
          shake <= shake_in;
          p1s   <= p1s_in;  p1a <= p1a_in;  p1n <= p1n_in;
          p2s   <= p2s_in;  p2a <= p2a_in;  p2n <= p2n_in;
          sfn   <= sfn_in;  sfx <= sfx_in;
          om    <= om_in;   oe0 <= oe0_in;  oe1 <= oe1_in;
          onum  <= on_in;   oslot <= oslot_in;
          rl    <= (rate_in == 2'd0) ? 5'd21 : (rate_in == 2'd1) ? 5'd17 : 5'd9;
          pos   <= 5'd0;
          part  <= 1'b0;
          lcnt  <= 8'd0;
          ocnt  <= 4'd0;
          hs    <= HS_ABS;
        end
        HS_ABS: begin
          if (pos == rl) begin
            hs   <= HS_PERM;
            hret <= HS_ABS;
            rnd  <= 5'd0;
          end else if (absorb) begin
            pos <= pos + 5'd1;
            if (part_last) begin
              lcnt <= 8'd0;
              if (!part && (p2n != 8'd0)) part <= 1'b1;
              else                        hs   <= HS_FIN;
            end else begin
              lcnt <= lcnt + 8'd1;
            end
          end
        end
        HS_FIN: begin
          if (pos == rl) begin
            hs   <= HS_PERM;
            hret <= HS_FIN;
            rnd  <= 5'd0;
          end else begin
            pos <= rl;
            hs  <= HS_SQZ;
          end
        end
        HS_SQZ: begin
          if (om == OM_SAMP && samp_done) begin
            hs <= HS_IDLE;
          end else if (pos == rl) begin
            hs   <= HS_PERM;
            hret <= HS_SQZ;
            rnd  <= 5'd0;
          end else if (sq_take) begin
            pos  <= pos + 5'd1;
            ocnt <= ocnt + 4'd1;
            if (om == OM_SEED && ocnt == onum - 4'd1) hs <= HS_IDLE;
            if (om == OM_CBD  && ocnt == 4'd15)       hs <= HS_WAIT;
          end
        end
        HS_WAIT: if (cbd_done) hs <= HS_IDLE;
        HS_PERM: begin
          rnd <= rnd + RSTEP;
          if (rnd == RLAST) begin
            hs  <= hret;
            pos <= 5'd0;
          end
        end
        default: hs <= HS_IDLE;
      endcase
    end
  end
endmodule
