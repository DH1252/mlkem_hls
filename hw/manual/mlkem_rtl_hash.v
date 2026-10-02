// -----------------------------------------------------------------------------
// mlkem_rtl_hash.v - the Keccak engine of the hand-written ML-KEM-768 core.
//
//   mlkem_keccak_round  one Keccak-f[1600] round, combinational
//   mlkem_parse         SampleNTT rejection sampler (FIPS 203 Alg. 7)
//   mlkem_cbd2          SamplePolyCBD_2 (FIPS 203 Alg. 8, eta = 2)
//   mlkem_hash          sponge engine: absorb from the mailbox or a seed
//                       register, pad, squeeze into a seed register or
//                       straight into a sampler
//
// The permutation runs one round per clock (24 clocks). Input and output
// move one 64-bit lane per clock (mailbox input: one lane per 2 clocks,
// because it arrives through one 32-bit port).
//
// UNTESTED FIRST VERSION - see hw/manual/README.md.
// -----------------------------------------------------------------------------

module mlkem_keccak_round (
  input  wire [1599:0] si,
  input  wire [63:0]   rc,
  output reg  [1599:0] so
);
  // rotation offsets r[x + 5y] (FIPS 202 Table 2)
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

  reg [63:0] a  [0:24];   // input
  reg [63:0] t  [0:24];   // after theta
  reg [63:0] b  [0:24];   // after rho and pi
  reg [63:0] cc [0:4];
  reg [63:0] dd [0:4];
  integer i, x, y;

  always @* begin
    for (i = 0; i < 25; i = i + 1)
      a[i] = si[64*i +: 64];
    // theta
    for (x = 0; x < 5; x = x + 1)
      cc[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20];
    for (x = 0; x < 5; x = x + 1)
      dd[x] = cc[(x+4) % 5] ^ rol(cc[(x+1) % 5], 1);
    for (i = 0; i < 25; i = i + 1)
      t[i] = a[i] ^ dd[i % 5];
    // rho and pi: lane (x, y) moves to (y, 2x + 3y) and is rotated
    for (x = 0; x < 5; x = x + 1)
      for (y = 0; y < 5; y = y + 1)
        b[y + 5*((2*x + 3*y) % 5)] = rol(t[x + 5*y], rho(x + 5*y));
    // chi and iota
    for (x = 0; x < 5; x = x + 1)
      for (y = 0; y < 5; y = y + 1)
        so[64*(x + 5*y) +: 64] = b[x + 5*y] ^ (~b[(x+1) % 5 + 5*y] & b[(x+2) % 5 + 5*y])
                                 ^ ((x == 0 && y == 0) ? rc : 64'd0);
  end
endmodule


// -----------------------------------------------------------------------------
// SampleNTT: takes the SHAKE128 stream one lane at a time, cuts it into 3-byte
// groups, each giving two 12-bit candidates; keeps those below q until 256
// coefficients are written (one word = two coefficients per write).
// -----------------------------------------------------------------------------
module mlkem_parse (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire        in_valid,
  input  wire [63:0] in_lane,
  output wire        in_ready,
  output wire        done,
  output wire [11:0] waddr,
  output wire [47:0] wdata,
  output wire [1:0]  wen
);
  reg [127:0] sbuf;    // stream bytes, oldest in [7:0]
  reg   [4:0] bcnt;    // bytes held (0..16)
  reg   [8:0] n;       // coefficients accepted
  reg  [11:0] pend;    // an accepted coefficient waiting for its partner
  reg         pv;
  reg   [6:0] widx;    // next word to write
  reg         fin;

  wire        can  = !fin && (bcnt >= 5'd3);
  wire  [7:0] b0   = sbuf[7:0];
  wire  [7:0] b1   = sbuf[15:8];
  wire  [7:0] b2   = sbuf[23:16];
  wire [11:0] d1   = {b1[3:0], b0};
  wire [11:0] d2   = {b2, b1[7:4]};
  wire        a1   = can && (d1 < 12'd3329);
  wire  [8:0] n1   = n + {8'd0, a1};
  wire        a2   = can && (d2 < 12'd3329) && (n1 < 9'd256);
  wire  [8:0] nn   = n1 + {8'd0, a2};
  wire  [4:0] bc_a = can ? (bcnt - 5'd3) : bcnt;
  assign in_ready  = !fin && (bc_a <= 5'd8);
  wire        take = in_valid && in_ready;

  // accepted values in stream order: pend (if any), d1 (if a1), d2 (if a2)
  wire  [1:0] kk   = {1'b0, pv} + {1'b0, a1} + {1'b0, a2};
  wire [11:0] v0   = pv ? pend : (a1 ? d1 : d2);
  wire [11:0] v1   = pv ? (a1 ? d1 : d2) : d2;
  wire        wr   = (kk >= 2'd2);

  assign wen   = wr ? ((^widx) ? 2'b10 : 2'b01) : 2'b00;
  assign waddr = {widx[6:1], widx[6:1]};
  assign wdata = {v1, v0, v1, v0};
  assign done  = fin;

  always @(posedge clk) begin
    if (rst || start) begin
      bcnt <= 5'd0;
      n    <= 9'd0;
      pv   <= 1'b0;
      widx <= 7'd0;
      fin  <= 1'b0;
      sbuf <= 128'd0;
    end else begin
      sbuf <= (can ? (sbuf >> 24) : sbuf)
            | (take ? ({64'd0, in_lane} << {bc_a, 3'b000}) : 128'd0);
      bcnt <= bc_a + (take ? 5'd8 : 5'd0);
      n    <= nn;
      if (nn == 9'd256) fin <= 1'b1;
      if (wr) widx <= widx + 7'd1;
      case (kk)
        2'd0: ;
        2'd1: begin pend <= v0; pv <= 1'b1; end
        2'd2: pv <= 1'b0;
        default: begin pend <= d2; pv <= 1'b1; end
      endcase
    end
  end
endmodule


// -----------------------------------------------------------------------------
// SamplePolyCBD_2: each byte of the PRF output gives one word: low nibble ->
// even coefficient, high nibble -> odd coefficient, value (b0+b1) - (b2+b3).
// A lane (8 bytes = 8 words) is written in 4 clocks, two words per clock
// (words 2m and 2m+1 are in different banks at the same address m).
// -----------------------------------------------------------------------------
module mlkem_cbd2 (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire        in_valid,
  input  wire [63:0] in_lane,
  output wire        in_ready,
  output wire        done,
  output wire [11:0] waddr,
  output wire [47:0] wdata,
  output wire [1:0]  wen
);
  function [11:0] cbdv(input [3:0] nb);
    reg [1:0] x, y;
    begin
      x = {1'b0, nb[0]} + {1'b0, nb[1]};
      y = {1'b0, nb[2]} + {1'b0, nb[3]};
      if (x >= y) cbdv = {10'd0, x - y};
      else        cbdv = 12'd3329 - {10'd0, y - x};
    end
  endfunction

  reg [63:0] lane;
  reg        lv;      // a lane is being written
  reg  [1:0] c;       // word pair within the lane
  reg  [3:0] li;      // index of the lane being written
  reg  [4:0] la;      // lanes accepted

  assign in_ready = (la < 5'd16) && (!lv || (c == 2'd3));
  wire   take     = in_valid && in_ready;

  wire  [5:0] m   = {li, c};                  // word pair address: words 2m, 2m+1
  wire  [7:0] ba  = lane[16*c +: 8];          // byte 2c
  wire  [7:0] bb  = lane[16*c + 8 +: 8];      // byte 2c+1
  wire [23:0] wa_ = {cbdv(ba[7:4]), cbdv(ba[3:0])};
  wire [23:0] wb_ = {cbdv(bb[7:4]), cbdv(bb[3:0])};

  assign wen   = lv ? 2'b11 : 2'b00;
  assign waddr = {m, m};
  assign wdata = (^m) ? {wa_, wb_} : {wb_, wa_};   // word 2m goes to bank parity(m)
  assign done  = (la == 5'd16) && !lv;

  always @(posedge clk) begin
    if (rst || start) begin
      lv <= 1'b0;
      la <= 5'd0;
      c  <= 2'd0;
    end else if (take) begin
      lane <= in_lane;
      lv   <= 1'b1;
      c    <= 2'd0;
      li   <= la[3:0];
      la   <= la + 5'd1;
    end else if (lv) begin
      if (c == 2'd3) lv <= 1'b0;
      c <= c + 2'd1;
    end
  end
endmodule


// -----------------------------------------------------------------------------
// Keccak sponge engine. One job = init, absorb part 1 (and part 2), pad,
// squeeze. The permutation runs lazily: only when a lane is needed from a
// full block. Jobs:
//   rate 168/136/72 bytes, pad 0x1F (SHAKE) or 0x06 (SHA3)
//   parts: n lanes from the mailbox (lane address) or 4 lanes from a seed
//          register; an optional 0..2-byte suffix before the padding
//   output: seed registers (n lanes: 0..3 -> oe0, 4..7 -> oe1),
//           SamplePolyCBD_2 into a slot, or SampleNTT into a slot
// -----------------------------------------------------------------------------
module mlkem_hash (
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
  // mailbox port B (reads)
  output wire        mb_active,
  output wire [10:0] mb_addr,
  input  wire [31:0] mb_rdata,
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
  output wire [11:0] s_waddr,
  output wire [47:0] s_wdata,
  output wire [1:0]  s_wen
);
  localparam [2:0] HS_IDLE = 3'd0, HS_ABS = 3'd1, HS_FIN = 3'd2,
                   HS_SQZ  = 3'd3, HS_PERM = 3'd4, HS_WAIT = 3'd5;
  localparam [1:0] OM_SEED = 2'd0, OM_CBD = 2'd1, OM_SAMP = 2'd2;

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
  reg           have_lo;
  reg  [31:0]   lo_w;
  reg           shake, p1s, p2s;
  reg  [9:0]    p1a, p2a;
  reg  [7:0]    p1n, p2n;
  reg  [1:0]    sfn, om;
  reg  [15:0]   sfx;
  reg  [2:0]    oe0, oe1;
  reg  [3:0]    onum, oslot;

  assign busy = start | (hs != HS_IDLE);

  wire       cur_seed = part ? p2s : p1s;
  wire [9:0] cur_addr = part ? p2a : p1a;
  wire [7:0] cur_n    = part ? p2n : p1n;

  // --- mailbox lane input (two 32-bit words per lane, port B) -----------------
  wire        rs_valid, rs_active;
  wire [31:0] rs_data;
  wire        in_abs    = (hs == HS_ABS);
  wire        lane_ok   = cur_seed ? 1'b1 : (have_lo && rs_valid);
  wire        absorb    = in_abs && (pos != rl) && lane_ok;
  wire        part_last = (lcnt == cur_n - 8'd1);
  wire        p2_go     = absorb && part_last && !part && (p2n != 8'd0) && !p2s;
  wire        rs_ready  = in_abs && !cur_seed && (!have_lo || absorb);
  wire        rs_start  = (start && (hs == HS_IDLE) && !p1s_in) || p2_go;
  wire [10:0] rs_base   = start ? {p1a_in, 1'b0} : {p2a, 1'b0};
  wire [11:0] rs_count  = start ? {3'd0, p1n_in, 1'b0} : {3'd0, p2n, 1'b0};

  mlkem_rd_stream u_rs (
    .clk      (clk),
    .rst      (rst),
    .start    (rs_start),
    .base     (rs_base),
    .count    (rs_count),
    .ram_addr (mb_addr),
    .ram_rdata(mb_rdata),
    .active   (rs_active),
    .out_valid(rs_valid),
    .out_data (rs_data),
    .out_ready(rs_ready)
  );
  assign mb_active = rs_active;

  assign sr_ent  = cur_addr[2:0];
  assign sr_lane = lcnt[1:0];
  wire [63:0] lane_in = cur_seed ? sr_data : {rs_data, lo_w};

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

  wire [11:0] sp_waddr, cb_waddr;
  wire [47:0] sp_wdata, cb_wdata;
  wire [1:0]  sp_wen,   cb_wen;

  mlkem_parse u_parse (
    .clk(clk), .rst(rst),
    .start   (start && (hs == HS_IDLE) && (om_in == OM_SAMP)),
    .in_valid(sq_avail && (om == OM_SAMP)),
    .in_lane (sq_lane),
    .in_ready(samp_ready),
    .done    (samp_done),
    .waddr(sp_waddr), .wdata(sp_wdata), .wen(sp_wen)
  );

  mlkem_cbd2 u_cbd (
    .clk(clk), .rst(rst),
    .start   (start && (hs == HS_IDLE) && (om_in == OM_CBD)),
    .in_valid(sq_avail && (om == OM_CBD)),
    .in_lane (sq_lane),
    .in_ready(cbd_ready),
    .done    (cbd_done),
    .waddr(cb_waddr), .wdata(cb_wdata), .wen(cb_wen)
  );

  assign s_slot  = oslot;
  assign s_waddr = (om == OM_CBD) ? cb_waddr : sp_waddr;
  assign s_wdata = (om == OM_CBD) ? cb_wdata : sp_wdata;
  assign s_wen   = (om == OM_CBD) ? cb_wen : ((om == OM_SAMP) ? sp_wen : 2'b00);

  // --- permutation ---------------------------------------------------------------
  wire [1599:0] st_rnd;
  mlkem_keccak_round u_round (.si(st), .rc(rc_of(rnd)), .so(st_rnd));

  integer x;
  always @(posedge clk) begin
    if (start && (hs == HS_IDLE)) begin
      st <= 1600'd0;
    end else if (hs == HS_PERM) begin
      st <= st_rnd;
    end else if (absorb) begin
      for (x = 0; x < 25; x = x + 1)
        if (pos == x) st[64*x +: 64] <= st[64*x +: 64] ^ lane_in;
    end else if (fin_now) begin
      for (x = 0; x < 25; x = x + 1)
        st[64*x +: 64] <= st[64*x +: 64]
                        ^ ((pos == x)     ? fin_lane : 64'd0)
                        ^ ((rl == x + 1)  ? 64'h8000000000000000 : 64'd0);
    end
  end

  // --- control ----------------------------------------------------------------------
  always @(posedge clk) begin
    if (rst) begin
      hs <= HS_IDLE;
    end else begin
      case (hs)
        HS_IDLE: if (start) begin
          shake   <= shake_in;
          p1s     <= p1s_in;  p1a <= p1a_in;  p1n <= p1n_in;
          p2s     <= p2s_in;  p2a <= p2a_in;  p2n <= p2n_in;
          sfn     <= sfn_in;  sfx <= sfx_in;
          om      <= om_in;   oe0 <= oe0_in;  oe1 <= oe1_in;
          onum    <= on_in;   oslot <= oslot_in;
          rl      <= (rate_in == 2'd0) ? 5'd21 : (rate_in == 2'd1) ? 5'd17 : 5'd9;
          pos     <= 5'd0;
          part    <= 1'b0;
          lcnt    <= 8'd0;
          have_lo <= 1'b0;
          ocnt    <= 4'd0;
          hs      <= HS_ABS;
        end
        HS_ABS: begin
          if (!cur_seed && !have_lo && rs_valid) begin
            have_lo <= 1'b1;
            lo_w    <= rs_data;
          end
          if (pos == rl) begin
            hs   <= HS_PERM;
            hret <= HS_ABS;
            rnd  <= 5'd0;
          end else if (absorb) begin
            pos <= pos + 5'd1;
            if (!cur_seed) have_lo <= 1'b0;
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
          rnd <= rnd + 5'd1;
          if (rnd == 5'd23) begin
            hs  <= hret;
            pos <= 5'd0;
          end
        end
        default: hs <= HS_IDLE;
      endcase
    end
  end
endmodule
