// -----------------------------------------------------------------------------
// mlkem3_hash.v - Keccak engine of the v3 core.
//
//   mlkem3_keccak_round  one Keccak-f[1600] round, combinational (as v2)
//   mlkem3_hash          sponge engine with a 21-lane block buffer
//
// v2 did everything in turn: absorb a lane per clock into the state, permute,
// squeeze a lane per clock from the state, permute again. v3 overlaps them
// with one block buffer `hb` (HPKA, IEEE TC 2023, uses separate input and
// output stages for the same reason):
//   absorb   lanes (mailbox: one 64-bit lane per clock, or seed registers)
//            are collected in hb while the previous block is being permuted;
//            a full block is XORed into the state in one clock.
//            H(ek): ~9 x 18 + 16 = ~180 clocks (v2 ~260).
//   squeeze  after a permutation the rate part of the state is copied to hb
//            in one clock; for SampleNTT the next permutation starts at once
//            and runs while the sampler reads hb (12 bytes per clock, 14
//            clocks per block, permutation 12 clocks at KR = 2).
//            SampleNTT: ~64 clocks per matrix entry (v2 ~130).
// The buffer is either an input or an output buffer, never both: within one
// job all absorbing ends before the first squeeze.
//
// Outputs: seed registers (G, H, J: a lane per clock), CBD (4 bytes per
// clock), SampleNTT (12 bytes per clock) - see mlkem3_sample.v.
//
// Power: the state only loads while permuting or absorbing a block, the
// buffer only when a lane arrives or a block is copied, mailbox reads are
// strobed, a finished SampleNTT stops the permutation at once, and KR = 1
// halves the combinational depth.
//
// UNTESTED FIRST VERSION of v3 - see hw/manual_v3/README.md.
// -----------------------------------------------------------------------------

module mlkem3_keccak_round (
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


module mlkem3_hash #(
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
  localparam [2:0] HS_IDLE = 3'd0, HS_LOAD = 3'd1, HS_FIN = 3'd2,
                   HS_SQZ  = 3'd3, HS_DRAIN = 3'd4;
  localparam [1:0] OM_SEED = 2'd0, OM_CBD = 2'd1, OM_SAMP = 2'd2;
  localparam [4:0] RSTEP = KR;
  localparam [4:0] RLAST = 5'd24 - KR;
  localparam [63:0] MSB = 64'h8000000000000000;

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

  reg  [2:0]    hs;
  reg  [1599:0] st;
  reg  [1343:0] hb;               // block buffer, lane L at [64*L +: 64]
  reg  [4:0]    rl, pos, rnd;
  reg           part;
  reg  [7:0]    lcnt;
  reg           shake, p1s, p2s;
  reg  [9:0]    p1a, p2a;
  reg  [7:0]    p1n, p2n;
  reg  [1:0]    sfn, om;
  reg  [15:0]   sfx;
  reg  [2:0]    oe0, oe1;
  reg  [3:0]    onum, oslot;
  reg           perm;             // permutation running
  reg           blk_rdy;          // hb holds a complete block to absorb
  reg           last_blk;         // ... the padded last one (then squeeze)
  reg           st_rdy;           // squeeze: permuted state not yet copied
  reg           ob_full;          // hb holds output not yet consumed
  reg  [4:0]    oidx;             // output item (lane / 4-byte / 12-byte chunk)

  wire idle_start = start && (hs == HS_IDLE);
  assign busy = start | (hs != HS_IDLE);

  wire       cur_seed = part ? p2s : p1s;
  wire [9:0] cur_addr = part ? p2a : p1a;
  wire [7:0] cur_n    = part ? p2n : p1n;

  // --- input lanes ------------------------------------------------------------
  wire        rs_valid, rs_active;
  wire [63:0] rs_data;
  wire        lane_ok   = cur_seed ? 1'b1 : rs_valid;
  wire        load      = (hs == HS_LOAD) && !blk_rdy && lane_ok;
  wire        part_last = (lcnt == cur_n - 8'd1);
  wire        p2_go     = load && part_last && !part && (p2n != 8'd0) && !p2s;
  wire        rs_ready  = load && !cur_seed;
  wire        rs_start  = (idle_start && !p1s_in) || p2_go;
  wire [9:0]  rs_base   = idle_start ? p1a_in : p2a;
  wire [11:0] rs_count  = idle_start ? {4'd0, p1n_in} : {4'd0, p2n};

  mlkem3_rd_stream #(.DW(64), .AW(10)) u_rs (
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

  // --- padding -------------------------------------------------------------------
  wire [7:0]  pad      = shake ? 8'h1F : 8'h06;
  wire [63:0] sfx_l    = (sfn == 2'd2) ? {48'd0, sfx} :
                         (sfn == 2'd1) ? {56'd0, sfx[7:0]} : 64'd0;
  wire [63:0] fin_lane = sfx_l | ({56'd0, pad} << {sfn, 3'b000});
  wire        fin_now  = (hs == HS_FIN) && !blk_rdy;
  wire [4:0]  rlm1     = rl - 5'd1;

  // --- output stage ------------------------------------------------------------------
  wire samp_full, samp_done;
  wire out_take = (hs == HS_SQZ) && ob_full && !((om == OM_SAMP) && samp_full);
  wire out_end  = (om == OM_SEED) ? (oidx == onum - 4'd1) :
                  (om == OM_CBD)  ? (oidx == 5'd31) : (oidx == 5'd13);
  wire out_last = out_take && out_end;
  wire out_free = !ob_full || out_last;

  // --- block moves ----------------------------------------------------------------------
  wire xor_now  = blk_rdy && !perm;
  wire copy_now = (hs == HS_SQZ) && st_rdy && !perm && out_free &&
                  !((om == OM_SAMP) && samp_full) &&
                  !((om != OM_SAMP) && ob_full);          // seed / CBD: one block only

  // --- permutation: KR rounds per clock ---------------------------------------------
  wire [1600*(KR+1)-1:0] rchain;
  assign rchain[1599:0] = st;
  genvar g;
  generate
    for (g = 0; g < KR; g = g + 1) begin : g_round
      mlkem3_keccak_round u_round (
        .si(rchain[1600*g +: 1600]),
        .rc(rc_of(rnd + g)),
        .so(rchain[1600*(g+1) +: 1600])
      );
    end
  endgenerate

  always @(posedge clk) begin
    if (idle_start)   st <= 1600'd0;
    else if (perm)    st <= rchain[1600*KR +: 1600];
    else if (xor_now) st <= st ^ {256'd0, hb};
  end

  always @(posedge clk) begin
    if (idle_start || xor_now) begin
      hb <= 1344'd0;
    end else if (copy_now) begin
      hb <= st[1343:0];
    end else if (load) begin
      hb[64*pos +: 64] <= lane_in;
    end else if (fin_now) begin
      hb[64*pos +: 64] <= fin_lane ^ ((pos == rlm1) ? MSB : 64'd0);
      if (pos != rlm1) hb[64*rlm1 +: 64] <= MSB;    // lanes after pos are zero
    end
  end

  // --- samplers ---------------------------------------------------------------------------
  // chunk indices kept inside the 21-lane buffer: 12-byte chunks 0..13,
  // 4-byte chunks 0..31, lanes 0..7
  wire [3:0]  cidx = (oidx < 5'd14) ? oidx[3:0] : 4'd0;
  wire [19:0] sp_waddr, cb_waddr;
  wire [95:0] sp_wdata, cb_wdata;
  wire [3:0]  sp_wen,   cb_wen;

  mlkem3_parse u_parse (
    .clk     (clk),
    .rst     (rst),
    .start   (idle_start && (om_in == OM_SAMP)),
    .in_valid(out_take && (om == OM_SAMP)),
    .in_chunk(hb[96*cidx +: 96]),
    .full    (samp_full),
    .done    (samp_done),
    .waddr   (sp_waddr),
    .wdata   (sp_wdata),
    .wen     (sp_wen)
  );

  mlkem3_cbd u_cbd (
    .clk     (clk),
    .rst     (rst),
    .start   (idle_start && (om_in == OM_CBD)),
    .in_valid(out_take && (om == OM_CBD)),
    .in_chunk(hb[32*oidx +: 32]),
    .in_group(oidx),
    .waddr   (cb_waddr),
    .wdata   (cb_wdata),
    .wen     (cb_wen)
  );

  assign s_slot  = oslot;
  assign s_waddr = (om == OM_CBD) ? cb_waddr : sp_waddr;
  assign s_wdata = (om == OM_CBD) ? cb_wdata : sp_wdata;
  assign s_we    = (om == OM_CBD) ? cb_wen : ((om == OM_SAMP) ? sp_wen : 4'b0000);

  assign sw_we   = out_take && (om == OM_SEED);
  assign sw_ent  = (oidx < 5'd4) ? oe0 : oe1;
  assign sw_lane = oidx[1:0];
  assign sw_data = hb[64*oidx[2:0] +: 64];

  // --- control ------------------------------------------------------------------------------
  always @(posedge clk) begin
    if (rst) begin
      hs       <= HS_IDLE;
      perm     <= 1'b0;
      blk_rdy  <= 1'b0;
      last_blk <= 1'b0;
      st_rdy   <= 1'b0;
      ob_full  <= 1'b0;
    end else begin
      // input side
      case (hs)
        HS_IDLE: if (start) begin
          shake    <= shake_in;
          p1s      <= p1s_in;  p1a <= p1a_in;  p1n <= p1n_in;
          p2s      <= p2s_in;  p2a <= p2a_in;  p2n <= p2n_in;
          sfn      <= sfn_in;  sfx <= sfx_in;
          om       <= om_in;   oe0 <= oe0_in;  oe1 <= oe1_in;
          onum     <= on_in;   oslot <= oslot_in;
          rl       <= (rate_in == 2'd0) ? 5'd21 : (rate_in == 2'd1) ? 5'd17 : 5'd9;
          pos      <= 5'd0;
          part     <= 1'b0;
          lcnt     <= 8'd0;
          perm     <= 1'b0;
          blk_rdy  <= 1'b0;
          last_blk <= 1'b0;
          st_rdy   <= 1'b0;
          ob_full  <= 1'b0;
          oidx     <= 5'd0;
          hs       <= HS_LOAD;
        end
        HS_LOAD: if (load) begin
          if (pos == rlm1) begin
            pos     <= 5'd0;
            blk_rdy <= 1'b1;
          end else begin
            pos <= pos + 5'd1;
          end
          if (part_last) begin
            lcnt <= 8'd0;
            if (!part && (p2n != 8'd0)) part <= 1'b1;
            else                        hs   <= HS_FIN;
          end else begin
            lcnt <= lcnt + 8'd1;
          end
        end
        HS_FIN: if (fin_now) begin
          blk_rdy  <= 1'b1;
          last_blk <= 1'b1;
          hs       <= HS_SQZ;
        end
        HS_SQZ: begin
          if (out_take) begin
            oidx <= oidx + 5'd1;
            if (out_last) ob_full <= 1'b0;
            if (out_last && (om == OM_SEED)) hs <= HS_IDLE;
            if (out_last && (om == OM_CBD))  hs <= HS_DRAIN;
          end
          if ((om == OM_SAMP) && samp_done) begin
            hs      <= HS_IDLE;
            perm    <= 1'b0;          // stop a speculative permutation
            ob_full <= 1'b0;
          end
        end
        HS_DRAIN: if (cb_wen == 4'b0000) hs <= HS_IDLE;   // last CBD group written
        default: hs <= HS_IDLE;
      endcase

      // permutation / absorb / copy (the three are mutually exclusive)
      if (hs != HS_IDLE && !((hs == HS_SQZ) && (om == OM_SAMP) && samp_done)) begin
        if (xor_now) begin
          blk_rdy <= 1'b0;
          perm    <= 1'b1;
          rnd     <= 5'd0;
        end else if (perm) begin
          rnd <= rnd + RSTEP;
          if (rnd == RLAST) begin
            perm <= 1'b0;
            // squeeze may start only after the padded last block itself has
            // been permuted: while it still waits in hb (blk_rdy), this was
            // the permutation of the block before it
            if (last_blk && !blk_rdy) st_rdy <= 1'b1;
          end
        end else if (copy_now) begin
          ob_full <= 1'b1;
          oidx    <= 5'd0;
          st_rdy  <= 1'b0;
          if (om == OM_SAMP) begin    // next block, while this one is consumed
            perm <= 1'b1;
            rnd  <= 5'd0;
          end
        end
      end
    end
  end
endmodule
