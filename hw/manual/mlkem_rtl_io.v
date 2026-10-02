// -----------------------------------------------------------------------------
// mlkem_rtl_io.v - the IO engine of the hand-written ML-KEM-768 core.
//
// Moves data between the mailbox, the polynomial memory and the seed
// registers, doing the bit (un)packing and (de)compression on the way:
//
//   op 0 DEC   slot <- ByteDecode_d (mailbox or seed register)
//              d = 12: reduce mod q, optionally flag values >= q (ek check)
//              d < 12: optionally Decompress_d
//   op 1 ENC   ByteEncode_d(slot) (optionally Compress_d first) ->
//              mailbox, mailbox at two places, compare with the mailbox
//              (sets DIFF on any mismatch), or a seed register
//   op 2 S2M   seed register -> mailbox (optionally a second copy)
//   op 3 M2M   mailbox -> mailbox
//   op 4 M2S   mailbox -> seed register
//   op 5 CMP   seed register vs mailbox, sets BAD on any mismatch
//   op 6 SEL   mailbox <- DIFF ? seed ent2 : seed ent   (constant time)
//   op 7 ZERO  mailbox <- 0
//
// Mailbox port A is used for all reads and single writes; port B only for
// the second copy (S2M dual, ENC dual) and for M2M writes, which the
// microcode never overlaps with a Keccak mailbox read (which uses port B).
// One coefficient pair (2 coefficients) per clock for DEC and ENC.
//
// UNTESTED FIRST VERSION - see hw/manual/README.md.
// -----------------------------------------------------------------------------
module mlkem_io (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [2:0]  op_in,
  input  wire [3:0]  slot_in,
  input  wire [3:0]  d_in,
  input  wire        fa_in,      // DEC: check | ENC: compress | S2M: dual
  input  wire        fb_in,      // DEC: decompress
  input  wire [1:0]  sel_in,     // DEC: 0 mailbox 1 seed | ENC: 0 mb 1 mb dual 2 compare 3 seed
  input  wire [10:0] addr_in,
  input  wire [10:0] addr2_in,
  input  wire [2:0]  ent_in,
  input  wire [2:0]  ent2_in,
  input  wire [3:0]  n_in,
  input  wire        diff_flag,
  output wire        busy,
  output reg         bad_set,
  output reg         diff_set,
  // mailbox port A
  output reg  [10:0] pa_addr,
  output reg         pa_we,
  output reg  [31:0] pa_wdata,
  input  wire [31:0] pa_rdata,
  // mailbox port B (writes only)
  output reg  [10:0] pb_addr,
  output reg         pb_we,
  output reg  [31:0] pb_wdata,
  // seed registers
  output reg  [2:0]  sr_ent,
  output reg  [2:0]  sr_word,
  input  wire [31:0] sr_data,
  output reg  [2:0]  sr2_ent,
  input  wire [31:0] sr2_data,
  output reg         sw_we,
  output reg  [2:0]  sw_ent,
  output reg  [2:0]  sw_word,
  output reg  [31:0] sw_data,
  // polynomial memory, role I
  output reg  [3:0]  i_slot,
  output wire        i_act,
  output wire [11:0] i_raddr,
  input  wire [47:0] i_rdata,
  output wire [11:0] i_waddr,
  output wire [47:0] i_wdata,
  output wire [1:0]  i_wen
);
  localparam [2:0] IO_DEC = 3'd0, IO_ENC = 3'd1, IO_S2M = 3'd2, IO_M2M  = 3'd3,
                   IO_M2S = 3'd4, IO_CMP = 3'd5, IO_SEL = 3'd6, IO_ZERO = 3'd7;
  localparam [1:0] K_MB = 2'd0, K_MBDUAL = 2'd1, K_CMP = 2'd2, K_SEED = 2'd3;

  reg        busy_r;
  reg  [2:0] op;
  reg  [3:0] d;
  reg        fa, fb;
  reg  [1:0] sel;
  reg [10:0] addr, addr2;
  reg  [2:0] ent, ent2;
  reg  [3:0] nw;

  assign busy  = start | busy_r;
  assign i_act = busy_r && (op == IO_ENC);

  wire [11:0] dmask = (12'd1 << d) - 12'd1;
  wire  [5:0] d2    = {1'b0, d, 1'b0};          // 2d

  // ======================================================================
  // DEC: word stream -> bit unpacker -> post-processing -> slot
  // ======================================================================
  wire        dec       = busy_r && (op == IO_DEC);
  wire        dsrc_seed = sel[0];
  wire        rs_valid, rs_active;
  wire [31:0] rs_data;
  wire [10:0] rs_addr;
  wire        rs_ready;

  mlkem_rd_stream u_rs (
    .clk      (clk),
    .rst      (rst),
    .start    (start && (op_in == IO_DEC) && !sel_in[0]),
    .base     (addr_in),
    .count    ({5'd0, d_in, 3'b000}),           // 8*d words
    .ram_addr (rs_addr),
    .ram_rdata(pa_rdata),
    .active   (rs_active),
    .out_valid(rs_valid),
    .out_data (rs_data),
    .out_ready(rs_ready)
  );

  reg  [63:0] ua;       // unpacker bits
  reg   [6:0] unb;      // number of valid bits in ua
  reg   [7:0] pcnt;     // pairs produced
  reg   [7:0] wtk;      // words taken
  reg   [3:0] sidx;     // seed word index
  wire  [7:0] wtot  = {1'b0, d, 3'b000};
  wire        prod  = dec && (unb >= {1'b0, d2}) && (pcnt < 8'd128);
  wire  [6:0] nb_a  = prod ? (unb - {1'b0, d2}) : unb;
  wire [63:0] ua_a  = prod ? (ua >> d2) : ua;
  wire        in_v  = dsrc_seed ? (sidx < 4'd8) : rs_valid;
  wire [31:0] in_d  = dsrc_seed ? sr_data : rs_data;
  wire        take  = dec && in_v && (nb_a <= 7'd32) && (wtk < wtot);
  assign rs_ready = take && !dsrc_seed;
  wire [63:0] ua_sh = ua >> d;
  wire [11:0] u_lo  = ua[11:0]    & dmask;
  wire [11:0] u_hi  = ua_sh[11:0] & dmask;

  function [11:0] dpost(input [11:0] v, input [3:0] dd, input decomp);
    reg [23:0] m;
    reg [12:0] r;
    begin
      if (dd == 4'd12) begin
        r     = {1'b0, v} - 13'd3329;
        dpost = (v >= 12'd3329) ? r[11:0] : v;
      end else if (decomp) begin
        m     = v * 24'd3329 + (24'd1 << (dd - 4'd1));
        m     = m >> dd;
        dpost = m[11:0];
      end else begin
        dpost = v;
      end
    end
  endfunction

  reg        q1_v, q2_v;
  reg [11:0] q1_lo, q1_hi;
  reg  [6:0] q1_i, q2_i;
  reg [23:0] q2_w;

  always @(posedge clk) begin
    if (start && (op_in == IO_DEC)) begin
      ua   <= 64'd0;
      unb  <= 7'd0;
      pcnt <= 8'd0;
      wtk  <= 8'd0;
      sidx <= 4'd0;
    end else if (dec) begin
      ua  <= ua_a | (take ? ({32'd0, in_d} << nb_a) : 64'd0);
      unb <= nb_a + (take ? 7'd32 : 7'd0);
      if (take) begin
        wtk <= wtk + 8'd1;
        if (dsrc_seed) sidx <= sidx + 4'd1;
      end
      if (prod) pcnt <= pcnt + 8'd1;
    end
    q1_v  <= prod;
    q1_lo <= u_lo;
    q1_hi <= u_hi;
    q1_i  <= pcnt[6:0];
    q2_v  <= q1_v;
    q2_w  <= {dpost(q1_hi, d, fb), dpost(q1_lo, d, fb)};
    q2_i  <= q1_i;
  end

  assign i_wen   = q2_v ? ((^q2_i) ? 2'b10 : 2'b01) : 2'b00;
  assign i_waddr = {q2_i[6:1], q2_i[6:1]};
  assign i_wdata = {q2_w, q2_w};

  // ======================================================================
  // ENC: slot -> (compress) -> bit packer -> mailbox / compare / seed
  // ======================================================================
  wire        enc   = busy_r && (op == IO_ENC);
  reg   [7:0] ecnt;
  wire        e_iss = enc && (ecnt < 8'd128);
  assign i_raddr = {ecnt[6:1], ecnt[6:1]};

  reg         e1_v, e1_b;
  reg         e2_v, e3_v, e4_v;
  reg  [22:0] e2_v0, e2_v1;
  reg  [11:0] e2_x0, e2_x1, e3_x0, e3_x1, e4_x0, e4_x1, e4_c0, e4_c1;
  reg  [44:0] e3_p0, e3_p1;
  wire [23:0] e1_w = e1_b ? i_rdata[47:24] : i_rdata[23:0];

  always @(posedge clk) begin
    e1_v  <= e_iss;
    e1_b  <= ^ecnt[6:0];
    // stage 2: v = (x << d) + (q-1)/2
    e2_v  <= e1_v;
    e2_x0 <= e1_w[11:0];
    e2_x1 <= e1_w[23:12];
    e2_v0 <= ({11'd0, e1_w[11:0]}  << d) + 23'd1664;
    e2_v1 <= ({11'd0, e1_w[23:12]} << d) + 23'd1664;
    // stage 3: v * 2580335   (floor(v/q) = (v * 2580335) >> 33 for v < 2^23)
    e3_v  <= e2_v;
    e3_x0 <= e2_x0;
    e3_x1 <= e2_x1;
    e3_p0 <= e2_v0 * 45'd2580335;
    e3_p1 <= e2_v1 * 45'd2580335;
    // stage 4: Compress_d = floor(v/q) mod 2^d
    e4_v  <= e3_v;
    e4_x0 <= e3_x0;
    e4_x1 <= e3_x1;
    e4_c0 <= e3_p0[44:33] & dmask;
    e4_c1 <= e3_p1[44:33] & dmask;
  end

  reg  [63:0] pk;
  reg   [5:0] pnb;
  reg   [7:0] wk;
  reg         em_v;
  reg  [31:0] em_w;
  reg   [7:0] em_k;
  reg         cm_v;
  reg  [31:0] cm_w;
  wire [11:0] vlo   = fa ? e4_c0 : e4_x0;
  wire [11:0] vhi   = fa ? e4_c1 : e4_x1;
  wire [23:0] pair  = ({12'd0, vhi} << d) | {12'd0, vlo};
  wire [63:0] pk_n  = pk | ({40'd0, pair} << pnb);
  wire  [6:0] pnb_n = {1'b0, pnb} + {1'b0, d2};

  always @(posedge clk) begin
    if (start && (op_in == IO_ENC)) begin
      pk   <= 64'd0;
      pnb  <= 6'd0;
      wk   <= 8'd0;
      ecnt <= 8'd0;
      em_v <= 1'b0;
    end else begin
      if (e_iss) ecnt <= ecnt + 8'd1;
      em_v <= 1'b0;
      if (enc && e4_v) begin
        if (pnb_n >= 7'd32) begin
          em_v <= 1'b1;
          em_w <= pk_n[31:0];
          em_k <= wk;
          wk   <= wk + 8'd1;
          pk   <= pk_n >> 32;
          pnb  <= pnb_n[5:0] - 6'd32;
        end else begin
          pk   <= pk_n;
          pnb  <= pnb_n[5:0];
        end
      end
    end
    // compare: the mailbox word read with em_v arrives one clock later
    cm_v <= enc && em_v && (sel == K_CMP);
    cm_w <= em_w;
  end

  // ======================================================================
  // word operations: S2M, M2M, M2S, CMP, SEL, ZERO
  // ======================================================================
  wire       wop   = busy_r && (op >= IO_S2M);
  reg  [3:0] wkc;         // words issued
  reg        wv;          // a read issued last clock (M2M, M2S, CMP)
  reg  [2:0] wkd;         // its word index
  wire       w_iss = wop && (wkc < nw);

  always @(posedge clk) begin
    if (start && (op_in >= IO_S2M)) begin
      wkc <= 4'd0;
      wv  <= 1'b0;
    end else begin
      if (w_iss) wkc <= wkc + 4'd1;
      wv  <= w_iss && (op == IO_M2M || op == IO_M2S || op == IO_CMP);
      wkd <= wkc[2:0];
    end
  end

  // ======================================================================
  // port, seed-register and flag multiplexing
  // ======================================================================
  always @* begin
    pa_addr  = 11'd0;
    pa_we    = 1'b0;
    pa_wdata = 32'd0;
    pb_addr  = 11'd0;
    pb_we    = 1'b0;
    pb_wdata = 32'd0;
    sr_ent   = ent;
    sr_word  = 3'd0;
    sr2_ent  = ent2;
    sw_we    = 1'b0;
    sw_ent   = ent;
    sw_word  = 3'd0;
    sw_data  = 32'd0;
    case (op)
      IO_DEC: begin
        pa_addr = rs_addr;
        sr_word = sidx[2:0];
      end
      IO_ENC: begin
        pa_addr = addr + {3'd0, em_k};
        if (busy_r && em_v) begin
          case (sel)
            K_MB: begin
              pa_we    = 1'b1;
              pa_wdata = em_w;
            end
            K_MBDUAL: begin
              pa_we    = 1'b1;
              pa_wdata = em_w;
              pb_we    = 1'b1;
              pb_addr  = addr2 + {3'd0, em_k};
              pb_wdata = em_w;
            end
            K_SEED: begin
              sw_we   = 1'b1;
              sw_word = em_k[2:0];
              sw_data = em_w;
            end
            default: ;   // K_CMP: pa_addr reads the word to compare
          endcase
        end
      end
      IO_S2M: begin
        sr_word = wkc[2:0];
        pa_addr = addr  + {7'd0, wkc};
        pb_addr = addr2 + {7'd0, wkc};
        if (w_iss) begin
          pa_we    = 1'b1;
          pa_wdata = sr_data;
          if (fa) begin
            pb_we    = 1'b1;
            pb_wdata = sr_data;
          end
        end
      end
      IO_M2M: begin
        pa_addr = addr  + {7'd0, wkc};
        pb_addr = addr2 + {8'd0, wkd};
        if (wv) begin
          pb_we    = 1'b1;
          pb_wdata = pa_rdata;
        end
      end
      IO_M2S: begin
        pa_addr = addr + {7'd0, wkc};
        if (wv) begin
          sw_we   = 1'b1;
          sw_word = wkd;
          sw_data = pa_rdata;
        end
      end
      IO_CMP: begin
        pa_addr = addr + {7'd0, wkc};
        sr_word = wkd;
      end
      IO_SEL: begin
        sr_word = wkc[2:0];
        pa_addr = addr + {7'd0, wkc};
        if (w_iss) begin
          pa_we    = 1'b1;
          pa_wdata = diff_flag ? sr2_data : sr_data;
        end
      end
      default: begin   // IO_ZERO
        pa_addr = addr + {7'd0, wkc};
        if (w_iss) begin
          pa_we    = 1'b1;
          pa_wdata = 32'd0;
        end
      end
    endcase
  end

  always @(posedge clk) begin
    bad_set  <= (q1_v && (d == 4'd12) && fa && ((q1_lo >= 12'd3329) || (q1_hi >= 12'd3329)))
              | (busy_r && (op == IO_CMP) && wv && (pa_rdata != sr_data));
    diff_set <= cm_v && (pa_rdata != cm_w);
  end

  // ======================================================================
  // command latch and completion
  // ======================================================================
  always @(posedge clk) begin
    if (rst) begin
      busy_r <= 1'b0;
    end else if (start) begin
      busy_r <= 1'b1;
      op     <= op_in;
      i_slot <= slot_in;
      d      <= d_in;
      fa     <= fa_in;
      fb     <= fb_in;
      sel    <= sel_in;
      addr   <= addr_in;
      addr2  <= addr2_in;
      ent    <= ent_in;
      ent2   <= ent2_in;
      nw     <= n_in;
    end else if (busy_r) begin
      case (op)
        IO_DEC:  if (pcnt == 8'd128 && !q1_v && !q2_v) busy_r <= 1'b0;
        IO_ENC:  if (ecnt == 8'd128 && !e1_v && !e2_v && !e3_v && !e4_v && !em_v && !cm_v)
                   busy_r <= 1'b0;
        default: if (wkc == nw && !wv) busy_r <= 1'b0;
      endcase
    end
  end
endmodule
