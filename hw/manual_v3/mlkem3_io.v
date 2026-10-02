// -----------------------------------------------------------------------------
// mlkem3_io.v - IO engine of the v3 core (v2: hw/manual_v2/mlkem2_io.v).
//
//   op 0 DEC   slot <- ByteDecode_d(mailbox or seed register)
//              d = 12: reduce mod q, optionally flag values >= q (ek check)
//              d < 12: optionally Decompress_d
//              acc:    slot <- slot + decoded (builds e2 + mu in one pass)
//   op 1 ENC   ByteEncode_d(slot) (optionally Compress_d) -> mailbox, two
//              mailbox places, compare with the mailbox (DIFF), or a seed reg
//   op 2 S2M   seed -> mailbox (optionally a second copy through port B)
//   op 3 M2M   mailbox -> mailbox
//   op 4 M2S   mailbox -> seed
//   op 5 CMP   seed vs mailbox -> BAD
//   op 6 SEL   mailbox <- DIFF ? seed ent2 : seed ent (constant time)
//   op 7 ZERO  mailbox <- 0
//
// v3 speed-ups (v2: one word = two coefficients per clock):
//   DEC  up to two words per clock (words 2k, 2k+1 are in different banks).
//        The 32-bit mailbox stream then limits it: d = 12 -> 96 clocks,
//        d = 10 -> 80, d = 4 and d = 1 -> 64 (v2: ~130 each).
//   ENC  two words per clock when 4d <= 32 bits fit the 32-bit mailbox port
//        in one clock (d = 1: m', d = 4: v) -> 64 clocks; d = 10, 12 stay at
//        one word per clock.
// Decaps starts with seven decodes on the critical path, so this matters.
//
// Polymem: v3 bank mapping (mlkem3_mem.v).
// Low power: only the banks holding the current words are read, mailbox
// reads are strobed (pa_re), pipelines are valid-gated.
//
// UNTESTED FIRST VERSION of v3 - see hw/manual_v3/README.md.
// -----------------------------------------------------------------------------
module mlkem3_io (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [2:0]  op_in,
  input  wire [3:0]  slot_in,
  input  wire [3:0]  d_in,
  input  wire        fa_in,      // DEC: check | ENC: compress | S2M: dual
  input  wire        fb_in,      // DEC: decompress
  input  wire        acc_in,     // DEC: add into the slot
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
  // mailbox port A (32-bit)
  output reg  [10:0] pa_addr,
  output reg         pa_re,
  output reg         pa_we,
  output reg  [31:0] pa_wdata,
  input  wire [31:0] pa_rdata,
  // mailbox port B (32-bit writes only)
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
  // polynomial memory, role I (4 banks)
  output reg  [3:0]  i_slot,
  output reg  [3:0]  i_re,
  output reg  [19:0] i_raddr,
  input  wire [95:0] i_rdata,
  output reg  [3:0]  i_we,
  output reg  [19:0] i_waddr,
  output reg  [95:0] i_wdata
);
  localparam [2:0] IO_DEC = 3'd0, IO_ENC = 3'd1, IO_S2M = 3'd2, IO_M2M  = 3'd3,
                   IO_M2S = 3'd4, IO_CMP = 3'd5, IO_SEL = 3'd6, IO_ZERO = 3'd7;
  localparam [1:0] K_MB = 2'd0, K_MBDUAL = 2'd1, K_CMP = 2'd2, K_SEED = 2'd3;

  function [1:0] bank_of(input [6:0] w);
    bank_of = {^(w & 7'b0101010), ^(w & 7'b1010101)};
  endfunction

  function [11:0] addq(input [11:0] x, input [11:0] y);
    reg [12:0] s, t;
    begin
      s = {1'b0, x} + {1'b0, y};
      t = s - 13'd3329;
      addq = (s >= 13'd3329) ? t[11:0] : s[11:0];
    end
  endfunction

  function [23:0] addw(input [23:0] x, input [23:0] y);
    addw = {addq(x[23:12], y[23:12]), addq(x[11:0], y[11:0])};
  endfunction

  reg        busy_r;
  reg  [2:0] op;
  reg  [3:0] d;
  reg        fa, fb, acc;
  reg  [1:0] sel;
  reg [10:0] addr, addr2;
  reg  [2:0] ent, ent2;
  reg  [3:0] nw;

  assign busy = start | busy_r;

  wire [11:0] dmask = (12'd1 << d) - 12'd1;
  wire  [6:0] d2x   = {2'b00, d, 1'b0};          // 2d
  wire  [6:0] d4x   = {1'b0, d, 2'b00};          // 4d

  // ======================================================================
  // DEC: word stream -> bit unpacker -> post-processing (-> + slot) -> slot
  // ======================================================================
  wire        dec       = busy_r && (op == IO_DEC);
  wire        dsrc_seed = sel[0];
  wire        rs_valid, rs_active, rs_re;
  wire [31:0] rs_data;
  wire [10:0] rs_addr;
  wire        rs_ready;

  mlkem3_rd_stream #(.DW(32), .AW(11)) u_rs (
    .clk      (clk),
    .rst      (rst),
    .start    (start && (op_in == IO_DEC) && !sel_in[0]),
    .base     (addr_in),
    .count    ({5'd0, d_in, 3'b000}),           // 8*d words
    .ram_re   (rs_re),
    .ram_addr (rs_addr),
    .ram_rdata(pa_rdata),
    .active   (rs_active),
    .out_valid(rs_valid),
    .out_data (rs_data),
    .out_ready(rs_ready)
  );

  reg  [95:0] ua;       // bit buffer, oldest bits in [0]
  reg   [6:0] unb;      // bits held (0..95)
  reg   [7:0] pcnt;     // words produced (0..128)
  reg   [7:0] wtk;      // input words taken
  reg   [3:0] sidx;
  wire  [7:0] wtot  = {1'b0, d, 3'b000};
  // two words when the pair is aligned (so they sit in two banks) and 4d bits
  // are there; else one word
  wire        can2  = dec && (pcnt < 8'd128) && !pcnt[0] && (unb >= d4x);
  wire        can1  = dec && (pcnt < 8'd128) && !can2 && (unb >= d2x);
  wire        prod  = can1 || can2;
  wire  [6:0] used  = can2 ? d4x : (can1 ? d2x : 7'd0);
  wire  [6:0] nb_a  = unb - used;
  wire [95:0] ua_a  = ua >> used;
  wire        in_v  = dsrc_seed ? (sidx < 4'd8) : rs_valid;
  wire [31:0] in_d  = dsrc_seed ? sr_data : rs_data;
  wire        take  = dec && in_v && (nb_a <= 7'd64) && (wtk < wtot);
  assign rs_ready = take && !dsrc_seed;
  wire [95:0] ua_s1 = ua >> d;
  wire [95:0] ua_s2 = ua >> d2x;
  wire [95:0] ua_s3 = ua_s2 >> d;
  wire [11:0] u0    = ua[11:0]    & dmask;
  wire [11:0] u1    = ua_s1[11:0] & dmask;
  wire [11:0] u2    = ua_s2[11:0] & dmask;
  wire [11:0] u3    = ua_s3[11:0] & dmask;

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

  reg        q1_v, q2_v, q1_two, q2_two;
  reg [11:0] q1_u0, q1_u1, q1_u2, q1_u3;
  reg  [6:0] q1_i, q2_i;
  reg [23:0] q2_w0, q2_w1;

  always @(posedge clk) begin
    if (start && (op_in == IO_DEC)) begin
      ua   <= 96'd0;
      unb  <= 7'd0;
      pcnt <= 8'd0;
      wtk  <= 8'd0;
      sidx <= 4'd0;
    end else if (dec && (prod || take)) begin
      ua  <= ua_a | (take ? ({64'd0, in_d} << nb_a) : 96'd0);
      unb <= nb_a + (take ? 7'd32 : 7'd0);
      if (take) begin
        wtk <= wtk + 8'd1;
        if (dsrc_seed) sidx <= sidx + 4'd1;
      end
      if (prod) pcnt <= pcnt + (can2 ? 8'd2 : 8'd1);
    end
    q1_v <= prod;
    q2_v <= q1_v;
    if (prod) begin
      q1_u0  <= u0;
      q1_u1  <= u1;
      q1_u2  <= u2;
      q1_u3  <= u3;
      q1_two <= can2;
      q1_i   <= pcnt[6:0];
    end
    if (q1_v) begin
      q2_w0  <= {dpost(q1_u1, d, fb), dpost(q1_u0, d, fb)};
      q2_w1  <= {dpost(q1_u3, d, fb), dpost(q1_u2, d, fb)};
      q2_two <= q1_two;
      q2_i   <= q1_i;
    end
  end

  // accumulate: the slot words are read when they are produced (prod),
  // arrive with q1 and are registered, so the add at q2 starts from registers
  reg  [23:0] q2_old0, q2_old1;
  always @(posedge clk) begin
    if (q1_v && acc) begin
      q2_old0 <= i_rdata[24*bank_of(q1_i) +: 24];
      q2_old1 <= i_rdata[24*bank_of(q1_i + 7'd1) +: 24];
    end
  end
  wire [23:0] q2_out0 = acc ? addw(q2_w0, q2_old0) : q2_w0;
  wire [23:0] q2_out1 = acc ? addw(q2_w1, q2_old1) : q2_w1;
  wire  [1:0] q2_b0   = bank_of(q2_i);
  wire  [1:0] q2_b1   = bank_of(q2_i + 7'd1);

  // ======================================================================
  // ENC: slot -> (compress) -> bit packer -> mailbox / compare / seed
  // ======================================================================
  wire        enc   = busy_r && (op == IO_ENC);
  wire        e2w   = (d <= 4'd8);               // two words per clock
  reg   [7:0] ecnt;
  wire        e_iss = enc && (ecnt < 8'd128);

  // polynomial memory ports
  reg [1:0] wb0, wb1;
  always @* begin
    i_re    = 4'b0000;
    i_raddr = 20'd0;
    i_we    = 4'b0000;
    i_waddr = {4{q2_i[6:2]}};
    i_wdata = 96'd0;
    wb0     = 2'd0;
    wb1     = 2'd0;
    if (op == IO_ENC) begin
      i_raddr = {4{ecnt[6:2]}};
      if (e_iss)
        i_re = (4'b0001 << bank_of(ecnt[6:0])) |
               (e2w ? (4'b0001 << bank_of(ecnt[6:0] + 7'd1)) : 4'b0000);
    end else begin
      // DEC accumulate reads (with prod); pcnt is even when two words
      i_raddr = {4{pcnt[6:2]}};
      if (prod && acc)
        i_re = (4'b0001 << bank_of(pcnt[6:0])) |
               (can2 ? (4'b0001 << bank_of(pcnt[6:0] + 7'd1)) : 4'b0000);
    end
    if (q2_v) begin
      wb0 = q2_b0;
      wb1 = q2_b1;
      i_we                  = (4'b0001 << wb0) | (q2_two ? (4'b0001 << wb1) : 4'b0000);
      i_wdata[24*wb0 +: 24] = q2_out0;
      if (q2_two) i_wdata[24*wb1 +: 24] = q2_out1;
    end
  end

  reg         e1_v, eq_v, e2_v, e3_v, e4_v;
  reg         e1_two, eq_two, e2_two, e3_two, e4_two;
  reg   [1:0] e1_b0, e1_b1;
  reg  [23:0] eq_w0, eq_w1;
  reg  [22:0] e2_v0, e2_v1, e2_v2, e2_v3;
  reg  [11:0] e2_x0, e2_x1, e2_x2, e2_x3;
  reg  [11:0] e3_x0, e3_x1, e3_x2, e3_x3;
  reg  [44:0] e3_p0, e3_p1, e3_p2, e3_p3;
  reg  [11:0] e4_x0, e4_x1, e4_x2, e4_x3;
  reg  [11:0] e4_c0, e4_c1, e4_c2, e4_c3;

  always @(posedge clk) begin
    e1_v <= e_iss;
    eq_v <= e1_v;
    e2_v <= eq_v;
    e3_v <= e2_v;
    e4_v <= e3_v;
    if (e_iss) begin
      e1_b0  <= bank_of(ecnt[6:0]);
      e1_b1  <= bank_of(ecnt[6:0] + 7'd1);
      e1_two <= e2w;
    end
    // input registers: the RAM words are registered before the shift and add
    if (e1_v) begin
      eq_w0  <= i_rdata[24*e1_b0 +: 24];
      eq_w1  <= i_rdata[24*e1_b1 +: 24];
      eq_two <= e1_two;
    end
    // stage 2: v = (x << d) + (q-1)/2
    if (eq_v) begin
      e2_x0  <= eq_w0[11:0];
      e2_x1  <= eq_w0[23:12];
      e2_v0  <= ({11'd0, eq_w0[11:0]}  << d) + 23'd1664;
      e2_v1  <= ({11'd0, eq_w0[23:12]} << d) + 23'd1664;
      e2_two <= eq_two;
      if (eq_two) begin
        e2_x2 <= eq_w1[11:0];
        e2_x3 <= eq_w1[23:12];
        e2_v2 <= ({11'd0, eq_w1[11:0]}  << d) + 23'd1664;
        e2_v3 <= ({11'd0, eq_w1[23:12]} << d) + 23'd1664;
      end
    end
    // stage 3: v * 2580335   (floor(v/q) = (v * 2580335) >> 33 for v < 2^23)
    if (e2_v) begin
      e3_x0  <= e2_x0;
      e3_x1  <= e2_x1;
      e3_p0  <= e2_v0 * 45'd2580335;
      e3_p1  <= e2_v1 * 45'd2580335;
      e3_two <= e2_two;
      if (e2_two) begin
        e3_x2 <= e2_x2;
        e3_x3 <= e2_x3;
        e3_p2 <= e2_v2 * 45'd2580335;
        e3_p3 <= e2_v3 * 45'd2580335;
      end
    end
    // stage 4: Compress_d = floor(v/q) mod 2^d
    if (e3_v) begin
      e4_x0  <= e3_x0;
      e4_x1  <= e3_x1;
      e4_c0  <= e3_p0[44:33] & dmask;
      e4_c1  <= e3_p1[44:33] & dmask;
      e4_two <= e3_two;
      if (e3_two) begin
        e4_x2 <= e3_x2;
        e4_x3 <= e3_x3;
        e4_c2 <= e3_p2[44:33] & dmask;
        e4_c3 <= e3_p3[44:33] & dmask;
      end
    end
  end

  reg  [63:0] pk;
  reg   [5:0] pnb;
  reg   [7:0] wk;
  reg         em_v;
  reg  [31:0] em_w;
  reg   [7:0] em_k;
  reg         cm_v;
  reg  [31:0] cm_w;
  wire [11:0] v0    = fa ? e4_c0 : e4_x0;
  wire [11:0] v1    = fa ? e4_c1 : e4_x1;
  wire [11:0] v2    = fa ? e4_c2 : e4_x2;
  wire [11:0] v3    = fa ? e4_c3 : e4_x3;
  wire [23:0] pair0 = ({12'd0, v1} << d) | {12'd0, v0};           // 2d bits
  wire [23:0] pair1 = ({12'd0, v3} << d) | {12'd0, v2};
  wire [47:0] bits  = e4_two ? (({24'd0, pair1} << d2x) | {24'd0, pair0}) : {24'd0, pair0};
  wire  [6:0] nbits = e4_two ? d4x : d2x;
  wire [63:0] pk_n  = pk | ({16'd0, bits} << pnb);
  wire  [6:0] pnb_n = {1'b0, pnb} + nbits;

  always @(posedge clk) begin
    if (start && (op_in == IO_ENC)) begin
      pk   <= 64'd0;
      pnb  <= 6'd0;
      wk   <= 8'd0;
      ecnt <= 8'd0;
      em_v <= 1'b0;
    end else begin
      if (e_iss) ecnt <= ecnt + (e2w ? 8'd2 : 8'd1);
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
    if (em_v) cm_w <= em_w;
  end

  // ======================================================================
  // word operations: S2M, M2M, M2S, CMP, SEL, ZERO (as v2)
  // ======================================================================
  wire       wop   = busy_r && (op >= IO_S2M);
  reg  [3:0] wkc;
  reg        wv;
  reg  [2:0] wkd;
  wire       w_iss = wop && (wkc < nw);
  wire       w_rd  = (op == IO_M2M || op == IO_M2S || op == IO_CMP);

  always @(posedge clk) begin
    if (start && (op_in >= IO_S2M)) begin
      wkc <= 4'd0;
      wv  <= 1'b0;
    end else begin
      if (w_iss) wkc <= wkc + 4'd1;
      wv <= w_iss && w_rd;
      if (w_iss) wkd <= wkc[2:0];
    end
  end

  // ======================================================================
  // port, seed-register and flag multiplexing (as v2)
  // ======================================================================
  always @* begin
    pa_addr  = addr;
    pa_re    = 1'b0;
    pa_we    = 1'b0;
    pa_wdata = 32'd0;
    pb_addr  = addr2;
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
        pa_re   = rs_re;
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
            default: pa_re = 1'b1;     // K_CMP: read the word to compare
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
        pa_re   = w_iss;
        pb_addr = addr2 + {8'd0, wkd};
        if (wv) begin
          pb_we    = 1'b1;
          pb_wdata = pa_rdata;
        end
      end
      IO_M2S: begin
        pa_addr = addr + {7'd0, wkc};
        pa_re   = w_iss;
        if (wv) begin
          sw_we   = 1'b1;
          sw_word = wkd;
          sw_data = pa_rdata;
        end
      end
      IO_CMP: begin
        pa_addr = addr + {7'd0, wkc};
        pa_re   = w_iss;
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

  // ek check (d = 12, fa): any decoded value >= q sets BAD
  wire q1_big = (q1_u0 >= 12'd3329) || (q1_u1 >= 12'd3329) ||
                (q1_two && ((q1_u2 >= 12'd3329) || (q1_u3 >= 12'd3329)));

  always @(posedge clk) begin
    bad_set  <= (q1_v && (d == 4'd12) && fa && q1_big)
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
      acc    <= acc_in;
      sel    <= sel_in;
      addr   <= addr_in;
      addr2  <= addr2_in;
      ent    <= ent_in;
      ent2   <= ent2_in;
      nw     <= n_in;
    end else if (busy_r) begin
      case (op)
        IO_DEC:  if (pcnt == 8'd128 && !q1_v && !q2_v) busy_r <= 1'b0;
        IO_ENC:  if (ecnt == 8'd128 && !e1_v && !eq_v && !e2_v && !e3_v && !e4_v && !em_v && !cm_v)
                   busy_r <= 1'b0;
        default: if (wkc == nw && !wv) busy_r <= 1'b0;
      endcase
    end
  end
endmodule
