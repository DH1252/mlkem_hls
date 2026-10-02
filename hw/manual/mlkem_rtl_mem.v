// -----------------------------------------------------------------------------
// mlkem_rtl_mem.v - storage of the hand-written ML-KEM-768 core.
//
//   mlkem_sdp_ram    simple dual-port RAM (1 write + 1 read port, read
//                    latency 1); Quartus maps it to M10K or MLAB
//   mlkem_polymem    12 polynomial slots with the crossbar that connects them
//                    to the engines
//   mlkem_seedregs   six 32-byte registers for seeds and hash outputs
//   mlkem_rd_stream  reads consecutive mailbox words through one RAM port
//                    and delivers them as a valid/ready stream
//
// UNTESTED FIRST VERSION - see hw/manual/README.md.
// -----------------------------------------------------------------------------

module mlkem_sdp_ram #(
  parameter AW = 6,
  parameter DW = 24
) (
  input  wire          clk,
  input  wire          we,
  input  wire [AW-1:0] waddr,
  input  wire [DW-1:0] wdata,
  input  wire [AW-1:0] raddr,
  output reg  [DW-1:0] rdata
);
  reg [DW-1:0] mem [0:(1<<AW)-1];
  always @(posedge clk) begin
    if (we) mem[waddr] <= wdata;
    rdata <= mem[raddr];
  end
endmodule


// -----------------------------------------------------------------------------
// Polynomial memory: NS slots x 2 banks x 64 words x 24 bits.
//
// A slot holds one polynomial. Word w = {coefficient 2w+1, coefficient 2w}
// lives in bank parity(w) (XOR of the 7 bits of w) at address w[6:1]. The two
// words of every NTT butterfly (w, w + 2^p) are therefore in different banks,
// and so are the words 2m, 2m+1 (both at address m).
//
// Roles (who may use which slot is decided by the microcode; a slot is only
// used by one role at a time):
//   C  ALU accumulator/in-place operand : read + write, both banks
//   A  ALU operand                       : read, both banks
//   B  ALU operand                       : read, both banks
//   S  sampler (Keccak engine)           : write, both banks
//   I  IO engine (encode/decode)         : read + write, both banks
// All address/data buses are {bank 1, bank 0}.
// -----------------------------------------------------------------------------
module mlkem_polymem #(
  parameter NS = 12
) (
  input  wire        clk,
  // role C
  input  wire [3:0]  c_slot,
  input  wire        c_act,
  input  wire [11:0] c_raddr,
  output wire [47:0] c_rdata,
  input  wire [11:0] c_waddr,
  input  wire [47:0] c_wdata,
  input  wire [1:0]  c_wen,
  // role A
  input  wire [3:0]  a_slot,
  input  wire        a_act,
  input  wire [11:0] a_raddr,
  output wire [47:0] a_rdata,
  // role B
  input  wire [3:0]  b_slot,
  input  wire        b_act,
  input  wire [11:0] b_raddr,
  output wire [47:0] b_rdata,
  // role S
  input  wire [3:0]  s_slot,
  input  wire [11:0] s_waddr,
  input  wire [47:0] s_wdata,
  input  wire [1:0]  s_wen,
  // role I
  input  wire [3:0]  i_slot,
  input  wire        i_act,
  input  wire [11:0] i_raddr,
  output wire [47:0] i_rdata,
  input  wire [11:0] i_waddr,
  input  wire [47:0] i_wdata,
  input  wire [1:0]  i_wen
);
  wire [NS*48-1:0] rd_all;   // slot s: {bank 1, bank 0} at [48*s +: 48]

  genvar s, k;
  generate
    for (s = 0; s < NS; s = s + 1) begin : g_slot
      for (k = 0; k < 2; k = k + 1) begin : g_bank
        wire       c_hit  = (c_slot == s);
        wire       rsel_c = c_act && c_hit;
        wire       rsel_a = a_act && (a_slot == s);
        wire       rsel_b = b_act && (b_slot == s);
        wire [5:0] ra = rsel_c ? c_raddr[6*k +: 6] :
                        rsel_a ? a_raddr[6*k +: 6] :
                        rsel_b ? b_raddr[6*k +: 6] :
                                 i_raddr[6*k +: 6];
        wire       wc = c_wen[k] && c_hit;
        wire       ws = s_wen[k] && (s_slot == s);
        wire       wi = i_wen[k] && (i_slot == s);
        wire [5:0]  wa = wc ? c_waddr[6*k +: 6]  : ws ? s_waddr[6*k +: 6]  : i_waddr[6*k +: 6];
        wire [23:0] wd = wc ? c_wdata[24*k +: 24] : ws ? s_wdata[24*k +: 24] : i_wdata[24*k +: 24];
        wire [23:0] rd;
        mlkem_sdp_ram #(.AW(6), .DW(24)) u_ram (
          .clk  (clk),
          .we   (wc | ws | wi),
          .waddr(wa),
          .wdata(wd),
          .raddr(ra),
          .rdata(rd)
        );
        assign rd_all[48*s + 24*k +: 24] = rd;
      end
    end
  endgenerate

  // read data follows the RAM latency: select with the slot of one clock ago
  reg [3:0] c_sq, a_sq, b_sq, i_sq;
  always @(posedge clk) begin
    c_sq <= c_slot;
    a_sq <= a_slot;
    b_sq <= b_slot;
    i_sq <= i_slot;
  end

  assign c_rdata = rd_all[48*c_sq +: 48];
  assign a_rdata = rd_all[48*a_sq +: 48];
  assign b_rdata = rd_all[48*b_sq +: 48];
  assign i_rdata = rd_all[48*i_sq +: 48];
endmodule


// -----------------------------------------------------------------------------
// Seed registers: entries 0..5 of 32 bytes (8 words, 4 lanes).
//   E0 K / K'   E1 sigma / r / r'   E2 H(ek)   E3 m'   E4 K-bar   E5 rho
// Written by the Keccak engine (one 64-bit lane at a time) and by the IO
// engine (one 32-bit word at a time); read by both (combinational).
// -----------------------------------------------------------------------------
module mlkem_seedregs (
  input  wire        clk,
  // Keccak engine write (lane) and read (lane)
  input  wire        h_we,
  input  wire [2:0]  h_ent,
  input  wire [1:0]  h_lane,
  input  wire [63:0] h_wdata,
  input  wire [2:0]  hr_ent,
  input  wire [1:0]  hr_lane,
  output wire [63:0] hr_data,
  // IO engine write (word) and two reads of the same word index
  input  wire        i_we,
  input  wire [2:0]  i_ent,
  input  wire [2:0]  i_word,
  input  wire [31:0] i_wdata,
  input  wire [2:0]  ir_ent,
  input  wire [2:0]  ir_word,
  output wire [31:0] ir_data,
  input  wire [2:0]  ir2_ent,
  output wire [31:0] ir2_data
);
  wire [6*256-1:0] all_e;

  genvar e;
  generate
    for (e = 0; e < 6; e = e + 1) begin : g_ent
      reg [255:0] r;
      integer w;
      always @(posedge clk) begin
        for (w = 0; w < 8; w = w + 1) begin
          if (h_we && (h_ent == e) && (h_lane == (w / 2)))
            r[32*w +: 32] <= h_wdata[32*(w % 2) +: 32];
          else if (i_we && (i_ent == e) && (i_word == w))
            r[32*w +: 32] <= i_wdata;
        end
      end
      assign all_e[256*e +: 256] = r;
    end
  endgenerate

  assign hr_data  = all_e[256*hr_ent + 64*hr_lane +: 64];
  assign ir_data  = all_e[256*ir_ent + 32*ir_word +: 32];
  assign ir2_data = all_e[256*ir2_ent + 32*ir_word +: 32];
endmodule


// -----------------------------------------------------------------------------
// Mailbox word reader: reads `count` consecutive words from `base` through
// one RAM port (read latency 1) into a 4-word FIFO; delivers them as a
// valid/ready stream. `active` stays high while reads are outstanding, so the
// port stays with this reader until the stream is complete.
// -----------------------------------------------------------------------------
module mlkem_rd_stream (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [10:0] base,
  input  wire [11:0] count,
  output wire [10:0] ram_addr,
  input  wire [31:0] ram_rdata,
  output wire        active,
  output wire        out_valid,
  output wire [31:0] out_data,
  input  wire        out_ready
);
  reg [10:0] addr;
  reg [11:0] left;
  reg        infl;
  reg [31:0] fifo [0:3];
  reg  [1:0] wp, rp;
  reg  [2:0] cnt;

  wire       pop   = out_valid && out_ready;
  // after this clock: cnt + infl - pop words held or in flight, plus the new read
  wire       issue = (left != 12'd0) && ((cnt + {2'd0, infl} - {2'd0, pop}) < 3'd4);

  always @(posedge clk) begin
    if (rst) begin
      left <= 12'd0;
      infl <= 1'b0;
      cnt  <= 3'd0;
      wp   <= 2'd0;
      rp   <= 2'd0;
    end else if (start) begin
      addr <= base;
      left <= count;
      infl <= 1'b0;
      cnt  <= 3'd0;
      wp   <= 2'd0;
      rp   <= 2'd0;
    end else begin
      infl <= issue;
      if (issue) begin
        addr <= addr + 11'd1;
        left <= left - 12'd1;
      end
      if (infl) begin
        fifo[wp] <= ram_rdata;
        wp       <= wp + 2'd1;
      end
      if (pop) rp <= rp + 2'd1;
      cnt <= cnt + {2'd0, infl} - {2'd0, pop};
    end
  end

  assign ram_addr  = addr;
  assign active    = (left != 12'd0) || infl;
  assign out_valid = (cnt != 3'd0);
  assign out_data  = fifo[rp];
endmodule
