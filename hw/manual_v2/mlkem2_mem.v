// -----------------------------------------------------------------------------
// mlkem2_mem.v - storage of the v2 hand-written ML-KEM-768 core.
//
//   mlkem2_sdp_ram     simple dual-port RAM with a read enable (low power: the
//                      RAM block is only read in clocks that need data)
//   mlkem2_polymem     12 polynomial slots, 4 banks each, and the crossbar
//                      that gives each slot to one engine role
//   mlkem2_seedregs    six 32-byte registers (seeds, hash outputs)
//   mlkem2_rd_stream   reads consecutive RAM words into a small FIFO and
//                      hands them out as a valid/ready stream
//
// 4-bank layout (v1 had 2 banks). A slot holds 128 words; word w =
// {coefficient 2w+1, coefficient 2w}, 24 bits. Word w lives in
//     bank  = {w[0], ^w}   (bank index 2*w[0] + parity(w))
//     addr  = w[6:2]       (32 words per bank)
// With this mapping the four words an NTT step touches, w ^ {0, 2^p, 2^q,
// 2^p + 2^q} with q = 0 (or q = 1 when p = 0), are always in four different
// banks, and so are the four words of an aligned group 4a..4a+3 (all at
// address a). So 4 butterflies, 4-word sampler writes and 4-word add/sub
// passes run at one step per clock without conflicts.
//
// All multi-bank buses are {bank 3, bank 2, bank 1, bank 0}: addresses 5 bits
// per bank, data 24 bits per bank, enables 1 bit per bank.
//
// UNTESTED FIRST VERSION - see hw/manual_v2/README.md.
// -----------------------------------------------------------------------------

module mlkem2_sdp_ram #(
  parameter AW = 5,
  parameter DW = 24
) (
  input  wire          clk,
  input  wire          re,
  input  wire          we,
  input  wire [AW-1:0] waddr,
  input  wire [DW-1:0] wdata,
  input  wire [AW-1:0] raddr,
  output reg  [DW-1:0] rdata
);
  reg [DW-1:0] mem [0:(1<<AW)-1];
  always @(posedge clk) begin
    if (we) mem[waddr] <= wdata;
    if (re) rdata <= mem[raddr];      // output holds when not reading
  end
endmodule


// -----------------------------------------------------------------------------
// Polynomial memory. Roles (the core never lets two engines use one slot at
// the same time; the hazard logic in mlkem2_core.v enforces it):
//   C  ALU result/in-place operand   read + write
//   A  ALU operand                   read
//   B  ALU operand                   read
//   S  Keccak engine samplers        write
//   I  IO engine                     read + write
// Read enables are per bank, so an operation that reads one or two banks
// per clock only powers those RAM blocks.
// -----------------------------------------------------------------------------
module mlkem2_polymem #(
  parameter NS = 12
) (
  input  wire        clk,
  // role C
  input  wire [3:0]  c_slot,
  input  wire [3:0]  c_re,
  input  wire [19:0] c_raddr,
  output wire [95:0] c_rdata,
  input  wire [3:0]  c_we,
  input  wire [19:0] c_waddr,
  input  wire [95:0] c_wdata,
  // role A
  input  wire [3:0]  a_slot,
  input  wire [3:0]  a_re,
  input  wire [19:0] a_raddr,
  output wire [95:0] a_rdata,
  // role B
  input  wire [3:0]  b_slot,
  input  wire [3:0]  b_re,
  input  wire [19:0] b_raddr,
  output wire [95:0] b_rdata,
  // role S
  input  wire [3:0]  s_slot,
  input  wire [3:0]  s_we,
  input  wire [19:0] s_waddr,
  input  wire [95:0] s_wdata,
  // role I
  input  wire [3:0]  i_slot,
  input  wire [3:0]  i_re,
  input  wire [19:0] i_raddr,
  output wire [95:0] i_rdata,
  input  wire [3:0]  i_we,
  input  wire [19:0] i_waddr,
  input  wire [95:0] i_wdata
);
  wire [NS*96-1:0] rd_all;   // slot s: {bank 3 .. bank 0} at [96*s +: 96]

  genvar s, k;
  generate
    for (s = 0; s < NS; s = s + 1) begin : g_slot
      for (k = 0; k < 4; k = k + 1) begin : g_bank
        wire        rc = c_re[k] && (c_slot == s);
        wire        ra = a_re[k] && (a_slot == s);
        wire        rb = b_re[k] && (b_slot == s);
        wire        ri = i_re[k] && (i_slot == s);
        wire [4:0]  rad = rc ? c_raddr[5*k +: 5] :
                          ra ? a_raddr[5*k +: 5] :
                          rb ? b_raddr[5*k +: 5] :
                               i_raddr[5*k +: 5];
        wire        wc = c_we[k] && (c_slot == s);
        wire        ws = s_we[k] && (s_slot == s);
        wire        wi = i_we[k] && (i_slot == s);
        wire [4:0]  wad = wc ? c_waddr[5*k +: 5]  : ws ? s_waddr[5*k +: 5]  : i_waddr[5*k +: 5];
        wire [23:0] wd  = wc ? c_wdata[24*k +: 24] : ws ? s_wdata[24*k +: 24] : i_wdata[24*k +: 24];
        wire [23:0] rd;
        mlkem2_sdp_ram #(.AW(5), .DW(24)) u_ram (
          .clk  (clk),
          .re   (rc | ra | rb | ri),
          .we   (wc | ws | wi),
          .waddr(wad),
          .wdata(wd),
          .raddr(rad),
          .rdata(rd)
        );
        assign rd_all[96*s + 24*k +: 24] = rd;
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

  assign c_rdata = rd_all[96*c_sq +: 96];
  assign a_rdata = rd_all[96*a_sq +: 96];
  assign b_rdata = rd_all[96*b_sq +: 96];
  assign i_rdata = rd_all[96*i_sq +: 96];
endmodule


// -----------------------------------------------------------------------------
// Seed registers: entries 0..5 of 32 bytes (8 words, 4 lanes).
//   E0 K / K'   E1 sigma / r / r'   E2 H(ek)   E3 m'   E4 K-bar   E5 rho
// Keccak engine: writes and reads 64-bit lanes (lane L = words 2L, 2L+1).
// IO engine: writes 32-bit words, reads two entries at one word index.
// Registers only load on a write (clock enable), so they are quiet otherwise.
// -----------------------------------------------------------------------------
module mlkem2_seedregs (
  input  wire        clk,
  input  wire        h_we,
  input  wire [2:0]  h_ent,
  input  wire [1:0]  h_lane,
  input  wire [63:0] h_wdata,
  input  wire [2:0]  hr_ent,
  input  wire [1:0]  hr_lane,
  output wire [63:0] hr_data,
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
// Read stream: reads `count` consecutive RAM words from `base` (read latency 1)
// into a 4-entry FIFO; valid/ready output. `active` covers the reads in
// flight, so a shared RAM port stays with this reader until it is done.
// ram_re strobes only on actual reads (low power).
// -----------------------------------------------------------------------------
module mlkem2_rd_stream #(
  parameter DW = 32,
  parameter AW = 11
) (
  input  wire          clk,
  input  wire          rst,
  input  wire          start,
  input  wire [AW-1:0] base,
  input  wire [11:0]   count,
  output wire          ram_re,
  output wire [AW-1:0] ram_addr,
  input  wire [DW-1:0] ram_rdata,
  output wire          active,
  output wire          out_valid,
  output wire [DW-1:0] out_data,
  input  wire          out_ready
);
  reg [AW-1:0] addr;
  reg  [11:0]  left;
  reg          infl;
  reg [DW-1:0] fifo [0:3];
  reg  [1:0]   wp, rp;
  reg  [2:0]   cnt;

  wire pop   = out_valid && out_ready;
  // after this clock: cnt + infl - pop words held; one more may be issued
  wire issue = (left != 12'd0) && ((cnt + {2'd0, infl} - {2'd0, pop}) < 3'd4);

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
        addr <= addr + 1'b1;
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

  assign ram_re    = issue && !start;
  assign ram_addr  = addr;
  assign active    = (left != 12'd0) || infl;
  assign out_valid = (cnt != 3'd0);
  assign out_data  = fifo[rp];
endmodule
