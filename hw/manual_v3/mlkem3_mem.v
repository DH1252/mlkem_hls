// -----------------------------------------------------------------------------
// mlkem3_mem.v - storage of the v3 core.
//
//   mlkem3_sdp_ram     simple dual-port RAM with a read enable
//   mlkem3_polymem     12 polynomial slots x 4 banks, and the crossbar that
//                      gives each slot to one engine role at a time
//   mlkem3_seedregs    six 32-byte registers (seeds, hash outputs)
//   mlkem3_rd_stream   reads consecutive RAM words into a small FIFO
//
// v3 bank mapping (v2: bank {w[0], ^w}). A slot holds 128 words; word w =
// {coefficient 2w+1, coefficient 2w}, 24 bits:
//     bank = {^(w & 7'b0101010), ^(w & 7'b1010101)}   (odd-bit parity,
//                                                      even-bit parity)
//     addr = w[6:2]
// Flipping one odd-position bit and one even-position bit of w reaches all
// four banks, so these four-word sets are conflict-free:
//   - an NTT/INTT radix-4 group: w, w^2^lo, w^2^hi, w^2^lo^2^hi with the
//     adjacent bit pairs (hi, lo) = (6,5), (4,3), (2,1), and the aligned
//     group of the single layer (bits 1, 0)
//   - an aligned group 4a..4a+3 (sampler, CBD, pointwise multiply, add)
//   - two consecutive words 2k, 2k+1 (IO engine, two words per clock)
//
// Roles (the sequencer never lets two engines use one slot at the same
// time, so each slot's RAMs serve one role at a time):
//   N   NTT engine, operand/result      read + write
//   NA  NTT engine, fused-add operand   read
//   P   PWM engine, result/accumulator  read + write
//   PA  PWM engine, operand a           read
//   PB  PWM engine, operand b           read
//   S   Keccak engine (samplers)        write
//   I   IO engine                       read + write
// Read enables are per bank: a RAM block is only read when needed.
//
// Parameter RAMSTYLE: 0 = let Quartus choose (M10K blocks, as v2),
// 1 = MLAB (LUT RAM). The banks are only 32 x 24 bits, so MLABs save 48
// M10K blocks and usually some power; try both in Quartus.
//
// UNTESTED FIRST VERSION of v3 - see hw/manual_v3/README.md.
// -----------------------------------------------------------------------------

module mlkem3_sdp_ram #(
  parameter AW = 5,
  parameter DW = 24,
  parameter RAMSTYLE = 0
) (
  input  wire          clk,
  input  wire          re,
  input  wire          we,
  input  wire [AW-1:0] waddr,
  input  wire [DW-1:0] wdata,
  input  wire [AW-1:0] raddr,
  output reg  [DW-1:0] rdata
);
  // The engines never read and write the same word in the same clock, so the
  // read-during-write behaviour does not matter (no_rw_check).
  generate
    if (RAMSTYLE == 1) begin : g_mlab
      (* ramstyle = "MLAB, no_rw_check" *) reg [DW-1:0] mem [0:(1<<AW)-1];
      always @(posedge clk) begin
        if (we) mem[waddr] <= wdata;
        if (re) rdata <= mem[raddr];
      end
    end else begin : g_auto
      (* ramstyle = "no_rw_check" *) reg [DW-1:0] mem [0:(1<<AW)-1];
      always @(posedge clk) begin
        if (we) mem[waddr] <= wdata;
        if (re) rdata <= mem[raddr];
      end
    end
  endgenerate
endmodule


module mlkem3_polymem #(
  parameter NS = 12,
  parameter RAMSTYLE = 0
) (
  input  wire        clk,
  // role N
  input  wire [3:0]  n_slot,
  input  wire [3:0]  n_re,
  input  wire [19:0] n_raddr,
  output wire [95:0] n_rdata,
  input  wire [3:0]  n_we,
  input  wire [19:0] n_waddr,
  input  wire [95:0] n_wdata,
  // role NA
  input  wire [3:0]  na_slot,
  input  wire [3:0]  na_re,
  input  wire [19:0] na_raddr,
  output wire [95:0] na_rdata,
  // role P
  input  wire [3:0]  p_slot,
  input  wire [3:0]  p_re,
  input  wire [19:0] p_raddr,
  output wire [95:0] p_rdata,
  input  wire [3:0]  p_we,
  input  wire [19:0] p_waddr,
  input  wire [95:0] p_wdata,
  // role PA
  input  wire [3:0]  pa_slot,
  input  wire [3:0]  pa_re,
  input  wire [19:0] pa_raddr,
  output wire [95:0] pa_rdata,
  // role PB
  input  wire [3:0]  pb_slot,
  input  wire [3:0]  pb_re,
  input  wire [19:0] pb_raddr,
  output wire [95:0] pb_rdata,
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
        wire        rn  = n_re[k]  && (n_slot  == s);
        wire        rna = na_re[k] && (na_slot == s);
        wire        rp  = p_re[k]  && (p_slot  == s);
        wire        rpa = pa_re[k] && (pa_slot == s);
        wire        rpb = pb_re[k] && (pb_slot == s);
        wire        ri  = i_re[k]  && (i_slot  == s);
        wire [4:0]  rad = rn  ? n_raddr[5*k +: 5]  :
                          rna ? na_raddr[5*k +: 5] :
                          rp  ? p_raddr[5*k +: 5]  :
                          rpa ? pa_raddr[5*k +: 5] :
                          rpb ? pb_raddr[5*k +: 5] :
                                i_raddr[5*k +: 5];
        wire        wn  = n_we[k] && (n_slot == s);
        wire        wp  = p_we[k] && (p_slot == s);
        wire        ws  = s_we[k] && (s_slot == s);
        wire        wi  = i_we[k] && (i_slot == s);
        wire [4:0]  wad = wn ? n_waddr[5*k +: 5] : wp ? p_waddr[5*k +: 5] :
                          ws ? s_waddr[5*k +: 5] : i_waddr[5*k +: 5];
        wire [23:0] wd  = wn ? n_wdata[24*k +: 24] : wp ? p_wdata[24*k +: 24] :
                          ws ? s_wdata[24*k +: 24] : i_wdata[24*k +: 24];
        wire [23:0] rd;
        mlkem3_sdp_ram #(.AW(5), .DW(24), .RAMSTYLE(RAMSTYLE)) u_ram (
          .clk  (clk),
          .re   (rn | rna | rp | rpa | rpb | ri),
          .we   (wn | wp | ws | wi),
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
  reg [3:0] n_sq, na_sq, p_sq, pa_sq, pb_sq, i_sq;
  always @(posedge clk) begin
    n_sq  <= n_slot;
    na_sq <= na_slot;
    p_sq  <= p_slot;
    pa_sq <= pa_slot;
    pb_sq <= pb_slot;
    i_sq  <= i_slot;
  end

  assign n_rdata  = rd_all[96*n_sq  +: 96];
  assign na_rdata = rd_all[96*na_sq +: 96];
  assign p_rdata  = rd_all[96*p_sq  +: 96];
  assign pa_rdata = rd_all[96*pa_sq +: 96];
  assign pb_rdata = rd_all[96*pb_sq +: 96];
  assign i_rdata  = rd_all[96*i_sq  +: 96];
endmodule


// -----------------------------------------------------------------------------
// Seed registers: entries 0..5 of 32 bytes (8 words, 4 lanes), as v2.
//   E0 K / K'   E1 sigma / r / r'   E2 H(ek)   E3 m'   E4 K-bar   E5 rho
// Keccak engine: writes and reads 64-bit lanes (lane L = words 2L, 2L+1).
// IO engine: writes 32-bit words, reads two entries at one word index.
// -----------------------------------------------------------------------------
module mlkem3_seedregs (
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
// Read stream (as v2): reads `count` consecutive RAM words from `base`
// (read latency 1) into a 4-entry FIFO; valid/ready output. `active` covers
// the reads in flight. ram_re strobes only on actual reads.
// -----------------------------------------------------------------------------
module mlkem3_rd_stream #(
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
