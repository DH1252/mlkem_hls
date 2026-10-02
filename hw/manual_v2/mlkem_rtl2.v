// -----------------------------------------------------------------------------
// mlkem_rtl2.v - top level of the v2 hand-written ML-KEM-768 accelerator.
//
// Drop-in replacement for mlkem_avalon (Bambu core) and mlkem_rtl (v1): same
// ports, register map, mailbox layout and bus behaviour (see
// hw/manual/mlkem_rtl.v for the register table). PARAMS reads 3.
//
// Mailbox: 2048 x 32-bit words as two word banks (even / odd word address),
// each four byte-wide true dual-port RAMs of 1024 x 8. Same block-RAM count
// as v1, but port B can now read one 64-bit Keccak lane (words 2L, 2L+1)
// per clock:
//   port A  Avalon when idle, core IO engine when busy (32-bit words)
//   port B  core: Keccak lane reads (64-bit) or IO second-copy writes (32-bit)
// Low power: every RAM port has an enable; nothing is read unless a bus
// read, an IO read or a Keccak lane read asks for it.
//
// Parameter KECCAK_RPC: Keccak rounds per clock (2 = fast, 1 = shorter logic
// paths, less glitching, lower peak power).
//
// UNTESTED FIRST VERSION - see hw/manual_v2/README.md.
// -----------------------------------------------------------------------------
module mlkem_rtl2 #(
  parameter MLKEM_K    = 3,   // for compatibility with mlkem_avalon; must be 3
  parameter KECCAK_RPC = 2
) (
  input  wire        clk,
  input  wire        reset,           // active high, synchronous to clk

  input  wire [11:0] avs_address,     // word address
  input  wire        avs_read,
  input  wire        avs_write,
  input  wire [31:0] avs_writedata,
  input  wire [3:0]  avs_byteenable,
  output wire [31:0] avs_readdata,

  output wire        irq
);

  localparam [31:0] ID_VALUE = 32'h4D4C4B4D;  // "MLKM"

  // ---------------------------------------------------------------------------
  // Control and status registers (as mlkem_avalon)
  // ---------------------------------------------------------------------------
  reg  [31:0] op_r;
  reg         start_r;
  reg         busy_r;
  reg         done_r;
  reg  [31:0] result_r;
  reg  [31:0] cycles_r;
  reg         irq_en_r;

  wire        csr_sel   = avs_address[11];
  wire [2:0]  csr_index = avs_address[2:0];
  wire        core_done;
  wire [31:0] core_result;

  always @(posedge clk) begin
    if (reset) begin
      op_r     <= 32'd0;
      start_r  <= 1'b0;
      busy_r   <= 1'b0;
      done_r   <= 1'b0;
      result_r <= 32'd0;
      cycles_r <= 32'd0;
      irq_en_r <= 1'b0;
    end else begin
      start_r <= 1'b0;
      if (avs_write && csr_sel) begin
        case (csr_index)
          3'd0: if (!busy_r) begin
                  op_r     <= avs_writedata;
                  start_r  <= 1'b1;
                  busy_r   <= 1'b1;
                  done_r   <= 1'b0;
                  cycles_r <= 32'd0;
                end
          3'd1: if (avs_writedata[1]) done_r <= 1'b0;
          3'd6: irq_en_r <= avs_writedata[0];
          default: ;
        endcase
      end
      if (busy_r)
        cycles_r <= cycles_r + 32'd1;
      if (busy_r && core_done) begin
        busy_r   <= 1'b0;
        done_r   <= 1'b1;
        result_r <= core_result;
      end
    end
  end

  assign irq = done_r & irq_en_r;

  // ---------------------------------------------------------------------------
  // Core
  // ---------------------------------------------------------------------------
  wire [10:0] ma_addr, mb_waddr;
  wire        ma_re, ma_we, mb_re, mb_we;
  wire [31:0] ma_wdata, ma_rdata, mb_wdata;
  wire [9:0]  mb_laddr;
  wire [63:0] mb_rdata;

  mlkem2_core #(.KR(KECCAK_RPC)) u_core (
    .clk     (clk),
    .rst     (reset),
    .start   (start_r),
    .op      (op_r),
    .done    (core_done),
    .result  (core_result),
    .ma_addr (ma_addr),
    .ma_re   (ma_re),
    .ma_we   (ma_we),
    .ma_wdata(ma_wdata),
    .ma_rdata(ma_rdata),
    .mb_re   (mb_re),
    .mb_laddr(mb_laddr),
    .mb_rdata(mb_rdata),
    .mb_we   (mb_we),
    .mb_waddr(mb_waddr),
    .mb_wdata(mb_wdata)
  );

  // ---------------------------------------------------------------------------
  // Mailbox: word bank b (0 even, 1 odd) x byte lane l
  // ---------------------------------------------------------------------------
  wire        core_owns = busy_r;
  // port A: one 32-bit word
  wire [10:0] pa_addr = core_owns ? ma_addr : avs_address[10:0];
  wire        pa_re   = core_owns ? ma_re   : (avs_read && !csr_sel);
  wire [3:0]  pa_be   = core_owns ? {4{ma_we}} : ((avs_write && !csr_sel) ? avs_byteenable : 4'b0000);
  wire [31:0] pa_d    = core_owns ? ma_wdata : avs_writedata;
  // port B: a 64-bit lane read or a 32-bit write
  wire [9:0]  pb_row  = mb_we ? mb_waddr[10:1] : mb_laddr;

  wire [7:0] qa [0:7];      // [4*b + l]
  wire [7:0] qb [0:7];

  genvar b, l;
  generate
    for (b = 0; b < 2; b = b + 1) begin : g_bank
      for (l = 0; l < 4; l = l + 1) begin : g_lane
        wire hit_a = (pa_addr[0] == b);
        mlkem2_tdp_ram #(.AW(10), .DW(8)) u_ram (
          .clk   (clk),
          .en_a  (hit_a && (pa_re || pa_be[l])),
          .we_a  (hit_a && pa_be[l]),
          .addr_a(pa_addr[10:1]),
          .d_a   (pa_d[8*l +: 8]),
          .q_a   (qa[4*b + l]),
          .en_b  (mb_re || (mb_we && (mb_waddr[0] == b))),
          .we_b  (mb_we && (mb_waddr[0] == b)),
          .addr_b(pb_row),
          .d_b   (mb_wdata[8*l +: 8]),
          .q_b   (qb[4*b + l])
        );
      end
    end
  endgenerate

  // port A read data: the bank of the word read one clock ago
  reg pa_bank_q;
  always @(posedge clk)
    if (pa_re) pa_bank_q <= pa_addr[0];

  assign ma_rdata = pa_bank_q ? {qa[7], qa[6], qa[5], qa[4]} : {qa[3], qa[2], qa[1], qa[0]};
  assign mb_rdata = {qb[7], qb[6], qb[5], qb[4], qb[3], qb[2], qb[1], qb[0]};

  // ---------------------------------------------------------------------------
  // Avalon read data, valid one clock after avs_read
  // ---------------------------------------------------------------------------
  reg        rd_csr_q;
  reg [31:0] csr_q;
  always @(posedge clk) begin
    rd_csr_q <= csr_sel;
    case (csr_index)
      3'd0:    csr_q <= op_r;
      3'd1:    csr_q <= {30'd0, done_r, busy_r};
      3'd2:    csr_q <= result_r;
      3'd3:    csr_q <= cycles_r;
      3'd4:    csr_q <= ID_VALUE;
      3'd5:    csr_q <= 32'd3;
      3'd6:    csr_q <= {31'd0, irq_en_r};
      default: csr_q <= 32'd0;
    endcase
  end
  assign avs_readdata = rd_csr_q ? csr_q : ma_rdata;

endmodule


// -----------------------------------------------------------------------------
// True dual-port RAM with a port enable per side (single clock, read latency
// 1, the output holds while the port is disabled).
// -----------------------------------------------------------------------------
module mlkem2_tdp_ram #(
  parameter AW = 10,
  parameter DW = 8
) (
  input  wire          clk,
  input  wire          en_a,
  input  wire          we_a,
  input  wire [AW-1:0] addr_a,
  input  wire [DW-1:0] d_a,
  output reg  [DW-1:0] q_a,
  input  wire          en_b,
  input  wire          we_b,
  input  wire [AW-1:0] addr_b,
  input  wire [DW-1:0] d_b,
  output reg  [DW-1:0] q_b
);
  reg [DW-1:0] ram [0:(1<<AW)-1];

  always @(posedge clk) begin
    if (en_a) begin
      if (we_a) begin
        ram[addr_a] <= d_a;
        q_a         <= d_a;
      end else begin
        q_a <= ram[addr_a];
      end
    end
  end

  always @(posedge clk) begin
    if (en_b) begin
      if (we_b) begin
        ram[addr_b] <= d_b;
        q_b         <= d_b;
      end else begin
        q_b <= ram[addr_b];
      end
    end
  end
endmodule
