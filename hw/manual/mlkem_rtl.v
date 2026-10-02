// -----------------------------------------------------------------------------
// mlkem_rtl.v - top level of the hand-written ML-KEM-768 accelerator.
//
// A drop-in replacement for mlkem_avalon (hw/rtl/mlkem_avalon.v, the Bambu
// core): same ports, same register map, same mailbox layout
// (src/mlkem_accel.h), same behaviour seen from the bus. The testbench
// (hw/sim/tb_mlkem_avalon.sv), the System Console script and the ARM program
// work with either.
//
//   byte offset       what
//   0x0000 - 0x1FFF   mailbox RAM, 8 KB
//   0x2000  CTRL      W: operation code (1 KeyGen, 2 Encaps, 3 Decaps) starts
//                        it; ignored while busy.  R: last operation code
//   0x2004  STATUS    R: bit 0 BUSY, bit 1 DONE.  W: 1 to bit 1 clears DONE
//   0x2008  RESULT    R: 0 OK, 1 key failed its input check, 2 bad op code
//   0x200C  CYCLES    R: clock cycles the last operation took
//   0x2010  ID        R: 0x4D4C4B4D ("MLKM")
//   0x2014  PARAMS    R: k = 3 (this core is ML-KEM-768 only)
//   0x2018  IRQ_EN    R/W: bit 0 enables the interrupt output
//
// While BUSY the core owns the mailbox (reads return undefined data, writes
// are dropped).
//
// The mailbox is four byte-wide true dual-port RAMs: the Avalon side needs
// byte enables; the core always moves whole 32-bit words through both ports.
//
// UNTESTED FIRST VERSION - see hw/manual/README.md.
// -----------------------------------------------------------------------------
module mlkem_rtl #(
  parameter MLKEM_K = 3  // kept for compatibility with mlkem_avalon; must be 3
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
  // Control and status registers (as in mlkem_avalon)
  // ---------------------------------------------------------------------------
  reg  [31:0] op_r;
  reg         start_r;      // one-cycle start pulse to the core
  reg         busy_r;
  reg         done_r;
  reg  [31:0] result_r;
  reg  [31:0] cycles_r;
  reg         irq_en_r;

  wire        csr_sel   = avs_address[11];         // 0x2000 and up
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
          3'd0: if (!busy_r) begin              // CTRL: start an operation
                  op_r     <= avs_writedata;
                  start_r  <= 1'b1;
                  busy_r   <= 1'b1;
                  done_r   <= 1'b0;
                  cycles_r <= 32'd0;
                end
          3'd1: if (avs_writedata[1]) done_r <= 1'b0;  // STATUS: clear DONE
          3'd6: irq_en_r <= avs_writedata[0];          // IRQ_EN
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
  // The core
  // ---------------------------------------------------------------------------
  wire [10:0] ma_addr, mb_addr;
  wire        ma_we, mb_we;
  wire [31:0] ma_wdata, mb_wdata;
  wire [31:0] ma_rdata, mb_rdata;

  mlkem_rtl_core u_core (
    .clk     (clk),
    .rst     (reset),
    .start   (start_r),
    .op      (op_r),
    .done    (core_done),
    .result  (core_result),
    .ma_addr (ma_addr),
    .ma_we   (ma_we),
    .ma_wdata(ma_wdata),
    .ma_rdata(ma_rdata),
    .mb_addr (mb_addr),
    .mb_we   (mb_we),
    .mb_wdata(mb_wdata),
    .mb_rdata(mb_rdata)
  );

  // ---------------------------------------------------------------------------
  // Mailbox RAM: 4 byte lanes x 2048 words
  //   port A: Avalon when idle, core port A when busy
  //   port B: core port B
  // ---------------------------------------------------------------------------
  wire core_owns = busy_r;  // set in the same cycle start_r goes high

  genvar lane;
  generate
    for (lane = 0; lane < 4; lane = lane + 1) begin : g_lane
      wire        we_a   = core_owns ? ma_we
                                     : (avs_write && !csr_sel && avs_byteenable[lane]);
      wire [10:0] addr_a = core_owns ? ma_addr : avs_address[10:0];
      wire [7:0]  d_a    = core_owns ? ma_wdata[8*lane +: 8] : avs_writedata[8*lane +: 8];

      mlkem_rtl_tdp_ram #(.AW(11), .DW(8)) u_ram (
        .clk   (clk),
        .we_a  (we_a),
        .addr_a(addr_a),
        .d_a   (d_a),
        .q_a   (ma_rdata[8*lane +: 8]),
        .we_b  (mb_we),
        .addr_b(mb_addr),
        .d_b   (mb_wdata[8*lane +: 8]),
        .q_b   (mb_rdata[8*lane +: 8])
      );
    end
  endgenerate

  // ---------------------------------------------------------------------------
  // Avalon read data, valid one cycle after avs_read
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
      3'd5:    csr_q <= 32'd3;                   // ML-KEM-768
      3'd6:    csr_q <= {31'd0, irq_en_r};
      default: csr_q <= 32'd0;
    endcase
  end
  assign avs_readdata = rd_csr_q ? csr_q : ma_rdata;

endmodule


// -----------------------------------------------------------------------------
// True dual-port RAM, one clock, read latency 1 (Intel's recommended coding
// style for an inferred M10K). A private copy of hw/rtl/mlkem_tdp_ram.v, so
// that hw/manual is self-contained and both cores can sit in one project.
// -----------------------------------------------------------------------------
module mlkem_rtl_tdp_ram #(
  parameter AW = 11,
  parameter DW = 8
) (
  input  wire          clk,
  input  wire          we_a,
  input  wire [AW-1:0] addr_a,
  input  wire [DW-1:0] d_a,
  output reg  [DW-1:0] q_a,
  input  wire          we_b,
  input  wire [AW-1:0] addr_b,
  input  wire [DW-1:0] d_b,
  output reg  [DW-1:0] q_b
);

  reg [DW-1:0] ram[0:(1<<AW)-1];

  always @(posedge clk) begin
    if (we_a) begin
      ram[addr_a] <= d_a;
      q_a         <= d_a;
    end else begin
      q_a <= ram[addr_a];
    end
  end

  always @(posedge clk) begin
    if (we_b) begin
      ram[addr_b] <= d_b;
      q_b         <= d_b;
    end else begin
      q_b <= ram[addr_b];
    end
  end

endmodule
