// -----------------------------------------------------------------------------
// mlkem_avalon.v - Avalon-MM wrapper around the Bambu-generated ML-KEM core.
//
// Gives the accelerator a memory-mapped interface that the Cyclone V HPS
// (ARM cores, through the lightweight HPS-to-FPGA bridge) or a JTAG-to-Avalon
// master can drive. 16 KB address span:
//
//   byte offset       what
//   0x0000 - 0x1FFF   mailbox RAM, 8 KB (layout in src/mlkem_accel.h)
//   0x2000  CTRL      W: write an operation code (1 KeyGen, 2 Encaps,
//                        3 Decaps) to start it; ignored while busy
//                     R: last operation code
//   0x2004  STATUS    R: bit 0 BUSY, bit 1 DONE
//                     W: write 1 to bit 1 to clear DONE (and the interrupt)
//   0x2008  RESULT    R: status returned by the operation (0 = OK,
//                        1 = key failed its input check, 2 = bad op code)
//   0x200C  CYCLES    R: clock cycles the last operation took
//   0x2010  ID        R: 0x4D4C4B4D ("MLKM")
//   0x2014  PARAMS    R: k (2 = ML-KEM-512, 3 = ML-KEM-768, 4 = ML-KEM-1024)
//   0x2018  IRQ_EN    R/W: bit 0 enables the interrupt output
//
// While BUSY the core owns the mailbox RAM; software must not read or write
// the mailbox until DONE is set (reads return undefined data, writes are
// dropped).
//
// Avalon-MM slave: 32-bit data, word addresses (12 bits), byte enables,
// fixed read latency of 1 clock, no wait states.
//
// The mailbox is four byte-wide dual-port RAMs ("lanes"), so the 32-bit
// Avalon side reads and writes whole words while the core, which has two
// independent byte-wide RAM ports, reaches any byte from either port.
// -----------------------------------------------------------------------------
module mlkem_avalon #(
  parameter MLKEM_K = 3  // must match the -DMLKEM_K the core was generated with
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
  // Control and status registers
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
  // The HLS core
  // ---------------------------------------------------------------------------
  wire [12:0] mem_address0, mem_address1;
  wire        mem_ce0, mem_ce1, mem_we0, mem_we1;
  wire [7:0]  mem_d0, mem_d1;
  wire [7:0]  mem_q0, mem_q1;

  mlkem_accel u_core (
    .clock       (clk),
    .reset       (reset),
    .start_port  (start_r),
    .op          (op_r),
    .done_port   (core_done),
    .return_port (core_result),
    .mem_address0(mem_address0),
    .mem_ce0     (mem_ce0),
    .mem_we0     (mem_we0),
    .mem_d0      (mem_d0),
    .mem_q0      (mem_q0),
    .mem_address1(mem_address1),
    .mem_ce1     (mem_ce1),
    .mem_we1     (mem_we1),
    .mem_d1      (mem_d1),
    .mem_q1      (mem_q1)
  );

  // ---------------------------------------------------------------------------
  // Mailbox RAM: 4 byte lanes x 2048 bytes
  //   port A: Avalon when idle, core port 0 when busy
  //   port B: core port 1
  // ---------------------------------------------------------------------------
  wire core_owns = busy_r;  // set in the same cycle start_r goes high

  wire [7:0] qa[0:3];
  wire [7:0] qb[0:3];

  genvar lane;
  generate
    for (lane = 0; lane < 4; lane = lane + 1) begin : g_lane
      wire hit0 = mem_ce0 && (mem_address0[1:0] == lane);
      wire hit1 = mem_ce1 && (mem_address1[1:0] == lane);

      wire        we_a   = core_owns ? (hit0 && mem_we0)
                                     : (avs_write && !csr_sel && avs_byteenable[lane]);
      wire [10:0] addr_a = core_owns ? mem_address0[12:2] : avs_address[10:0];
      wire [7:0]  d_a    = core_owns ? mem_d0 : avs_writedata[8*lane +: 8];

      mlkem_tdp_ram #(.AW(11), .DW(8)) u_ram (
        .clk   (clk),
        .we_a  (we_a),
        .addr_a(addr_a),
        .d_a   (d_a),
        .q_a   (qa[lane]),
        .we_b  (hit1 && mem_we1),
        .addr_b(mem_address1[12:2]),
        .d_b   (mem_d1),
        .q_b   (qb[lane])
      );
    end
  endgenerate

  // The core reads one byte per port; pick its lane one cycle later, when the
  // RAM output is valid (1-cycle read latency, as Bambu's array interface
  // expects).
  reg [1:0] lane0_q, lane1_q;
  always @(posedge clk) begin
    lane0_q <= mem_address0[1:0];
    lane1_q <= mem_address1[1:0];
  end
  assign mem_q0 = qa[lane0_q];
  assign mem_q1 = qb[lane1_q];

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
      3'd5:    csr_q <= MLKEM_K;
      3'd6:    csr_q <= {31'd0, irq_en_r};
      default: csr_q <= 32'd0;
    endcase
  end
  assign avs_readdata = rd_csr_q ? csr_q : {qa[3], qa[2], qa[1], qa[0]};

endmodule
