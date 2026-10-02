// -----------------------------------------------------------------------------
// mlkem_tdp_ram.v - true dual-port RAM, one clock, 1-cycle read latency.
//
// Written in the coding style Intel recommends for inferring a true dual-port
// M10K block RAM in Quartus ("True Dual-Port RAM with a Single Clock"), so no
// vendor IP core is needed. Yosys and Verilator understand it as well.
// -----------------------------------------------------------------------------
module mlkem_tdp_ram #(
  parameter AW = 11,  // address bits -> 2^AW words
  parameter DW = 8    // data bits per word
) (
  input  wire          clk,
  // port A
  input  wire          we_a,
  input  wire [AW-1:0] addr_a,
  input  wire [DW-1:0] d_a,
  output reg  [DW-1:0] q_a,
  // port B
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
