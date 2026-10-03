// -----------------------------------------------------------------------------
// pqse_spi.v - SPI slave (mode 0) for the PQSE register bus: the chip's only
// interface (4 pins + IRQ). SCK, CS_N and MOSI are oversampled by the system
// clock, so SCK must be at most clk / 4.
//
// Transaction (CS_N low for its whole length):
//   write: 0x02, addr[11:8], addr[7:0], then 4 bytes per 32-bit word
//          (least significant byte first), the address increments per word
//   read : 0x03, addr[11:8], addr[7:0], one dummy byte, then 4 bytes per word
//          (MISO, least significant byte first, MSB of each byte first)
// Word addresses as in pqse_host.v.
//
// UNTESTED FIRST VERSION - see hw/se/README.md.
// -----------------------------------------------------------------------------
module pqse_spi (
  input  wire        clk,
  input  wire        rst,
  input  wire        sck,
  input  wire        cs_n,
  input  wire        mosi,
  output wire        miso,
  output reg         bus_we,
  output reg         bus_re,
  output reg  [11:0] bus_addr,
  output reg  [31:0] bus_wdata,
  input  wire [31:0] bus_rdata
);
  reg [2:0] s_sck, s_cs, s_mo;
  always @(posedge clk) begin
    s_sck <= {s_sck[1:0], sck};
    s_cs  <= {s_cs[1:0],  cs_n};
    s_mo  <= {s_mo[1:0],  mosi};
  end
  wire sck_r  = (s_sck[2:1] == 2'b01);
  wire sck_f  = (s_sck[2:1] == 2'b10);
  wire active = !s_cs[1];
  wire cs_f   = (s_cs[2:1] == 2'b10);

  reg  [2:0]  bitn;
  reg  [7:0]  sh_in;
  reg  [7:0]  sh_out;
  reg  [15:0] nbyte;     // bytes received in this transaction
  reg  [7:0]  opc;
  reg  [31:0] ow;        // word being sent
  reg         rd_v;      // bus_re was on the bus last clock: bus_rdata is valid now
  reg  [1:0]  bsel;      // byte of ow to send next

  assign miso = active ? sh_out[7] : 1'b0;

  wire [7:0] rx = {sh_in[6:0], s_mo[1]};

  always @(posedge clk) begin
    if (rst) begin
      bitn <= 3'd0; nbyte <= 16'd0; bus_we <= 1'b0; bus_re <= 1'b0; rd_v <= 1'b0;
      sh_out <= 8'd0;
    end else begin
      bus_we <= 1'b0;
      bus_re <= 1'b0;
      // bus_re is a register: the host samples it (and bus_addr) one clock after
      // it is set here, and its data is valid one clock after that (read
      // latency 1), so the word is taken the clock after bus_re was on the bus
      rd_v <= bus_re;
      if (rd_v) ow <= bus_rdata;
      if (!active) begin
        bitn  <= 3'd0;
        nbyte <= 16'd0;
        sh_out <= 8'd0;
      end else begin
        if (cs_f) sh_out <= 8'd0;
        if (sck_r) begin
          sh_in <= rx;
          bitn  <= bitn + 3'd1;
          if (bitn == 3'd7) begin        // a byte is complete
            nbyte <= nbyte + 16'd1;
            case (nbyte)
              16'd0: opc <= rx;
              16'd1: bus_addr[11:8] <= rx[3:0];
              16'd2: begin
                bus_addr[7:0] <= rx;
                if (opc == 8'h03) begin bus_re <= 1'b1; bsel <= 2'd0; end
              end
              default: if (opc == 8'h02) begin
                bus_wdata <= {rx, bus_wdata[31:8]};
                if (nbyte[1:0] == 2'd2) begin  // 4th byte of a word (bytes 3..6, 7..10, ...)
                  bus_we <= 1'b1;
                end
              end
            endcase
          end
        end
        // write address increment after each word
        if (bus_we) bus_addr <= bus_addr + 12'd1;
        // MISO: shift on the falling edge; at byte boundaries load the next byte
        if (sck_f) begin
          if (bitn == 3'd0 && opc == 8'h03 && nbyte >= 16'd4) begin
            sh_out <= ow[8*bsel +: 8];
            if (bsel == 2'd3) begin      // fetch the next word
              bus_addr <= bus_addr + 12'd1;
              bus_re   <= 1'b1;
            end
            bsel <= bsel + 2'd1;
          end else begin
            sh_out <= {sh_out[6:0], 1'b0};
          end
        end
      end
    end
  end
endmodule
