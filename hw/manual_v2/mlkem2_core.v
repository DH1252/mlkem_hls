// -----------------------------------------------------------------------------
// mlkem2_core.v - the v2 hand-written ML-KEM-768 core: sequencer with
// hardware hazard checking, and the three engines.
//
// Sequencer: one instruction per clock, in order (programs in
// mlkem2_ucode.v). An engine instruction issues when
//   (1) its engine is idle, and
//   (2) it has no conflict with the operations still running on the other
//       engines: disjoint polynomial slots, disjoint seed registers, and no
//       Keccak mailbox read while the IO engine writes the mailbox (or the
//       other way round).
// Because issue is in order, every earlier instruction is either finished
// or running, so (2) covers all read-after-write, write-after-read and
// write-after-write hazards, and the structural one (a slot's RAM port
// serves one engine). The microcode needs no WAITs for them; this is what
// v1 did by hand. BR waits until the IO engine (which sets BAD) is idle.
//
// Each engine takes its command from its own copy of the issued
// instruction (h_ins, a_ins, i_ins), so its inputs only change when it gets
// new work (low power), and the hazard masks are computed once, at issue.
//
// Define MLKEM_TRACE in simulation to print every issued instruction.
//
// UNTESTED FIRST VERSION - see hw/manual_v2/README.md.
// -----------------------------------------------------------------------------
module mlkem2_core #(
  parameter KR = 2                 // Keccak rounds per clock
) (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [31:0] op,
  output reg         done,
  output reg  [31:0] result,
  // mailbox port A (32-bit, IO engine)
  output wire [10:0] ma_addr,
  output wire        ma_re,
  output wire        ma_we,
  output wire [31:0] ma_wdata,
  input  wire [31:0] ma_rdata,
  // mailbox port B: 64-bit lane reads (Keccak) or 32-bit writes (IO)
  output wire        mb_re,
  output wire [9:0]  mb_laddr,
  input  wire [63:0] mb_rdata,
  output wire        mb_we,
  output wire [10:0] mb_waddr,
  output wire [31:0] mb_wdata
);
  localparam [3:0] C_END  = 4'd0, C_WAIT = 4'd1, C_BR = 4'd2,
                   C_HASH = 4'd3, C_ALU  = 4'd4, C_IO = 4'd5;
  localparam [2:0] A_NTT = 3'd0, A_INTT = 3'd1, A_PWM = 3'd2, A_ADD = 3'd3, A_SUB = 3'd4;
  localparam [2:0] I_DEC = 3'd0, I_ENC = 3'd1, I_S2M = 3'd2, I_M2M  = 3'd3,
                   I_M2S = 3'd4, I_CMP = 3'd5, I_SEL = 3'd6, I_ZERO = 3'd7;
  localparam [1:0] K_MB = 2'd0, K_MBDUAL = 2'd1, K_CMP = 2'd2, K_SEED = 2'd3;
  localparam [1:0] OM_SEED = 2'd0;
  localparam [8:0] PC_KG = 9'd0, PC_EN = 9'd128, PC_DE = 9'd256;

  // --- resource masks of an instruction ----------------------------------------
  function [11:0] slots_of(input [79:0] w);
    begin
      slots_of = 12'd0;
      case (w[3:0])
        C_HASH: if (w[64:63] != OM_SEED) slots_of = 12'd1 << w[78:75];
        C_ALU: begin
          slots_of = 12'd1 << w[11:8];
          if ((w[6:4] == A_PWM) || (w[6:4] == A_ADD) || (w[6:4] == A_SUB) ||
              ((w[6:4] == A_INTT) && (w[21:20] != 2'd0)))
            slots_of = slots_of | (12'd1 << w[15:12]);
          if (w[6:4] == A_PWM)
            slots_of = slots_of | (12'd1 << w[19:16]);
        end
        C_IO: if ((w[6:4] == I_DEC) || (w[6:4] == I_ENC)) slots_of = 12'd1 << w[10:7];
        default: ;
      endcase
    end
  endfunction

  function [5:0] seeds_of(input [79:0] w);
    begin
      seeds_of = 6'd0;
      case (w[3:0])
        C_HASH: begin
          if (w[7])                           seeds_of = seeds_of | (6'd1 << w[10:8]);
          if (w[26] && (w[44:37] != 8'd0))    seeds_of = seeds_of | (6'd1 << w[29:27]);
          if (w[64:63] == OM_SEED) begin
            seeds_of = seeds_of | (6'd1 << w[67:65]);
            if (w[74:71] > 4'd4)              seeds_of = seeds_of | (6'd1 << w[70:68]);
          end
        end
        C_IO: case (w[6:4])
          I_DEC:                 if (w[17])             seeds_of = 6'd1 << w[43:41];
          I_ENC:                 if (w[18:17] == K_SEED) seeds_of = 6'd1 << w[43:41];
          I_S2M, I_M2S, I_CMP:                          seeds_of = 6'd1 << w[43:41];
          I_SEL:                 seeds_of = (6'd1 << w[43:41]) | (6'd1 << w[46:44]);
          default: ;
        endcase
        default: ;
      endcase
    end
  endfunction

  function mbr_of(input [79:0] w);           // Keccak job reads the mailbox
    mbr_of = (w[3:0] == C_HASH) && (!w[7] || ((w[44:37] != 8'd0) && !w[26]));
  endfunction

  function mbw_of(input [79:0] w);           // IO job writes the mailbox
    mbw_of = (w[3:0] == C_IO) &&
             (((w[6:4] == I_ENC) && ((w[18:17] == K_MB) || (w[18:17] == K_MBDUAL))) ||
              (w[6:4] == I_S2M) || (w[6:4] == I_M2M) || (w[6:4] == I_SEL) || (w[6:4] == I_ZERO));
  endfunction

  // --- sequencer ------------------------------------------------------------------
  reg        run;
  reg  [8:0] pc;
  reg [79:0] ins;                        // = ROM(pc)
  reg [79:0] h_ins, a_ins, i_ins;        // the job each engine is running
  reg        h_go, a_go, i_go;
  reg [11:0] h_sl, a_sl, i_sl;           // its slots
  reg  [5:0] h_se, i_se;                 // its seed registers
  reg        h_mr, i_mw;                 // mailbox read (Keccak) / write (IO)
  reg        bad, diff;

  wire       h_busy, a_busy, i_busy;
  wire       io_bad_set, io_diff_set;
  wire [79:0] rom_q;
  wire [3:0] cls = ins[3:0];

  wire [11:0] n_sl = slots_of(ins);
  wire  [5:0] n_se = seeds_of(ins);
  wire        n_mr = mbr_of(ins);
  wire        n_mw = mbw_of(ins);

  wire hz_h = h_busy && (((n_sl & h_sl) != 12'd0) || ((n_se & h_se) != 6'd0) || (n_mw && h_mr));
  wire hz_a = a_busy &&  ((n_sl & a_sl) != 12'd0);
  wire hz_i = i_busy && (((n_sl & i_sl) != 12'd0) || ((n_se & i_se) != 6'd0) || (n_mr && i_mw));
  wire hazard   = hz_h | hz_a | hz_i;
  wire wait_ok  = !(ins[4] && h_busy) && !(ins[5] && a_busy) && !(ins[6] && i_busy);
  wire all_idle = !h_busy && !a_busy && !i_busy;
  wire op_ok    = (op == 32'd1) || (op == 32'd2) || (op == 32'd3);

  reg  [8:0] pc_nx;
  reg        iss_h, iss_a, iss_i, fin;

  always @* begin
    pc_nx = pc;
    iss_h = 1'b0;
    iss_a = 1'b0;
    iss_i = 1'b0;
    fin   = 1'b0;
    if (!run) begin
      if (start)
        pc_nx = (op[1:0] == 2'd1) ? PC_KG : (op[1:0] == 2'd2) ? PC_EN : PC_DE;
    end else begin
      case (cls)
        C_END:  fin = all_idle;
        C_WAIT: if (wait_ok) pc_nx = pc + 9'd1;
        C_BR:   if (!i_busy) pc_nx = bad ? ins[16:8] : (pc + 9'd1);
        C_HASH: if (!h_busy && !hazard) begin iss_h = 1'b1; pc_nx = pc + 9'd1; end
        C_ALU:  if (!a_busy && !hazard) begin iss_a = 1'b1; pc_nx = pc + 9'd1; end
        C_IO:   if (!i_busy && !hazard) begin iss_i = 1'b1; pc_nx = pc + 9'd1; end
        default: fin = 1'b1;              // not an instruction: stop, status 15
      endcase
    end
  end

  mlkem2_ucode u_rom (.addr(pc_nx), .ins(rom_q));

  always @(posedge clk) begin
    pc  <= pc_nx;
    ins <= rom_q;                        // registered ROM output, matches pc
    if (iss_h) begin h_ins <= ins; h_sl <= n_sl; h_se <= n_se; h_mr <= n_mr; end
    if (iss_a) begin a_ins <= ins; a_sl <= n_sl; end
    if (iss_i) begin i_ins <= ins; i_sl <= n_sl; i_se <= n_se; i_mw <= n_mw; end
  end

  always @(posedge clk) begin
    if (rst) begin
      run    <= 1'b0;
      done   <= 1'b0;
      result <= 32'd0;
      h_go   <= 1'b0;
      a_go   <= 1'b0;
      i_go   <= 1'b0;
      bad    <= 1'b0;
      diff   <= 1'b0;
    end else begin
      done <= 1'b0;
      h_go <= iss_h;
      a_go <= iss_a;
      i_go <= iss_i;
      if (!run) begin
        if (start) begin
          bad  <= 1'b0;
          diff <= 1'b0;
          if (op_ok) begin
            run <= 1'b1;
          end else begin
            done   <= 1'b1;
            result <= 32'd2;               // MLKEM_STATUS_BAD_OP
          end
        end
      end else begin
        if (io_bad_set)  bad  <= 1'b1;
        if (io_diff_set) diff <= 1'b1;
        if (fin) begin
          run    <= 1'b0;
          done   <= 1'b1;
          result <= (cls == C_END) ? {28'd0, ins[7:4]} : 32'd15;
        end
      end
    end
  end

`ifdef MLKEM_TRACE
  // synthesis translate_off
  always @(posedge clk) begin
    if (!rst && run) begin
      if (iss_h) $display("%0t %3d HASH om %0d slot S%0d", $time, pc, ins[64:63], ins[78:75]);
      if (iss_a) $display("%0t %3d ALU  op %0d c S%0d a S%0d b S%0d acc %0d fuse %0d",
                          $time, pc, ins[6:4], ins[11:8], ins[15:12], ins[19:16], ins[7], ins[21:20]);
      if (iss_i) $display("%0t %3d IO   op %0d slot S%0d d %0d sel %0d acc %0d addr %h E%0d",
                          $time, pc, ins[6:4], ins[10:7], ins[14:11], ins[18:17], ins[51],
                          ins[29:19], ins[43:41]);
      if (cls == C_BR && !i_busy) $display("%0t %3d BR   bad %0d", $time, pc, bad);
      if (fin) $display("%0t %3d END  status %0d (bad %0d diff %0d)", $time, pc, ins[7:4], bad, diff);
    end
  end
  // synthesis translate_on
`endif

  // --- Keccak engine -------------------------------------------------------------------
  wire [2:0]  hs_sr_ent;
  wire [1:0]  hs_sr_lane;
  wire [63:0] hs_sr_data;
  wire        hs_sw_we;
  wire [2:0]  hs_sw_ent;
  wire [1:0]  hs_sw_lane;
  wire [63:0] hs_sw_data;
  wire        hs_mb_active;
  wire [3:0]  s_slot, s_we;
  wire [19:0] s_waddr;
  wire [95:0] s_wdata;

  mlkem2_hash #(.KR(KR)) u_hash (
    .clk      (clk),
    .rst      (rst),
    .start    (h_go),
    .rate_in  (h_ins[5:4]),
    .shake_in (h_ins[6]),
    .p1s_in   (h_ins[7]),
    .p1a_in   (h_ins[17:8]),
    .p1n_in   (h_ins[25:18]),
    .p2s_in   (h_ins[26]),
    .p2a_in   (h_ins[36:27]),
    .p2n_in   (h_ins[44:37]),
    .sfn_in   (h_ins[46:45]),
    .sfx_in   (h_ins[62:47]),
    .om_in    (h_ins[64:63]),
    .oe0_in   (h_ins[67:65]),
    .oe1_in   (h_ins[70:68]),
    .on_in    (h_ins[74:71]),
    .oslot_in (h_ins[78:75]),
    .busy     (h_busy),
    .mb_active(hs_mb_active),
    .mb_re    (mb_re),
    .mb_laddr (mb_laddr),
    .mb_rdata (mb_rdata),
    .sr_ent   (hs_sr_ent),
    .sr_lane  (hs_sr_lane),
    .sr_data  (hs_sr_data),
    .sw_we    (hs_sw_we),
    .sw_ent   (hs_sw_ent),
    .sw_lane  (hs_sw_lane),
    .sw_data  (hs_sw_data),
    .s_slot   (s_slot),
    .s_we     (s_we),
    .s_waddr  (s_waddr),
    .s_wdata  (s_wdata)
  );

  // --- polynomial ALU --------------------------------------------------------------------
  wire [3:0]  c_slot, a_slot, b_slot, c_re, a_re, b_re, c_we;
  wire [19:0] c_raddr, c_waddr, a_raddr, b_raddr;
  wire [95:0] c_rdata, c_wdata, a_rdata, b_rdata;

  mlkem2_alu u_alu (
    .clk    (clk),
    .rst    (rst),
    .start  (a_go),
    .op_in  (a_ins[6:4]),
    .acc_in (a_ins[7]),
    .fuse_in(a_ins[21:20]),
    .c_in   (a_ins[11:8]),
    .a_in   (a_ins[15:12]),
    .b_in   (a_ins[19:16]),
    .busy   (a_busy),
    .c_slot (c_slot),
    .a_slot (a_slot),
    .b_slot (b_slot),
    .c_re   (c_re),
    .c_raddr(c_raddr),
    .c_rdata(c_rdata),
    .c_we   (c_we),
    .c_waddr(c_waddr),
    .c_wdata(c_wdata),
    .a_re   (a_re),
    .a_raddr(a_raddr),
    .a_rdata(a_rdata),
    .b_re   (b_re),
    .b_raddr(b_raddr),
    .b_rdata(b_rdata)
  );

  // --- IO engine -------------------------------------------------------------------------
  wire [2:0]  io_sr_ent, io_sr_word, io_sr2_ent, io_sw_ent, io_sw_word;
  wire [31:0] io_sr_data, io_sr2_data, io_sw_data;
  wire        io_sw_we;
  wire [3:0]  i_slot, i_re, i_we;
  wire [19:0] i_raddr, i_waddr;
  wire [95:0] i_rdata, i_wdata;

  mlkem2_io u_io (
    .clk      (clk),
    .rst      (rst),
    .start    (i_go),
    .op_in    (i_ins[6:4]),
    .slot_in  (i_ins[10:7]),
    .d_in     (i_ins[14:11]),
    .fa_in    (i_ins[15]),
    .fb_in    (i_ins[16]),
    .acc_in   (i_ins[51]),
    .sel_in   (i_ins[18:17]),
    .addr_in  (i_ins[29:19]),
    .addr2_in (i_ins[40:30]),
    .ent_in   (i_ins[43:41]),
    .ent2_in  (i_ins[46:44]),
    .n_in     (i_ins[50:47]),
    .diff_flag(diff),
    .busy     (i_busy),
    .bad_set  (io_bad_set),
    .diff_set (io_diff_set),
    .pa_addr  (ma_addr),
    .pa_re    (ma_re),
    .pa_we    (ma_we),
    .pa_wdata (ma_wdata),
    .pa_rdata (ma_rdata),
    .pb_addr  (mb_waddr),
    .pb_we    (mb_we),
    .pb_wdata (mb_wdata),
    .sr_ent   (io_sr_ent),
    .sr_word  (io_sr_word),
    .sr_data  (io_sr_data),
    .sr2_ent  (io_sr2_ent),
    .sr2_data (io_sr2_data),
    .sw_we    (io_sw_we),
    .sw_ent   (io_sw_ent),
    .sw_word  (io_sw_word),
    .sw_data  (io_sw_data),
    .i_slot   (i_slot),
    .i_re     (i_re),
    .i_raddr  (i_raddr),
    .i_rdata  (i_rdata),
    .i_we     (i_we),
    .i_waddr  (i_waddr),
    .i_wdata  (i_wdata)
  );

  // --- storage ---------------------------------------------------------------------------
  mlkem2_polymem #(.NS(12)) u_pmem (
    .clk    (clk),
    .c_slot (c_slot), .c_re(c_re), .c_raddr(c_raddr), .c_rdata(c_rdata),
    .c_we   (c_we),   .c_waddr(c_waddr), .c_wdata(c_wdata),
    .a_slot (a_slot), .a_re(a_re), .a_raddr(a_raddr), .a_rdata(a_rdata),
    .b_slot (b_slot), .b_re(b_re), .b_raddr(b_raddr), .b_rdata(b_rdata),
    .s_slot (s_slot), .s_we(s_we), .s_waddr(s_waddr), .s_wdata(s_wdata),
    .i_slot (i_slot), .i_re(i_re), .i_raddr(i_raddr), .i_rdata(i_rdata),
    .i_we   (i_we),   .i_waddr(i_waddr), .i_wdata(i_wdata)
  );

  mlkem2_seedregs u_seed (
    .clk     (clk),
    .h_we    (hs_sw_we),
    .h_ent   (hs_sw_ent),
    .h_lane  (hs_sw_lane),
    .h_wdata (hs_sw_data),
    .hr_ent  (hs_sr_ent),
    .hr_lane (hs_sr_lane),
    .hr_data (hs_sr_data),
    .i_we    (io_sw_we),
    .i_ent   (io_sw_ent),
    .i_word  (io_sw_word),
    .i_wdata (io_sw_data),
    .ir_ent  (io_sr_ent),
    .ir_word (io_sr_word),
    .ir_data (io_sr_data),
    .ir2_ent (io_sr2_ent),
    .ir2_data(io_sr2_data)
  );

  // hs_mb_active is not needed outside: the hazard check keeps Keccak mailbox
  // reads and IO mailbox writes apart, so port B has one user at a time.
endmodule
