// -----------------------------------------------------------------------------
// mlkem3_core.v - the v3 hand-written ML-KEM-768 core: sequencer with
// hardware hazard checking, and four engines that run in parallel:
//
//   H  Keccak engine + samplers   (mlkem3_hash.v, mlkem3_sample.v)
//   N  NTT engine                 (mlkem3_ntt.v)    NTT / INTT (+ fused add)
//   P  pointwise engine           (mlkem3_pwm.v)    PWM / ADD / SUB
//   I  IO engine                  (mlkem3_io.v)     encode / decode / words
//
// (v2 had three: the NTT and the pointwise ops shared one ALU, which was busy
// 80-87 % of every operation.)
//
// Sequencer: one instruction per clock, in order (programs in
// mlkem3_ucode.v). An engine instruction issues when its engine is idle and
// it has no conflict with the jobs still running on the other engines:
//   - polynomial slots: disjoint (this also gives each slot's RAMs to one
//     engine at a time)
//   - seed registers: disjoint
//   - mailbox (v3: by region): a Keccak job may not read a mailbox region
//     that a running IO job writes, or the other way round. Regions:
//     0 seeds/K (words 0x000-0x03F), 1 ek (0x040-0x1FF), 2 dk (0x200-0x5FF),
//     3 ciphertext (0x600-0x7FF). So KeyGen can write dk while H(ek) reads
//     ek. Mailbox port B is shared by Keccak lane reads and IO second-copy
//     writes, so those two also exclude each other.
// Because issue is in order, this covers every true dependency and conflict;
// the programs need no WAITs. BR waits until the IO engine (which sets BAD)
// is idle.
//
// The hazard masks of the next instruction are computed from the ROM output
// before it is registered, so the issue decision only compares registers.
// Each engine takes its command from its own copy of the issued instruction,
// so its inputs only change when it gets new work (low power).
//
// Define MLKEM_TRACE in simulation to print every issued instruction and,
// at the end of each operation, how many clocks each engine was busy.
//
// UNTESTED FIRST VERSION of v3 - see hw/manual_v3/README.md.
// -----------------------------------------------------------------------------
module mlkem3_core #(
  parameter KR       = 2,          // Keccak rounds per clock
  parameter RAMSTYLE = 0           // polynomial RAMs: 0 auto (M10K), 1 MLAB
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
  localparam [3:0] C_END = 4'd0, C_WAIT = 4'd1, C_BR  = 4'd2, C_HASH = 4'd3,
                   C_NTT = 4'd4, C_IO   = 4'd5, C_PWM = 4'd6;
  localparam [2:0] A_PWM = 3'd2;
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
        C_NTT: begin
          slots_of = 12'd1 << w[11:8];
          if (w[21:20] != 2'd0) slots_of = slots_of | (12'd1 << w[15:12]);
        end
        C_PWM: begin
          slots_of = (12'd1 << w[11:8]) | (12'd1 << w[15:12]);
          if (w[6:4] == A_PWM) slots_of = slots_of | (12'd1 << w[19:16]);
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

  // mailbox region of a word address
  function [3:0] rgn(input [10:0] a);
    rgn = (a < 11'h040) ? 4'b0001 :
          (a < 11'h200) ? 4'b0010 :
          (a < 11'h600) ? 4'b0100 : 4'b1000;
  endfunction

  // regions a Keccak job reads (its mailbox parts; lane address -> word)
  function [3:0] hrd_of(input [79:0] w);
    begin
      hrd_of = 4'd0;
      if (w[3:0] == C_HASH) begin
        if (!w[7])                           hrd_of = hrd_of | rgn({w[17:8], 1'b0});
        if (!w[26] && (w[44:37] != 8'd0))    hrd_of = hrd_of | rgn({w[36:27], 1'b0});
      end
    end
  endfunction

  // regions an IO job writes
  function [3:0] iwr_of(input [79:0] w);
    begin
      iwr_of = 4'd0;
      if (w[3:0] == C_IO)
        case (w[6:4])
          I_ENC: begin
            if (w[18:17] == K_MB)     iwr_of = rgn(w[29:19]);
            if (w[18:17] == K_MBDUAL) iwr_of = rgn(w[29:19]) | rgn(w[40:30]);
          end
          I_S2M:          iwr_of = rgn(w[29:19]) | (w[15] ? rgn(w[40:30]) : 4'd0);
          I_M2M:          iwr_of = rgn(w[40:30]);
          I_SEL, I_ZERO:  iwr_of = rgn(w[29:19]);
          default: ;
        endcase
    end
  endfunction

  // IO job writing through mailbox port B
  function ipb_of(input [79:0] w);
    ipb_of = (w[3:0] == C_IO) &&
             (((w[6:4] == I_ENC) && (w[18:17] == K_MBDUAL)) ||
              ((w[6:4] == I_S2M) && w[15]) ||
              (w[6:4] == I_M2M));
  endfunction

  // --- sequencer ------------------------------------------------------------------
  reg        run;
  reg  [8:0] pc;
  reg [79:0] ins;                        // = ROM(pc)
  reg [11:0] q_sl;                       // its masks
  reg  [5:0] q_se;
  reg  [3:0] q_hrd, q_iwr;
  reg        q_hpb, q_ipb;
  reg [79:0] h_ins, n_ins, p_ins, i_ins; // the job each engine is running
  reg        h_go, n_go, p_go, i_go;
  reg [11:0] h_sl, n_sl, p_sl, i_sl;     // its slots
  reg  [5:0] h_se, i_se;                 // its seed registers
  reg  [3:0] h_rg, i_rg;                 // mailbox regions read (H) / written (I)
  reg        h_pb, i_pb;                 // mailbox port B in use
  reg        bad, diff;

  wire       h_busy, n_busy, p_busy, i_busy;
  wire       io_bad_set, io_diff_set;
  wire [79:0] rom_q;
  wire [3:0] cls = ins[3:0];

  wire hz_h = h_busy && (((q_sl & h_sl) != 12'd0) || ((q_se & h_se) != 6'd0) ||
                         ((q_iwr & h_rg) != 4'd0) || (q_ipb && h_pb));
  wire hz_n = n_busy &&  ((q_sl & n_sl) != 12'd0);
  wire hz_p = p_busy &&  ((q_sl & p_sl) != 12'd0);
  wire hz_i = i_busy && (((q_sl & i_sl) != 12'd0) || ((q_se & i_se) != 6'd0) ||
                         ((q_hrd & i_rg) != 4'd0) || (q_hpb && i_pb));
  wire hazard   = hz_h | hz_n | hz_p | hz_i;
  wire wait_ok  = !(ins[4] && h_busy) && !(ins[5] && n_busy) &&
                  !(ins[6] && i_busy) && !(ins[7] && p_busy);
  wire all_idle = !h_busy && !n_busy && !p_busy && !i_busy;
  wire op_ok    = (op == 32'd1) || (op == 32'd2) || (op == 32'd3);

  reg  [8:0] pc_nx;
  reg        iss_h, iss_n, iss_p, iss_i, fin;

  always @* begin
    pc_nx = pc;
    iss_h = 1'b0;
    iss_n = 1'b0;
    iss_p = 1'b0;
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
        C_NTT:  if (!n_busy && !hazard) begin iss_n = 1'b1; pc_nx = pc + 9'd1; end
        C_PWM:  if (!p_busy && !hazard) begin iss_p = 1'b1; pc_nx = pc + 9'd1; end
        C_IO:   if (!i_busy && !hazard) begin iss_i = 1'b1; pc_nx = pc + 9'd1; end
        default: fin = 1'b1;              // not an instruction: stop, status 15
      endcase
    end
  end

  mlkem3_ucode u_rom (.addr(pc_nx), .ins(rom_q));

  always @(posedge clk) begin
    pc    <= pc_nx;
    ins   <= rom_q;                      // registered ROM output, matches pc
    q_sl  <= slots_of(rom_q);
    q_se  <= seeds_of(rom_q);
    q_hrd <= hrd_of(rom_q);
    q_hpb <= (hrd_of(rom_q) != 4'd0);
    q_iwr <= iwr_of(rom_q);
    q_ipb <= ipb_of(rom_q);
    if (iss_h) begin h_ins <= ins; h_sl <= q_sl; h_se <= q_se; h_rg <= q_hrd; h_pb <= q_hpb; end
    if (iss_n) begin n_ins <= ins; n_sl <= q_sl; end
    if (iss_p) begin p_ins <= ins; p_sl <= q_sl; end
    if (iss_i) begin i_ins <= ins; i_sl <= q_sl; i_se <= q_se; i_rg <= q_iwr; i_pb <= q_ipb; end
  end

  always @(posedge clk) begin
    if (rst) begin
      run    <= 1'b0;
      done   <= 1'b0;
      result <= 32'd0;
      h_go   <= 1'b0;
      n_go   <= 1'b0;
      p_go   <= 1'b0;
      i_go   <= 1'b0;
      bad    <= 1'b0;
      diff   <= 1'b0;
    end else begin
      done <= 1'b0;
      h_go <= iss_h;
      n_go <= iss_n;
      p_go <= iss_p;
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
  integer t_all, t_h, t_n, t_p, t_i;
  always @(posedge clk) begin
    if (rst || (!run && start)) begin
      t_all = 0; t_h = 0; t_n = 0; t_p = 0; t_i = 0;
    end else if (run) begin
      t_all = t_all + 1;
      if (h_busy) t_h = t_h + 1;
      if (n_busy) t_n = t_n + 1;
      if (p_busy) t_p = t_p + 1;
      if (i_busy) t_i = t_i + 1;
      if (iss_h) $display("%0t %3d HASH om %0d slot S%0d", $time, pc, ins[64:63], ins[78:75]);
      if (iss_n) $display("%0t %3d NTT  %s c S%0d a S%0d fuse %0d",
                          $time, pc, ins[4] ? "INTT" : "NTT ", ins[11:8], ins[15:12], ins[21:20]);
      if (iss_p) $display("%0t %3d PWM  op %0d c S%0d a S%0d b S%0d acc %0d",
                          $time, pc, ins[6:4], ins[11:8], ins[15:12], ins[19:16], ins[7]);
      if (iss_i) $display("%0t %3d IO   op %0d slot S%0d d %0d sel %0d acc %0d addr %h E%0d",
                          $time, pc, ins[6:4], ins[10:7], ins[14:11], ins[18:17], ins[51],
                          ins[29:19], ins[43:41]);
      if (cls == C_BR && !i_busy) $display("%0t %3d BR   bad %0d", $time, pc, bad);
      if (fin) begin
        $display("%0t %3d END  status %0d (bad %0d diff %0d)", $time, pc, ins[7:4], bad, diff);
        $display("       busy clocks of %0d: Keccak %0d, NTT %0d, PWM %0d, IO %0d",
                 t_all, t_h, t_n, t_p, t_i);
      end
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

  mlkem3_hash #(.KR(KR)) u_hash (
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

  // --- NTT engine ------------------------------------------------------------------------
  wire [3:0]  n_slot, n_re, n_we, na_slot, na_re;
  wire [19:0] n_raddr, n_waddr, na_raddr;
  wire [95:0] n_rdata, n_wdata, na_rdata;

  mlkem3_ntt u_ntt (
    .clk     (clk),
    .rst     (rst),
    .start   (n_go),
    .op_in   (n_ins[4]),
    .fuse_in (n_ins[21:20]),
    .c_in    (n_ins[11:8]),
    .a_in    (n_ins[15:12]),
    .busy    (n_busy),
    .n_slot  (n_slot),
    .n_re    (n_re),
    .n_raddr (n_raddr),
    .n_rdata (n_rdata),
    .n_we    (n_we),
    .n_waddr (n_waddr),
    .n_wdata (n_wdata),
    .na_slot (na_slot),
    .na_re   (na_re),
    .na_raddr(na_raddr),
    .na_rdata(na_rdata)
  );

  // --- pointwise engine ------------------------------------------------------------------
  wire [3:0]  p_slot, p_re, p_we, pa_slot, pa_re, pb_slot, pb_re;
  wire [19:0] p_raddr, p_waddr, pa_raddr, pb_raddr;
  wire [95:0] p_rdata, p_wdata, pa_rdata, pb_rdata;

  mlkem3_pwm u_pwm (
    .clk     (clk),
    .rst     (rst),
    .start   (p_go),
    .op_in   (p_ins[6:4]),
    .acc_in  (p_ins[7]),
    .c_in    (p_ins[11:8]),
    .a_in    (p_ins[15:12]),
    .b_in    (p_ins[19:16]),
    .busy    (p_busy),
    .p_slot  (p_slot),
    .p_re    (p_re),
    .p_raddr (p_raddr),
    .p_rdata (p_rdata),
    .p_we    (p_we),
    .p_waddr (p_waddr),
    .p_wdata (p_wdata),
    .pa_slot (pa_slot),
    .pa_re   (pa_re),
    .pa_raddr(pa_raddr),
    .pa_rdata(pa_rdata),
    .pb_slot (pb_slot),
    .pb_re   (pb_re),
    .pb_raddr(pb_raddr),
    .pb_rdata(pb_rdata)
  );

  // --- IO engine -------------------------------------------------------------------------
  wire [2:0]  io_sr_ent, io_sr_word, io_sr2_ent, io_sw_ent, io_sw_word;
  wire [31:0] io_sr_data, io_sr2_data, io_sw_data;
  wire        io_sw_we;
  wire [3:0]  i_slot, i_re, i_we;
  wire [19:0] i_raddr, i_waddr;
  wire [95:0] i_rdata, i_wdata;

  mlkem3_io u_io (
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
  mlkem3_polymem #(.NS(12), .RAMSTYLE(RAMSTYLE)) u_pmem (
    .clk     (clk),
    .n_slot  (n_slot),  .n_re (n_re),  .n_raddr (n_raddr),  .n_rdata (n_rdata),
    .n_we    (n_we),    .n_waddr(n_waddr), .n_wdata(n_wdata),
    .na_slot (na_slot), .na_re(na_re), .na_raddr(na_raddr), .na_rdata(na_rdata),
    .p_slot  (p_slot),  .p_re (p_re),  .p_raddr (p_raddr),  .p_rdata (p_rdata),
    .p_we    (p_we),    .p_waddr(p_waddr), .p_wdata(p_wdata),
    .pa_slot (pa_slot), .pa_re(pa_re), .pa_raddr(pa_raddr), .pa_rdata(pa_rdata),
    .pb_slot (pb_slot), .pb_re(pb_re), .pb_raddr(pb_raddr), .pb_rdata(pb_rdata),
    .s_slot  (s_slot),  .s_we (s_we),  .s_waddr (s_waddr),  .s_wdata (s_wdata),
    .i_slot  (i_slot),  .i_re (i_re),  .i_raddr (i_raddr),  .i_rdata (i_rdata),
    .i_we    (i_we),    .i_waddr(i_waddr), .i_wdata(i_wdata)
  );

  mlkem3_seedregs u_seed (
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
endmodule
