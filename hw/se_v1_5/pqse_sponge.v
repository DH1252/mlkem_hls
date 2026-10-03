// -----------------------------------------------------------------------------
// pqse_sponge.v - sponge controller around the masked Keccak core.
//
// One HASH instruction = one job: clear, absorb part 1 and part 2 (whole
// lanes), suffix bytes + padding, then squeeze into one sink. The permutation
// runs only when a block is full or more output is needed.
// The Keccak state lives in RAM (pqse_keccak.v): absorbing a lane is a
// read-modify-write inside the core, and a squeezed lane arrives one clock
// after it is read (H_SRD -> H_SKX, H_STRM -> H_STRV).
//
// Sources (per part): SEED (seed registers, lanes entry*4 + i, both shares),
//                     BUF (I/O buffer lanes, public), TRNG (raw 64-bit words).
// KMAC256 jobs (SP 800-185, secure messaging): the sponge itself absorbs
//   bytepad(encode_string("KMAC") || encode_string(S), 136), then
//   bytepad(encode_string(K), 136) with the key from the seed registers
//   (part 1) shifted 5 bytes, both shares on their own, then the message X
//   (part 2) and right_encode(L), padded with 0x04 (cSHAKE).
// Sinks: SEED / SXOR  write / XOR lanes into seed entries oe0 (lanes 0-3),
//                     oe1 (lanes 4-7)
//        SNTT, CBD    the unmasked samplers (pqse_sample.v)
//        MB2A, MCMP   the masked unit (both shares of every lane)
//
// Masked job (msk = 1): seed lanes enter as two shares, everything public
// enters share 0, and the squeezed lanes leave as two shares.
// Unmasked job (msk = 0: H(ek), the XOF of the matrix A): public buffer input
// only, share 1 stays zero. A seed source always needs a masked job, so no
// gate here ever combines the two shares of a seed lane; the only place the
// sponge combines shares is the keystream sink (kx0 / kx1 below), whose
// output is public.
//
// Instruction fields: see pqse_defs.vh and pqse_ucode.v (u_hash).
// -----------------------------------------------------------------------------
module pqse_sponge #(
  parameter MASKED = 1
) (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [95:0] ins,
  output wire        busy,
  // seed registers
  output reg         sr_re,
  output reg  [5:0]  sr_addr,
  input  wire [63:0] sr_d0,
  input  wire [63:0] sr_d1,
  output reg         sw_we,
  output reg  [5:0]  sw_addr,
  output reg  [63:0] sw_d0,
  output reg  [63:0] sw_d1,
  // I/O buffer (read; write for the keystream sink SNK_BXOR)
  output reg         br_re,
  output reg  [8:0]  br_addr,
  input  wire [63:0] br_d,
  output reg         bw_we,
  output reg  [8:0]  bw_addr,
  output reg  [63:0] bw_d,
  // TRNG
  output wire        trng_en,
  input  wire        trng_valid,
  input  wire [63:0] trng_word,
  output wire        trng_take,
  // lane stream to a sampler / the masked unit
  output wire        so_valid,
  output wire [63:0] so_v0,
  output wire [63:0] so_v1,
  input  wire        so_ready,
  input  wire        samp_done,   // SampleNTT has 256 coefficients
  input  wire        sink_done,   // the stream sink has finished writing
  // randomness for the masked chi
  input  wire [63:0] rnd,
  output wire        rnd_take,
  output wire        perr          // Keccak state parity error (a fault)
);
  `include "pqse_defs.vh"

  // ---- latched job ----------------------------------------------------------------
  reg [95:0] J;
  wire [1:0] j_rate  = J[91:90];
  wire       j_shake = J[89];
  wire       j_msk   = J[88] & (MASKED != 0);
  wire [1:0] j_p1src = J[87:86];
  wire [8:0] j_p1a   = J[84:76];
  wire [7:0] j_p1n   = J[75:68];
  wire [1:0] j_p2src = J[67:66];
  wire [8:0] j_p2a   = J[65:57];
  wire [7:0] j_p2n   = J[56:49];
  wire [1:0] j_sfn   = J[48:47];
  wire [15:0] j_sfx  = J[46:31];
  wire [2:0] j_sink  = J[30:28];
  wire [3:0] j_oe0   = J[27:24];
  wire [3:0] j_oe1   = J[23:20];
  wire [7:0] j_onl   = J[19:12];
  // KMAC256 job (SP 800-185): J[2] = 1. Part 1 is the 32-byte key (seed entry),
  // part 2 the message X (buffer); J[1:0] picks the customization string S,
  // J[85] = 1: KMACXOF256 (right_encode(0)), 0: 256-bit output (right_encode(256))
  wire       j_kmac  = J[2];
  wire [1:0] j_kcs   = J[1:0];
  wire       j_kxof  = J[85];

  localparam [4:0] H_IDLE = 5'd0, H_CLR = 5'd1, H_ARD = 5'd2, H_AWR = 5'd3,
                   H_FIN1 = 5'd4, H_FIN2 = 5'd5, H_PGO = 5'd6, H_PW = 5'd7,
                   H_SQ0  = 5'd8, H_SRD = 5'd9, H_SWR = 5'd10, H_STRM = 5'd11,
                   H_WAIT = 5'd12,
                   H_KA   = 5'd13,   // KMAC: bytepad(encode_string("KMAC") || encode_string(S), 136)
                   H_KR   = 5'd14,   // KMAC: bytepad(encode_string(K), 136): read a key lane
                   H_KW   = 5'd15,   //       ... absorb it, shifted by the 5-byte prefix
                   H_SKX  = 5'd16,   // squeeze: the state lane read in H_SRD arrives (RAM latency)
                   H_STRV = 5'd17;   // stream: the lane read in H_STRM is on so_v0 / so_v1

  // KMAC constant lanes (little-endian byte order of the absorbed string)
  //   block A, lane 0: 01 88 | 01 20 "KMAC"        lane 1: 01 10 S0 S1
  //   block B prefix : 01 88 | 02 01 00, then K (32 bytes) from byte 5 on
  // S = "E1" / "E2" (keystream, initiator / responder sends), "T1" / "T2" (tag)
  // bytes 01 88 01 20 4B 4D 41 43 ("K" "M" "A" "C" = 4B 4D 41 43), byte 0 lowest
  localparam [63:0] KM_A0  = 64'h43414D4B20018801;
  localparam [63:0] KM_PRE = 64'h0000000001028801;
  wire [63:0] km_a1 = (j_kcs == 2'd0) ? 64'h0000000031451001 :      // "E1"
                      (j_kcs == 2'd1) ? 64'h0000000032451001 :      // "E2"
                      (j_kcs == 2'd2) ? 64'h0000000031541001 :      // "T1"
                                        64'h0000000032541001;       // "T2"
  reg  [2:0]  kc;                       // key lane 0..4
  reg  [63:0] kp0, kp1;                 // previous key lane, per share

  reg  [4:0] hs, hret;
  reg  [4:0] hs_n, hret_n;              // complemented shadows (fault protection)
  reg        hbad;                      // state mismatch (registered)
  wire       k_perr;
  reg        idl;                       // the idle registers are cleared
  reg  [4:0] pos;
  reg        part;
  reg  [7:0] lcnt;
  reg  [7:0] ocnt;

  wire [4:0] rl = (j_rate == RATE_168) ? 5'd21 : (j_rate == RATE_136) ? 5'd17 : 5'd9;
  // seed entry of output lane ocnt: lanes 0-3 -> oe0, 4-7 -> oe1, 8-23 -> oe0 + 2 ..
  // oe0 + 5 (a 16- or 24-lane PRF output into the consecutive E_CBD entries:
  // oe0 = E_CBD, oe1 = E_CBD + 1; 24 lanes for eta = 3, ML-KEM-512)
  wire [3:0] oent = (ocnt[4:2] == 3'd0) ? j_oe0 :
                    (ocnt[4:2] == 3'd1) ? j_oe1 : (j_oe0 + {1'b0, ocnt[4:2]});
  wire [1:0] csrc = part ? j_p2src : j_p1src;
  wire [8:0] cadr = part ? j_p2a   : j_p1a;
  wire [7:0] cn   = part ? j_p2n   : j_p1n;

  assign busy = start | (hs != H_IDLE);

  // ---- Keccak core (state in RAM: a lane read arrives one clock later) ------------------
  reg         k_clr, k_ax, k_go, k_rd;
  reg  [4:0]  k_idx;
  reg  [63:0] k_v0, k_v1;
  wire [63:0] k_r0, k_r1;
  wire        k_busy;

  pqse_keccak #(.MASKED(MASKED)) u_keccak (
    .clk(clk), .rst(rst), .msk(j_msk),
    .clr(k_clr), .ax_en(k_ax), .ax_idx(k_idx), .ax_v0(k_v0), .ax_v1(k_v1),
    .rd_en(k_rd), .rd_idx(pos), .rd_v0(k_r0), .rd_v1(k_r1),
    .go(k_go), .busy(k_busy), .rnd(rnd), .rnd_take(rnd_take), .perr(k_perr)
  );

  assign perr = k_perr | hbad;          // Keccak state / control, sponge state: a fault

  // ---- padding ------------------------------------------------------------------------
  // SHA3 0x06, SHAKE 0x1F, cSHAKE / KMAC 0x04; KMAC appends right_encode(L) itself
  wire [7:0]  pad      = j_kmac ? 8'h04 : j_shake ? 8'h1F : 8'h06;
  wire [1:0]  e_sfn    = j_kmac ? (j_kxof ? 2'd2 : 2'd3) : j_sfn;
  wire [23:0] e_sfx    = j_kmac ? (j_kxof ? 24'h000100 : 24'h020001) : {8'd0, j_sfx};
  wire [63:0] sfx_l    = (e_sfn == 2'd3) ? {40'd0, e_sfx} :
                         (e_sfn == 2'd2) ? {48'd0, e_sfx[15:0]} :
                         (e_sfn == 2'd1) ? {56'd0, e_sfx[7:0]} : 64'd0;
  wire [63:0] fin_lane = sfx_l | ({56'd0, pad} << {e_sfn, 3'b000});
  wire [63:0] msb      = 64'h8000000000000000;
  // KMAC key lane from the seed registers, per share. The two seed shares never
  // meet in a gate here: a seed source is always read by a masked job (the
  // unmasked jobs, H(ek) and the XOF of A, read only the public buffer); in
  // the unprotected build (MASKED = 0) share 1 is zero.
  wire [63:0] kd0 = sr_d0;
  wire [63:0] kd1 = j_msk ? sr_d1 : 64'd0;

  // ---- absorb data ----------------------------------------------------------------------
  wire [63:0] in0 = (csrc == SRC_SEED) ? sr_d0 :
                    (csrc == SRC_BUF)  ? br_d : trng_word;
  wire [63:0] in1 = ((csrc == SRC_SEED) && j_msk) ? sr_d1 : 64'd0;
  wire        in_ok = (csrc != SRC_TRNG) || trng_valid;

  // keystream sink (SNK_BXOR): the squeezed lane's shares are copied into
  // kx0 / kx1, registers only this sink loads, and combined there (the
  // keystream becomes public with the message it encrypts; no gate combines
  // the shares of any other state lane)
  reg  [63:0] kx0, kx1;

  assign trng_en   = (hs != H_IDLE) && ((j_p1src == SRC_TRNG) || (j_p2src == SRC_TRNG));
  assign trng_take = (hs == H_AWR) && (csrc == SRC_TRNG) && trng_valid;

  // ---- squeeze stream ---------------------------------------------------------------------
  wire strm_end = (j_sink == SNK_SNTT) ? samp_done : (ocnt == j_onl);
  // H_STRM reads lane pos, H_STRV presents it until the sink takes it
  assign so_valid = (hs == H_STRV) && !strm_end;
  assign so_v0    = so_valid ? k_r0 : 64'd0;
  assign so_v1    = (so_valid && j_msk) ? k_r1 : 64'd0;

  // ---- control --------------------------------------------------------------------------------
  always @* begin
    k_clr = 1'b0; k_ax = 1'b0; k_go = 1'b0; k_rd = 1'b0;
    k_idx = pos;  k_v0 = 64'd0; k_v1 = 64'd0;
    sr_re = 1'b0; sr_addr = 6'd0;
    br_re = 1'b0; br_addr = 9'd0;
    sw_we = 1'b0; sw_addr = 6'd0; sw_d0 = 64'd0; sw_d1 = 64'd0;
    bw_we = 1'b0; bw_addr = 9'd0; bw_d = 64'd0;
    case (hs)
      // the state is wiped after every job (pqse_keccak.v writes its RAMs to 0
      // once, while idle) and the next job waits in H_CLR until that is done,
      // so no hash state (keys, seeds) stays behind between jobs
      H_IDLE, H_CLR: k_clr = 1'b1;
      // KMAC block A: two constant lanes (the other 15 are zero), share 0
      H_KA: begin
        k_ax = 1'b1;
        k_v0 = (pos == 5'd0) ? KM_A0 : km_a1;
      end
      // KMAC block B: key lanes 0..3 read, lanes 0..4 absorbed shifted by 5 bytes
      H_KR: begin
        if (kc < 3'd4) begin
          sr_re = 1'b1; sr_addr = j_p1a[5:0] + {3'd0, kc};
        end else begin                                  // lane 4: the key's last 5 bytes
          k_ax = 1'b1; k_idx = 5'd4;
          k_v0 = kp0 >> 24;
          k_v1 = kp1 >> 24;
        end
      end
      H_KW: begin
        k_ax  = 1'b1; k_idx = {2'b00, kc};
        k_v0  = (kd0 << 40) | ((kc == 3'd0) ? KM_PRE : (kp0 >> 24));
        k_v1  = (kd1 << 40) | ((kc == 3'd0) ? 64'd0  : (kp1 >> 24));
      end
      H_ARD: if (pos != rl) begin
        if (csrc == SRC_SEED) begin sr_re = 1'b1; sr_addr = cadr[5:0] + lcnt[5:0]; end
        if (csrc == SRC_BUF)  begin br_re = 1'b1; br_addr = cadr + {1'b0, lcnt}; end
      end
      H_AWR: if (in_ok) begin
        k_ax = 1'b1; k_v0 = in0; k_v1 = in1;
      end
      H_FIN1: if (pos != rl) begin
        k_ax = 1'b1;
        k_v0 = fin_lane ^ ((pos == rl - 5'd1) ? msb : 64'd0);
      end
      H_FIN2: if (pos != rl - 5'd1) begin
        k_ax = 1'b1; k_idx = rl - 5'd1; k_v0 = msb;
      end
      H_PGO: k_go = 1'b1;
      H_STRM: if (!strm_end && pos != rl) k_rd = 1'b1;   // lane pos -> so_v0 / so_v1 in H_STRV
      H_SRD: if (ocnt != j_onl && pos != rl) begin
        k_rd = 1'b1;                                    // lane pos: k_r0 / k_r1 from H_SKX on
        if (j_sink == SNK_BXOR) begin
          br_re   = 1'b1;
          br_addr = B_SM_MSG + {1'b0, ocnt};
        end else begin
          sr_re   = 1'b1;
          sr_addr = {oent, ocnt[1:0]};
        end
      end
      H_SWR: if (j_sink == SNK_BXOR) begin
        // keystream XOR into the message lanes: the shares are combined here,
        // from kx0 / kx1; the result (ciphertext or plaintext) is the public output
        bw_we   = 1'b1;
        bw_addr = B_SM_MSG + {1'b0, ocnt};
        bw_d    = br_d ^ kx0 ^ kx1;
      end else begin
        sw_we   = 1'b1;
        sw_addr = {oent, ocnt[1:0]};
        if (j_sink == SNK_SXOR) begin
          sw_d0 = sr_d0 ^ k_r0;
          sw_d1 = sr_d1 ^ (j_msk ? k_r1 : 64'd0);
        end else begin
          sw_d0 = k_r0;
          sw_d1 = j_msk ? k_r1 : 64'd0;
        end
      end
      default: ;
    endcase
  end

  always @(posedge clk) begin
    if (rst) begin
      begin hs  <= H_IDLE; hs_n <= ~(H_IDLE); end
      begin hret <= H_IDLE; hret_n <= ~(H_IDLE); end
      hbad <= 1'b0;
      idl <= 1'b0;
    end else begin
      hbad <= (hs != ~hs_n) | (hret != ~hret_n);
      case (hs)
        H_IDLE: if (!start) begin
          // no key / keystream left (cleared once on entering idle, then held:
          // low power, a gateable clock)
          if (!idl) begin
            kp0 <= 64'd0; kp1 <= 64'd0; kx0 <= 64'd0; kx1 <= 64'd0;
            idl <= 1'b1;
          end
        end else begin
          idl  <= 1'b0;
          J    <= ins;
          pos  <= 5'd0;
          part <= 1'b0;
          lcnt <= 8'd0;
          ocnt <= 8'd0;
          begin hs   <= H_CLR; hs_n <= ~(H_CLR); end
        end
        H_CLR: if (!k_busy) begin       // the state RAMs are wiped (pqse_keccak.v)
          if (j_kmac)                   begin hs <= H_KA; hs_n <= ~(H_KA); end
          else if (j_p1src != SRC_NONE) begin hs <= H_ARD; hs_n <= ~(H_ARD); end
          else if (j_p2src != SRC_NONE) begin part <= 1'b1; begin hs <= H_ARD; hs_n <= ~(H_ARD); end end
          else                          begin hs <= H_FIN1; hs_n <= ~(H_FIN1); end
        end
        H_KA: begin
          if (pos == 5'd1) begin
            kc   <= 3'd0;
            begin hret <= H_KR; hret_n <= ~(H_KR); end
            begin hs   <= H_PGO; hs_n <= ~(H_PGO); end                // permute block A
          end else begin
            pos <= pos + 5'd1;
          end
        end
        H_KR: begin
          if (kc < 3'd4) begin
            begin hs <= H_KW; hs_n <= ~(H_KW); end
          end else begin                  // block B complete: permute, then X (part 2)
            part <= 1'b1;
            lcnt <= 8'd0;
            begin hret <= H_ARD; hret_n <= ~(H_ARD); end
            begin hs   <= H_PGO; hs_n <= ~(H_PGO); end
          end
        end
        H_KW: begin
          kp0 <= kd0;
          kp1 <= kd1;
          kc  <= kc + 3'd1;
          begin hs  <= H_KR; hs_n <= ~(H_KR); end
        end
        H_ARD: begin
          if (pos == rl) begin
            begin hret <= H_ARD; hret_n <= ~(H_ARD); end
            begin hs   <= H_PGO; hs_n <= ~(H_PGO); end
          end else begin
            begin hs <= H_AWR; hs_n <= ~(H_AWR); end
          end
        end
        H_AWR: if (in_ok) begin
          pos <= pos + 5'd1;
          if (lcnt == cn - 8'd1) begin
            lcnt <= 8'd0;
            if (!part && (j_p2src != SRC_NONE)) begin
              part <= 1'b1;
              begin hs   <= H_ARD; hs_n <= ~(H_ARD); end
            end else begin
              begin hs <= H_FIN1; hs_n <= ~(H_FIN1); end
            end
          end else begin
            lcnt <= lcnt + 8'd1;
            begin hs   <= H_ARD; hs_n <= ~(H_ARD); end
          end
        end
        H_FIN1: begin
          if (pos == rl) begin
            begin hret <= H_FIN1; hret_n <= ~(H_FIN1); end
            begin hs   <= H_PGO; hs_n <= ~(H_PGO); end
          end else begin
            begin hs <= H_FIN2; hs_n <= ~(H_FIN2); end
          end
        end
        H_FIN2: begin
          pos  <= rl;          // the block is complete: permute, then squeeze
          begin hret <= H_SQ0; hret_n <= ~(H_SQ0); end
          begin hs   <= H_PGO; hs_n <= ~(H_PGO); end
        end
        H_PGO: begin hs <= H_PW; hs_n <= ~(H_PW); end
        H_PW:  if (!k_busy) begin
          pos <= 5'd0;
          begin hs  <= hret; hs_n <= ~(hret); end
        end
        H_SQ0: begin hs <= ((j_sink == SNK_SEED) || (j_sink == SNK_SXOR) || (j_sink == SNK_BXOR)) ?
                     H_SRD : H_STRM; hs_n <= ~(((j_sink == SNK_SEED) || (j_sink == SNK_SXOR) || (j_sink == SNK_BXOR)) ?
                     H_SRD : H_STRM); end
        H_SRD: begin
          if (ocnt == j_onl) begin
            begin hs <= H_IDLE; hs_n <= ~(H_IDLE); end
          end else if (pos == rl) begin
            begin hret <= H_SRD; hret_n <= ~(H_SRD); end
            begin hs   <= H_PGO; hs_n <= ~(H_PGO); end
          end else begin
            begin hs <= H_SKX; hs_n <= ~(H_SKX); end                             // state lane read issued
          end
        end
        H_SKX: begin                                 // the lane is on k_r0 / k_r1
          if (j_sink == SNK_BXOR) begin              // keystream lane, per share
            kx0 <= k_r0;
            kx1 <= j_msk ? k_r1 : 64'd0;
          end
          begin hs <= H_SWR; hs_n <= ~(H_SWR); end
        end
        H_SWR: begin
          pos  <= pos + 5'd1;
          ocnt <= ocnt + 8'd1;
          begin hs   <= H_SRD; hs_n <= ~(H_SRD); end
        end
        H_STRM: begin                                // read lane pos
          if (strm_end) begin
            begin hs <= H_WAIT; hs_n <= ~(H_WAIT); end
          end else if (pos == rl) begin
            begin hret <= H_STRM; hret_n <= ~(H_STRM); end
            begin hs   <= H_PGO; hs_n <= ~(H_PGO); end
          end else begin
            begin hs <= H_STRV; hs_n <= ~(H_STRV); end
          end
        end
        H_STRV: begin                                // lane pos offered until taken
          if (strm_end) begin
            begin hs <= H_WAIT; hs_n <= ~(H_WAIT); end
          end else if (so_ready) begin
            pos  <= pos + 5'd1;
            ocnt <= ocnt + 8'd1;
            begin hs   <= H_STRM; hs_n <= ~(H_STRM); end
          end
        end
        H_WAIT: if (sink_done) begin hs <= H_IDLE; hs_n <= ~(H_IDLE); end
        default: begin hs <= H_IDLE; hs_n <= ~(H_IDLE); end
      endcase
    end
  end
endmodule
