// -----------------------------------------------------------------------------
// mlkem_rtl_core.v - the hand-written ML-KEM-768 core: a small microcoded
// sequencer that drives three engines working in parallel.
//
//               start, op --> +------------------------------+ --> done, result
//                             | sequencer, microcode ROM      |
//                             | (KeyGen, Encaps, Decaps)      |
//                             +---+-----------+-----------+---+
//                           HASH  |      ALU  |       IO  |
//                                 v           v           v
//   mailbox port B  <----- +-----------+ +----------+ +------------+ <---> mailbox port A
//   (Keccak reads)         | Keccak    | | NTT INTT | | ByteDecode | ----> mailbox port B
//                          | sponge +  | | PWM ADD  | | ByteEncode |       (2nd copies)
//                          | CBD /     | | SUB      | | compress,  |
//                          | SampleNTT | |          | | copy, cmp  |
//                          +--+-----+--+ +----+-----+ +--+------+--+
//                             |     |         |          |      |
//                             |  +--+---------+----------+--+   |
//                             |  | polynomial memory S0-S11 |   |
//                             |  +--------------------------+   |
//                             +---- seed registers E0-E5 -------+
//
// The sequencer issues one instruction per clock, in order. An engine
// instruction waits until that engine is idle; WAIT waits for the named
// engines; END waits for all of them. So the engines overlap exactly as far
// as the program lets them (e.g. SampleNTT of the next matrix entry runs while
// the ALU multiplies the current one). The microcode, not the hardware, keeps
// the engines apart:
//   - a polynomial slot is used by one engine at a time (the memory gives
//     each slot to one reader: ALU C > ALU A > ALU B > IO);
//   - mailbox port B belongs to the Keccak engine while it streams mailbox
//     words in; the IO engine writes through it (ENC/S2M second copies, M2M)
//     only when no Keccak mailbox read is running;
//   - BR (branch if BAD) comes after a WAIT for the IO step that sets BAD.
//
// Instruction word (80 bits; unused bits are 0):
//   all   [3:0]  class: 0 END, 1 WAIT, 2 BR, 3 HASH, 4 ALU, 5 IO
//   END   [7:4]  status for the RESULT register
//   WAIT  [4] Keccak engine  [5] ALU  [6] IO engine
//   BR    [16:8] target, taken when BAD is set
//   HASH  [5:4] rate (0: 168 B SHAKE128, 1: 136 B SHA3-256/SHAKE256, 2: 72 B SHA3-512)
//         [6] SHAKE padding (else SHA-3)
//         [7] part 1 from a seed register  [17:8] its lane address / entry  [25:18] lanes
//         [26] part 2 from a seed register [36:27] its lane address / entry [44:37] lanes (0: none)
//         [46:45] suffix bytes  [62:47] suffix (first byte in [54:47])
//         [64:63] output: 0 seed registers, 1 SamplePolyCBD_2, 2 SampleNTT
//         [67:65] entry for output lanes 0-3  [70:68] for lanes 4-7  [74:71] output lanes
//         [78:75] output slot
//   ALU   [6:4] 0 NTT, 1 INTT, 2 PWM, 3 ADD, 4 SUB   [7] PWM accumulates
//         [11:8] C (result) slot  [15:12] A slot  [19:16] B slot
//   IO    [6:4] 0 DEC, 1 ENC, 2 S2M, 3 M2M, 4 M2S, 5 CMP, 6 SEL, 7 ZERO
//         [10:7] slot  [14:11] d  [15] fa  [16] fb  [18:17] sel
//         [29:19] mailbox word address  [40:30] second address
//         [43:41] seed entry  [46:44] second entry  [50:47] words (word ops)
//   (meaning of fa/fb/sel per operation: see mlkem_rtl_io.v)
//
// Mailbox layout: src/mlkem_accel.h (byte offsets; here as 32-bit word and
// 64-bit lane addresses). ML-KEM-768 only (k = 3, eta1 = eta2 = 2, du = 10,
// dv = 4).
//
// Define MLKEM_TRACE in simulation to print every issued instruction.
//
// UNTESTED FIRST VERSION - see hw/manual/README.md.
// -----------------------------------------------------------------------------
module mlkem_rtl_core (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,      // one-clock pulse, core idle
  input  wire [31:0] op,         // 1 KeyGen, 2 Encaps, 3 Decaps
  output reg         done,       // one-clock pulse
  output reg  [31:0] result,     // valid with done: 0 OK, 1 bad key, 2 bad op
  // mailbox port A (32-bit words, read latency 1): the IO engine
  output wire [10:0] ma_addr,
  output wire        ma_we,
  output wire [31:0] ma_wdata,
  input  wire [31:0] ma_rdata,
  // mailbox port B: Keccak reads while its read stream runs, else IO writes
  output wire [10:0] mb_addr,
  output wire        mb_we,
  output wire [31:0] mb_wdata,
  input  wire [31:0] mb_rdata
);

  // ===========================================================================
  // constants
  // ===========================================================================
  localparam [3:0] C_END  = 4'd0, C_WAIT = 4'd1, C_BR = 4'd2,
                   C_HASH = 4'd3, C_ALU  = 4'd4, C_IO = 4'd5;
  localparam [2:0] WH = 3'b001, WA = 3'b010, WI = 3'b100;         // WAIT masks
  localparam [2:0] A_NTT = 3'd0, A_INTT = 3'd1, A_PWM = 3'd2,
                   A_ADD = 3'd3, A_SUB  = 3'd4;
  localparam [2:0] I_DEC = 3'd0, I_ENC = 3'd1, I_S2M = 3'd2, I_M2M  = 3'd3,
                   I_M2S = 3'd4, I_CMP = 3'd5, I_SEL = 3'd6, I_ZERO = 3'd7;
  localparam [1:0] K_MB = 2'd0, K_MBDUAL = 2'd1, K_CMP = 2'd2, K_SEED = 2'd3;
  localparam [1:0] OM_SEED = 2'd0, OM_CBD = 2'd1, OM_SAMP = 2'd2;

  // seed registers (32 bytes each)
  localparam [2:0] E0 = 3'd0,    // K (Encaps), K' (Decaps)
                   E1 = 3'd1,    // sigma (KeyGen), r (Encaps), r' (Decaps)
                   E2 = 3'd2,    // H(ek)
                   E3 = 3'd3,    // m' (Decaps)
                   E4 = 3'd4,    // K-bar = J(z || c) (Decaps)
                   E5 = 3'd5;    // rho
  // polynomial slots
  localparam [3:0] S0 = 4'd0, S1 = 4'd1, S2  = 4'd2,  S3  = 4'd3,
                   S4 = 4'd4, S5 = 4'd5, S6  = 4'd6,  S7  = 4'd7,
                   S8 = 4'd8, S9 = 4'd9, S10 = 4'd10, S11 = 4'd11;

  // mailbox word addresses (= byte offset / 4)
  localparam [10:0] W_D        = 11'h000,  // d                    byte 0x0000
                    W_Z        = 11'h008,  // z                    byte 0x0020
                    W_M        = 11'h010,  // m                    byte 0x0040
                    W_SS       = 11'h018,  // shared secret K      byte 0x0060
                    W_EK       = 11'h040,  // ek: t-hat[0]         byte 0x0100
                    W_EK_T1    = 11'h0A0,  //     t-hat[1]
                    W_EK_T2    = 11'h100,  //     t-hat[2]
                    W_EK_RHO   = 11'h160,  //     rho
                    W_DK       = 11'h200,  // dk: s-hat[0]         byte 0x0800
                    W_DK_S1    = 11'h260,  //     s-hat[1]
                    W_DK_S2    = 11'h2C0,  //     s-hat[2]
                    W_DKEK     = 11'h320,  //     ek: t-hat[0]
                    W_DKEK_T1  = 11'h380,  //         t-hat[1]
                    W_DKEK_T2  = 11'h3E0,  //         t-hat[2]
                    W_DKEK_RHO = 11'h440,  //         rho
                    W_DK_H     = 11'h448,  //     H(ek)
                    W_DK_Z     = 11'h450,  //     z
                    W_CT       = 11'h600,  // c:  u[0]             byte 0x1800
                    W_CT_U1    = 11'h650,  //     u[1]
                    W_CT_U2    = 11'h6A0,  //     u[2]
                    W_CT_V     = 11'h6F0;  //     v
  // the same places as 64-bit lane addresses (Keccak engine)
  localparam [9:0]  L_D    = 10'h000, L_M    = 10'h008, L_EK   = 10'h020,
                    L_DKEK = 10'h190, L_DK_H = 10'h224, L_DK_Z = 10'h228,
                    L_CT   = 10'h300;

  // program entry points (the programs start at multiples of 128)
  localparam [8:0] PC_KG = 9'd0;
  localparam [8:0] PC_EN = 9'd128;
  localparam [8:0] PC_DE = 9'd256;
  localparam [8:0] EN_FAIL = 9'd128 + 9'd77;   // Encaps: ek failed the modulus check
  localparam [8:0] DE_FAIL = 9'd256 + 9'd101;  // Decaps: dk failed the hash check

  // ===========================================================================
  // instruction builders
  // ===========================================================================
  function [79:0] U_END(input [3:0] status);
    begin
      U_END      = 80'd0;
      U_END[3:0] = C_END;
      U_END[7:4] = status;
    end
  endfunction

  function [79:0] U_WAIT(input [2:0] mask);          // mask: WH | WA | WI
    begin
      U_WAIT      = 80'd0;
      U_WAIT[3:0] = C_WAIT;
      U_WAIT[6:4] = mask;
    end
  endfunction

  function [79:0] U_BR(input [8:0] target);
    begin
      U_BR       = 80'd0;
      U_BR[3:0]  = C_BR;
      U_BR[16:8] = target;
    end
  endfunction

  function [79:0] U_HASH(input [1:0] rate, input shk,
                         input p1s, input [9:0] p1a, input [7:0] p1n,
                         input p2s, input [9:0] p2a, input [7:0] p2n,
                         input [1:0] sfn, input [15:0] sfx,
                         input [1:0] omode, input [2:0] oe0, input [2:0] oe1,
                         input [3:0] nout, input [3:0] oslot);
    begin
      U_HASH        = 80'd0;
      U_HASH[3:0]   = C_HASH;
      U_HASH[5:4]   = rate;
      U_HASH[6]     = shk;
      U_HASH[7]     = p1s;
      U_HASH[17:8]  = p1a;
      U_HASH[25:18] = p1n;
      U_HASH[26]    = p2s;
      U_HASH[36:27] = p2a;
      U_HASH[44:37] = p2n;
      U_HASH[46:45] = sfn;
      U_HASH[62:47] = sfx;
      U_HASH[64:63] = omode;
      U_HASH[67:65] = oe0;
      U_HASH[70:68] = oe1;
      U_HASH[74:71] = nout;
      U_HASH[78:75] = oslot;
    end
  endfunction

  // H: SHA3-256 of n mailbox lanes -> seed entry
  function [79:0] U_SHA3_256(input [9:0] lane, input [7:0] n, input [2:0] ent);
    U_SHA3_256 = U_HASH(2'd1, 1'b0, 1'b0, lane, n, 1'b0, 10'd0, 8'd0,
                        2'd0, 16'd0, OM_SEED, ent, 3'd0, 4'd4, 4'd0);
  endfunction

  // G: SHA3-512 of part 1 (4 lanes) || part 2 (p2n lanes) || suffix
  //    -> bytes 0-31 to e0, bytes 32-63 to e1
  function [79:0] U_SHA3_512(input p1s, input [9:0] p1a,
                             input p2s, input [9:0] p2a, input [7:0] p2n,
                             input [1:0] sfn, input [15:0] sfx,
                             input [2:0] e0, input [2:0] e1);
    U_SHA3_512 = U_HASH(2'd2, 1'b0, p1s, p1a, 8'd4, p2s, p2a, p2n,
                        sfn, sfx, OM_SEED, e0, e1, 4'd8, 4'd0);
  endfunction

  // J: SHAKE256 of z (4 mailbox lanes) || c (cn mailbox lanes), 32 bytes -> ent
  function [79:0] U_SHAKE_J(input [9:0] zl, input [9:0] cl, input [7:0] cn,
                            input [2:0] ent);
    U_SHAKE_J = U_HASH(2'd1, 1'b1, 1'b0, zl, 8'd4, 1'b0, cl, cn,
                       2'd0, 16'd0, OM_SEED, ent, 3'd0, 4'd4, 4'd0);
  endfunction

  // slot = SamplePolyCBD_2(PRF_2(seed ent, nonce)),  PRF = SHAKE256(s || N, 128 B)
  function [79:0] U_CBD(input [3:0] slot, input [2:0] ent, input [7:0] nonce);
    U_CBD = U_HASH(2'd1, 1'b1, 1'b1, {7'd0, ent}, 8'd4, 1'b0, 10'd0, 8'd0,
                   2'd1, {8'd0, nonce}, OM_CBD, 3'd0, 3'd0, 4'd0, slot);
  endfunction

  // slot = SampleNTT(seed ent || b32 || b33),  XOF = SHAKE128
  function [79:0] U_XOF(input [3:0] slot, input [2:0] ent, input [7:0] b32,
                        input [7:0] b33);
    U_XOF = U_HASH(2'd0, 1'b1, 1'b1, {7'd0, ent}, 8'd4, 1'b0, 10'd0, 8'd0,
                   2'd2, {b33, b32}, OM_SAMP, 3'd0, 3'd0, 4'd0, slot);
  endfunction

  function [79:0] U_ALU(input [2:0] aop, input [3:0] c, input [3:0] a,
                        input [3:0] b, input acc);
    begin
      U_ALU        = 80'd0;
      U_ALU[3:0]   = C_ALU;
      U_ALU[6:4]   = aop;
      U_ALU[7]     = acc;
      U_ALU[11:8]  = c;
      U_ALU[15:12] = a;
      U_ALU[19:16] = b;
    end
  endfunction

  function [79:0] U_NTT(input [3:0] c);
    U_NTT = U_ALU(A_NTT, c, 4'd0, 4'd0, 1'b0);
  endfunction

  function [79:0] U_INTT(input [3:0] c);
    U_INTT = U_ALU(A_INTT, c, 4'd0, 4'd0, 1'b0);
  endfunction

  // c = (acc ? c : 0) + a o b   (NTT domain)
  function [79:0] U_PWM(input [3:0] c, input [3:0] a, input [3:0] b, input acc);
    U_PWM = U_ALU(A_PWM, c, a, b, acc);
  endfunction

  function [79:0] U_ADD(input [3:0] c, input [3:0] a);      // c = c + a
    U_ADD = U_ALU(A_ADD, c, a, 4'd0, 1'b0);
  endfunction

  function [79:0] U_SUB(input [3:0] c, input [3:0] a);      // c = c - a
    U_SUB = U_ALU(A_SUB, c, a, 4'd0, 1'b0);
  endfunction

  function [79:0] U_IO(input [2:0] iop, input [3:0] slot, input [3:0] d,
                       input fa, input fb, input [1:0] sel,
                       input [10:0] addr, input [10:0] addr2,
                       input [2:0] ent, input [2:0] ent2, input [3:0] n);
    begin
      U_IO        = 80'd0;
      U_IO[3:0]   = C_IO;
      U_IO[6:4]   = iop;
      U_IO[10:7]  = slot;
      U_IO[14:11] = d;
      U_IO[15]    = fa;
      U_IO[16]    = fb;
      U_IO[18:17] = sel;
      U_IO[29:19] = addr;
      U_IO[40:30] = addr2;
      U_IO[43:41] = ent;
      U_IO[46:44] = ent2;
      U_IO[50:47] = n;
    end
  endfunction

  // slot = ByteDecode_d(mailbox at addr, or seed register ent if seedsrc)
  //   check : (d = 12) set BAD if a value is >= q (the ek modulus check)
  //   decomp: Decompress_d
  function [79:0] U_DEC(input [3:0] slot, input seedsrc, input [10:0] addr,
                        input [2:0] ent, input [3:0] d, input check,
                        input decomp);
    U_DEC = U_IO(I_DEC, slot, d, check, decomp, {1'b0, seedsrc}, addr, 11'd0,
                 ent, 3'd0, 4'd0);
  endfunction

  // ByteEncode_d(comp ? Compress_d(slot) : slot) -> sink:
  //   K_MB mailbox at addr, K_MBDUAL at addr and addr2, K_CMP compare with the
  //   mailbox at addr (sets DIFF on a mismatch), K_SEED seed register ent
  function [79:0] U_ENC(input [3:0] slot, input [1:0] sink, input [10:0] addr,
                        input [10:0] addr2, input [2:0] ent, input [3:0] d,
                        input comp);
    U_ENC = U_IO(I_ENC, slot, d, comp, 1'b0, sink, addr, addr2, ent, 3'd0, 4'd0);
  endfunction

  // n-word operations: S2M (seed ent -> addr, and addr2 if dual), M2M (addr ->
  // addr2), M2S (addr -> ent), CMP (ent vs addr -> BAD), SEL (DIFF ? ent2 :
  // ent -> addr), ZERO (0 -> addr)
  function [79:0] U_WOP(input [2:0] iop, input [10:0] addr, input [10:0] addr2,
                        input [2:0] ent, input [2:0] ent2, input [3:0] n,
                        input dual);
    U_WOP = U_IO(iop, 4'd0, 4'd0, dual, 1'b0, 2'd0, addr, addr2, ent, ent2, n);
  endfunction

  // ===========================================================================
  // microcode
  // ===========================================================================

  // --- KeyGen (FIPS 203 Alg. 16 / 13): (d, z) -> ek, dk ------------------------
  // S0-S2 s-hat, S5-S7 e-hat then t-hat, S3/S4 matrix entries (alternating)
  function [79:0] prog_kg(input [6:0] k);
    case (k)
      // (rho, sigma) = G(d || 3): rho -> E5, sigma -> E1
      7'd0:  prog_kg = U_SHA3_512(1'b0, L_D, 1'b0, 10'd0, 8'd0, 2'd1, 16'h0003, E5, E1);
      7'd1:  prog_kg = U_WAIT(WH);
      7'd2:  prog_kg = U_WOP(I_S2M, W_EK_RHO, W_DKEK_RHO, E5, E0, 4'd8, 1'b1); // rho -> ek, dk
      7'd3:  prog_kg = U_WOP(I_M2M, W_Z, W_DK_Z, E0, E0, 4'd8, 1'b0);          // z -> dk
      // s (S0-S2, N = 0..2) and e (S5-S7, N = 3..5): sample, NTT; s-hat -> dk
      7'd4:  prog_kg = U_CBD(S0, E1, 8'd0);
      7'd5:  prog_kg = U_WAIT(WH);
      7'd6:  prog_kg = U_CBD(S1, E1, 8'd1);
      7'd7:  prog_kg = U_NTT(S0);
      7'd8:  prog_kg = U_WAIT(WH);
      7'd9:  prog_kg = U_CBD(S2, E1, 8'd2);
      7'd10: prog_kg = U_NTT(S1);
      7'd11: prog_kg = U_ENC(S0, K_MB, W_DK, 11'd0, E0, 4'd12, 1'b0);
      7'd12: prog_kg = U_WAIT(WH);
      7'd13: prog_kg = U_CBD(S5, E1, 8'd3);
      7'd14: prog_kg = U_NTT(S2);
      7'd15: prog_kg = U_ENC(S1, K_MB, W_DK_S1, 11'd0, E0, 4'd12, 1'b0);
      7'd16: prog_kg = U_WAIT(WH);
      7'd17: prog_kg = U_CBD(S6, E1, 8'd4);
      7'd18: prog_kg = U_NTT(S5);
      7'd19: prog_kg = U_ENC(S2, K_MB, W_DK_S2, 11'd0, E0, 4'd12, 1'b0);
      7'd20: prog_kg = U_WAIT(WH);
      7'd21: prog_kg = U_CBD(S7, E1, 8'd5);
      7'd22: prog_kg = U_NTT(S6);
      7'd23: prog_kg = U_WAIT(WH);
      7'd24: prog_kg = U_NTT(S7);
      // t-hat[i] = e-hat[i] + sum_j A[i][j] o s-hat[j],  A[i][j] = SampleNTT(rho || j || i).
      // The next entry is sampled while the current one is multiplied. The IO
      // engine must be done reading S2 before the ALU reads it (WAIT at 26).
      7'd25: prog_kg = U_XOF(S3, E5, 8'd0, 8'd0);   // A[0][0]
      7'd26: prog_kg = U_WAIT(WH | WI);
      7'd27: prog_kg = U_XOF(S4, E5, 8'd1, 8'd0);   // A[0][1]
      7'd28: prog_kg = U_PWM(S5, S3, S0, 1'b1);
      7'd29: prog_kg = U_WAIT(WH | WA);
      7'd30: prog_kg = U_XOF(S3, E5, 8'd2, 8'd0);   // A[0][2]
      7'd31: prog_kg = U_PWM(S5, S4, S1, 1'b1);
      7'd32: prog_kg = U_WAIT(WH | WA);
      7'd33: prog_kg = U_XOF(S4, E5, 8'd0, 8'd1);   // A[1][0]
      7'd34: prog_kg = U_PWM(S5, S3, S2, 1'b1);
      7'd35: prog_kg = U_WAIT(WH | WA);
      7'd36: prog_kg = U_ENC(S5, K_MBDUAL, W_EK, W_DKEK, E0, 4'd12, 1'b0);        // t-hat[0]
      7'd37: prog_kg = U_XOF(S3, E5, 8'd1, 8'd1);   // A[1][1]
      7'd38: prog_kg = U_PWM(S6, S4, S0, 1'b1);
      7'd39: prog_kg = U_WAIT(WH | WA);
      7'd40: prog_kg = U_XOF(S4, E5, 8'd2, 8'd1);   // A[1][2]
      7'd41: prog_kg = U_PWM(S6, S3, S1, 1'b1);
      7'd42: prog_kg = U_WAIT(WH | WA);
      7'd43: prog_kg = U_XOF(S3, E5, 8'd0, 8'd2);   // A[2][0]
      7'd44: prog_kg = U_PWM(S6, S4, S2, 1'b1);
      7'd45: prog_kg = U_WAIT(WH | WA);
      7'd46: prog_kg = U_ENC(S6, K_MBDUAL, W_EK_T1, W_DKEK_T1, E0, 4'd12, 1'b0);  // t-hat[1]
      7'd47: prog_kg = U_XOF(S4, E5, 8'd1, 8'd2);   // A[2][1]
      7'd48: prog_kg = U_PWM(S7, S3, S0, 1'b1);
      7'd49: prog_kg = U_WAIT(WH | WA);
      7'd50: prog_kg = U_XOF(S3, E5, 8'd2, 8'd2);   // A[2][2]
      7'd51: prog_kg = U_PWM(S7, S4, S1, 1'b1);
      7'd52: prog_kg = U_WAIT(WH | WA);
      7'd53: prog_kg = U_PWM(S7, S3, S2, 1'b1);
      7'd54: prog_kg = U_WAIT(WA);
      7'd55: prog_kg = U_ENC(S7, K_MBDUAL, W_EK_T2, W_DKEK_T2, E0, 4'd12, 1'b0);  // t-hat[2]
      7'd56: prog_kg = U_WAIT(WI);
      // H(ek) -> dk
      7'd57: prog_kg = U_SHA3_256(L_EK, 8'd148, E2);
      7'd58: prog_kg = U_WAIT(WH);
      7'd59: prog_kg = U_WOP(I_S2M, W_DK_H, 11'd0, E2, E0, 4'd8, 1'b0);
      7'd60: prog_kg = U_END(4'd0);
      default: prog_kg = U_END(4'hF);
    endcase
  endfunction

  // --- K-PKE.Encrypt (FIPS 203 Alg. 14), shared by Encaps and Decaps ------------
  // Needs: r in E1, rho in E5, t-hat in S7-S9.
  //   dec = 0 (Encaps): mu from the mailbox (m), c written to the mailbox
  //   dec = 1 (Decaps): mu from E3 (m'), c' compared with the mailbox (DIFF)
  // Slots: S0-S2 y-hat, S3/S4 matrix entries (alternating), S5/S6/S10 u[0..2],
  // S11 e1[i] and e2, then S3 mu and S4 v.
  // u[i] = INTT(sum_j A[j][i] o y-hat[j]) + e1[i],  A[j][i] = SampleNTT(rho || i || j)
  function [79:0] reenc(input [6:0] k, input dec);
    reg [1:0] snk;
    begin
      snk = dec ? K_CMP : K_MB;
      case (k)
        // y (N = 0..2)
        7'd0:  reenc = U_CBD(S0, E1, 8'd0);
        7'd1:  reenc = U_WAIT(WH);
        7'd2:  reenc = U_CBD(S1, E1, 8'd1);
        7'd3:  reenc = U_NTT(S0);
        7'd4:  reenc = U_WAIT(WH);
        7'd5:  reenc = U_CBD(S2, E1, 8'd2);
        7'd6:  reenc = U_NTT(S1);
        7'd7:  reenc = U_WAIT(WH);
        7'd8:  reenc = U_NTT(S2);
        // u[0]
        7'd9:  reenc = U_XOF(S3, E5, 8'd0, 8'd0);   // A[0][0]
        7'd10: reenc = U_WAIT(WH);
        7'd11: reenc = U_XOF(S4, E5, 8'd0, 8'd1);   // A[1][0]
        7'd12: reenc = U_PWM(S5, S3, S0, 1'b0);
        7'd13: reenc = U_WAIT(WH | WA);
        7'd14: reenc = U_XOF(S3, E5, 8'd0, 8'd2);   // A[2][0]
        7'd15: reenc = U_PWM(S5, S4, S1, 1'b1);
        7'd16: reenc = U_WAIT(WH | WA);
        7'd17: reenc = U_XOF(S4, E5, 8'd1, 8'd0);   // A[0][1]
        7'd18: reenc = U_PWM(S5, S3, S2, 1'b1);
        7'd19: reenc = U_INTT(S5);
        7'd20: reenc = U_WAIT(WH);
        7'd21: reenc = U_CBD(S11, E1, 8'd3);        // e1[0]
        7'd22: reenc = U_WAIT(WH);
        7'd23: reenc = U_ADD(S5, S11);
        7'd24: reenc = U_WAIT(WA);
        7'd25: reenc = U_ENC(S5, snk, W_CT, 11'd0, E0, 4'd10, 1'b1);
        // u[1]
        7'd26: reenc = U_XOF(S3, E5, 8'd1, 8'd1);   // A[1][1]
        7'd27: reenc = U_PWM(S6, S4, S0, 1'b0);
        7'd28: reenc = U_WAIT(WH | WA);
        7'd29: reenc = U_XOF(S4, E5, 8'd1, 8'd2);   // A[2][1]
        7'd30: reenc = U_PWM(S6, S3, S1, 1'b1);
        7'd31: reenc = U_WAIT(WH | WA);
        7'd32: reenc = U_XOF(S3, E5, 8'd2, 8'd0);   // A[0][2]
        7'd33: reenc = U_PWM(S6, S4, S2, 1'b1);
        7'd34: reenc = U_INTT(S6);
        7'd35: reenc = U_WAIT(WH);
        7'd36: reenc = U_CBD(S11, E1, 8'd4);        // e1[1]
        7'd37: reenc = U_WAIT(WH);
        7'd38: reenc = U_ADD(S6, S11);
        7'd39: reenc = U_WAIT(WA);
        7'd40: reenc = U_ENC(S6, snk, W_CT_U1, 11'd0, E0, 4'd10, 1'b1);
        // u[2]
        7'd41: reenc = U_XOF(S4, E5, 8'd2, 8'd1);   // A[1][2]
        7'd42: reenc = U_PWM(S10, S3, S0, 1'b0);
        7'd43: reenc = U_WAIT(WH | WA);
        7'd44: reenc = U_XOF(S3, E5, 8'd2, 8'd2);   // A[2][2]
        7'd45: reenc = U_PWM(S10, S4, S1, 1'b1);
        7'd46: reenc = U_WAIT(WH | WA);
        7'd47: reenc = U_PWM(S10, S3, S2, 1'b1);
        7'd48: reenc = U_INTT(S10);
        7'd49: reenc = U_CBD(S11, E1, 8'd5);        // e1[2]
        7'd50: reenc = U_WAIT(WH);
        7'd51: reenc = U_ADD(S10, S11);
        7'd52: reenc = U_WAIT(WA);
        7'd53: reenc = U_ENC(S10, snk, W_CT_U2, 11'd0, E0, 4'd10, 1'b1);
        // v = INTT(t-hat^T o y-hat) + e2 + mu
        7'd54: reenc = U_CBD(S11, E1, 8'd6);        // e2
        7'd55: reenc = U_PWM(S4, S7, S0, 1'b0);
        7'd56: reenc = U_PWM(S4, S8, S1, 1'b1);
        7'd57: reenc = U_PWM(S4, S9, S2, 1'b1);
        7'd58: reenc = U_INTT(S4);
        7'd59: reenc = U_DEC(S3, dec, W_M, E3, 4'd1, 1'b0, 1'b1);   // mu = Decompress_1(m)
        7'd60: reenc = U_WAIT(WH | WA | WI);
        7'd61: reenc = U_ADD(S4, S11);
        7'd62: reenc = U_ADD(S4, S3);
        7'd63: reenc = U_WAIT(WA);
        7'd64: reenc = U_ENC(S4, snk, W_CT_V, 11'd0, E0, 4'd4, 1'b1);
        default: reenc = U_END(4'hF);
      endcase
    end
  endfunction

  // --- Encaps (FIPS 203 Alg. 17 + input check): (ek, m) -> c, K -----------------
  function [79:0] prog_en(input [6:0] k);
    begin
      if (k >= 7'd11 && k <= 7'd75)
        prog_en = reenc(k - 7'd11, 1'b0);
      else
        case (k)
          // H(ek) runs while the modulus check decodes t-hat into S7-S9
          7'd0:  prog_en = U_SHA3_256(L_EK, 8'd148, E2);
          7'd1:  prog_en = U_DEC(S7, 1'b0, W_EK,    E0, 4'd12, 1'b1, 1'b0);
          7'd2:  prog_en = U_DEC(S8, 1'b0, W_EK_T1, E0, 4'd12, 1'b1, 1'b0);
          7'd3:  prog_en = U_DEC(S9, 1'b0, W_EK_T2, E0, 4'd12, 1'b1, 1'b0);
          7'd4:  prog_en = U_WOP(I_M2S, W_EK_RHO, 11'd0, E5, E0, 4'd8, 1'b0);   // rho
          7'd5:  prog_en = U_WAIT(WI);
          7'd6:  prog_en = U_BR(EN_FAIL);
          7'd7:  prog_en = U_WAIT(WH);
          // (K, r) = G(m || H(ek)): K -> E0 -> mailbox, r -> E1
          7'd8:  prog_en = U_SHA3_512(1'b0, L_M, 1'b1, {7'd0, E2}, 8'd4, 2'd0, 16'd0, E0, E1);
          7'd9:  prog_en = U_WAIT(WH);
          7'd10: prog_en = U_WOP(I_S2M, W_SS, 11'd0, E0, E0, 4'd8, 1'b0);
          // 11-75: K-PKE.Encrypt (reenc, dec = 0)
          7'd76: prog_en = U_END(4'd0);
          7'd77: prog_en = U_END(4'd1);    // EN_FAIL (nothing was written)
          default: prog_en = U_END(4'hF);
        endcase
    end
  endfunction

  // --- Decaps (FIPS 203 Alg. 18 + input check): (dk, c) -> K --------------------
  // Decrypt: S3/S10/S3 u'[i] (NTT), S4/S11/S4 s-hat[i], S5 accumulator, S6 v'.
  function [79:0] prog_de(input [6:0] k);
    begin
      if (k >= 7'd33 && k <= 7'd97)
        prog_de = reenc(k - 7'd33, 1'b1);
      else
        case (k)
          7'd0:  prog_de = U_SHA3_256(L_DKEK, 8'd148, E2);                    // for the hash check
          7'd1:  prog_de = U_WOP(I_M2S, W_DKEK_RHO, 11'd0, E5, E0, 4'd8, 1'b0);
          7'd2:  prog_de = U_DEC(S3, 1'b0, W_CT,    E0, 4'd10, 1'b0, 1'b1);   // u'[0]
          7'd3:  prog_de = U_DEC(S4, 1'b0, W_DK,    E0, 4'd12, 1'b0, 1'b0);   // s-hat[0]
          7'd4:  prog_de = U_WAIT(WI);
          7'd5:  prog_de = U_NTT(S3);
          7'd6:  prog_de = U_DEC(S10, 1'b0, W_CT_U1, E0, 4'd10, 1'b0, 1'b1);  // u'[1]
          7'd7:  prog_de = U_DEC(S11, 1'b0, W_DK_S1, E0, 4'd12, 1'b0, 1'b0);  // s-hat[1]
          7'd8:  prog_de = U_WAIT(WH);
          7'd9:  prog_de = U_SHAKE_J(L_DK_Z, L_CT, 8'd136, E4);              // K-bar = J(z || c)
          7'd10: prog_de = U_PWM(S5, S3, S4, 1'b0);
          7'd11: prog_de = U_WAIT(WI);
          7'd12: prog_de = U_NTT(S10);
          7'd13: prog_de = U_DEC(S3, 1'b0, W_CT_U2, E0, 4'd10, 1'b0, 1'b1);   // u'[2]
          7'd14: prog_de = U_DEC(S4, 1'b0, W_DK_S2, E0, 4'd12, 1'b0, 1'b0);   // s-hat[2]
          7'd15: prog_de = U_PWM(S5, S10, S11, 1'b1);
          7'd16: prog_de = U_WAIT(WI);
          7'd17: prog_de = U_NTT(S3);
          7'd18: prog_de = U_WOP(I_CMP, W_DK_H, 11'd0, E2, E0, 4'd8, 1'b0);    // H(ek) = h ?
          7'd19: prog_de = U_DEC(S6, 1'b0, W_CT_V,    E0, 4'd4,  1'b0, 1'b1); // v'
          7'd20: prog_de = U_DEC(S7, 1'b0, W_DKEK,    E0, 4'd12, 1'b0, 1'b0); // t-hat
          7'd21: prog_de = U_DEC(S8, 1'b0, W_DKEK_T1, E0, 4'd12, 1'b0, 1'b0);
          7'd22: prog_de = U_DEC(S9, 1'b0, W_DKEK_T2, E0, 4'd12, 1'b0, 1'b0);
          7'd23: prog_de = U_PWM(S5, S3, S4, 1'b1);
          7'd24: prog_de = U_INTT(S5);
          7'd25: prog_de = U_WAIT(WA | WI);
          7'd26: prog_de = U_BR(DE_FAIL);
          // w = v' - INTT(s-hat^T o NTT(u')),  m' = ByteEncode_1(Compress_1(w))
          7'd27: prog_de = U_SUB(S6, S5);
          7'd28: prog_de = U_WAIT(WA);
          7'd29: prog_de = U_ENC(S6, K_SEED, 11'd0, 11'd0, E3, 4'd1, 1'b1);
          7'd30: prog_de = U_WAIT(WH | WI);
          // (K', r') = G(m' || h)
          7'd31: prog_de = U_SHA3_512(1'b1, {7'd0, E3}, 1'b0, L_DK_H, 8'd4, 2'd0, 16'd0, E0, E1);
          7'd32: prog_de = U_WAIT(WH);
          // 33-97: c' = K-PKE.Encrypt(ek, m', r'), compared with c (reenc, dec = 1)
          7'd98:  prog_de = U_WAIT(WI);
          7'd99:  prog_de = U_WOP(I_SEL, W_SS, 11'd0, E0, E4, 4'd8, 1'b0);  // c = c' ? K' : K-bar
          7'd100: prog_de = U_END(4'd0);
          7'd101: prog_de = U_WOP(I_ZERO, W_SS, 11'd0, E0, E0, 4'd8, 1'b0);  // DE_FAIL
          7'd102: prog_de = U_END(4'd1);
          default: prog_de = U_END(4'hF);
        endcase
    end
  endfunction

  function [79:0] ucode(input [8:0] a);
    case (a[8:7])
      2'd0:    ucode = prog_kg(a[6:0]);
      2'd1:    ucode = prog_en(a[6:0]);
      2'd2:    ucode = prog_de(a[6:0]);
      default: ucode = U_END(4'hF);
    endcase
  endfunction

  // ===========================================================================
  // sequencer
  // ===========================================================================
  reg        run;
  reg  [8:0] pc;
  reg [79:0] ins;          // = ucode(pc); registered ROM output
  reg [79:0] cmd;          // the instruction just issued to an engine
  reg        h_go, a_go, i_go;
  reg        bad, diff;

  wire       h_busy, a_busy, i_busy;
  wire       io_bad_set, io_diff_set;

  wire [3:0] cls      = ins[3:0];
  wire       wait_ok  = !(ins[4] && h_busy) && !(ins[5] && a_busy) && !(ins[6] && i_busy);
  wire       all_idle = !h_busy && !a_busy && !i_busy;
  wire       op_ok    = (op == 32'd1) || (op == 32'd2) || (op == 32'd3);

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
        C_BR:   pc_nx = bad ? ins[16:8] : (pc + 9'd1);
        C_HASH: if (!h_busy) begin iss_h = 1'b1; pc_nx = pc + 9'd1; end
        C_ALU:  if (!a_busy) begin iss_a = 1'b1; pc_nx = pc + 9'd1; end
        C_IO:   if (!i_busy) begin iss_i = 1'b1; pc_nx = pc + 9'd1; end
        default: fin = 1'b1;       // not an instruction: stop with status 15
      endcase
    end
  end

  // the ROM is addressed with the next pc so that ins always matches pc
  // (a registered-output ROM; Quartus can put it in block RAM)
  always @(posedge clk) begin
    pc  <= pc_nx;
    ins <= ucode(pc_nx);
    if (iss_h | iss_a | iss_i) cmd <= ins;
  end

  // Engine start pulses are registered: an engine sees its command one clock
  // after issue, and its busy output includes the start pulse, so the next
  // instruction already sees it busy.
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
            result <= 32'd2;           // MLKEM_STATUS_BAD_OP
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
      if (iss_h)
        $display("%0t  %3d  HASH rate %0d  mode %0d  slot %0d  in %0s %h/%0d  %0s %h/%0d",
                 $time, pc, ins[5:4], ins[64:63], ins[78:75],
                 ins[7] ? "seed" : "mb", ins[17:8], ins[25:18],
                 ins[26] ? "seed" : "mb", ins[36:27], ins[44:37]);
      if (iss_a)
        $display("%0t  %3d  ALU  op %0d  c S%0d  a S%0d  b S%0d  acc %0d",
                 $time, pc, ins[6:4], ins[11:8], ins[15:12], ins[19:16], ins[7]);
      if (iss_i)
        $display("%0t  %3d  IO   op %0d  slot S%0d  d %0d  sel %0d  addr %h  addr2 %h  E%0d E%0d",
                 $time, pc, ins[6:4], ins[10:7], ins[14:11], ins[18:17], ins[29:19],
                 ins[40:30], ins[43:41], ins[46:44]);
      if (cls == C_BR)
        $display("%0t  %3d  BR   bad %0d", $time, pc, bad);
      if (fin)
        $display("%0t  %3d  END  status %0d  (bad %0d diff %0d)", $time, pc, ins[7:4], bad, diff);
    end
  end
  // synthesis translate_on
`endif

  // ===========================================================================
  // engines and storage
  // ===========================================================================
  // Keccak engine
  wire        hs_mb_active;
  wire [10:0] hs_mb_addr;
  wire [2:0]  hs_sr_ent;
  wire [1:0]  hs_sr_lane;
  wire [63:0] hs_sr_data;
  wire        hs_sw_we;
  wire [2:0]  hs_sw_ent;
  wire [1:0]  hs_sw_lane;
  wire [63:0] hs_sw_data;
  wire [3:0]  s_slot;
  wire [11:0] s_waddr;
  wire [47:0] s_wdata;
  wire [1:0]  s_wen;

  mlkem_hash u_hash (
    .clk      (clk),
    .rst      (rst),
    .start    (h_go),
    .rate_in  (cmd[5:4]),
    .shake_in (cmd[6]),
    .p1s_in   (cmd[7]),
    .p1a_in   (cmd[17:8]),
    .p1n_in   (cmd[25:18]),
    .p2s_in   (cmd[26]),
    .p2a_in   (cmd[36:27]),
    .p2n_in   (cmd[44:37]),
    .sfn_in   (cmd[46:45]),
    .sfx_in   (cmd[62:47]),
    .om_in    (cmd[64:63]),
    .oe0_in   (cmd[67:65]),
    .oe1_in   (cmd[70:68]),
    .on_in    (cmd[74:71]),
    .oslot_in (cmd[78:75]),
    .busy     (h_busy),
    .mb_active(hs_mb_active),
    .mb_addr  (hs_mb_addr),
    .mb_rdata (mb_rdata),
    .sr_ent   (hs_sr_ent),
    .sr_lane  (hs_sr_lane),
    .sr_data  (hs_sr_data),
    .sw_we    (hs_sw_we),
    .sw_ent   (hs_sw_ent),
    .sw_lane  (hs_sw_lane),
    .sw_data  (hs_sw_data),
    .s_slot   (s_slot),
    .s_waddr  (s_waddr),
    .s_wdata  (s_wdata),
    .s_wen    (s_wen)
  );

  // polynomial ALU
  wire [3:0]  c_slot, a_slot, b_slot;
  wire        c_act, a_act, b_act;
  wire [11:0] c_raddr, c_waddr, a_raddr, b_raddr;
  wire [47:0] c_rdata, c_wdata, a_rdata, b_rdata;
  wire [1:0]  c_wen;

  mlkem_alu u_alu (
    .clk    (clk),
    .rst    (rst),
    .start  (a_go),
    .op_in  (cmd[6:4]),
    .acc_in (cmd[7]),
    .c_in   (cmd[11:8]),
    .a_in   (cmd[15:12]),
    .b_in   (cmd[19:16]),
    .busy   (a_busy),
    .c_slot (c_slot),
    .a_slot (a_slot),
    .b_slot (b_slot),
    .c_act  (c_act),
    .a_act  (a_act),
    .b_act  (b_act),
    .c_raddr(c_raddr),
    .c_rdata(c_rdata),
    .c_waddr(c_waddr),
    .c_wdata(c_wdata),
    .c_wen  (c_wen),
    .a_raddr(a_raddr),
    .a_rdata(a_rdata),
    .b_raddr(b_raddr),
    .b_rdata(b_rdata)
  );

  // IO engine
  wire [10:0] io_pb_addr;
  wire        io_pb_we;
  wire [31:0] io_pb_wdata;
  wire [2:0]  io_sr_ent, io_sr_word, io_sr2_ent;
  wire [31:0] io_sr_data, io_sr2_data;
  wire        io_sw_we;
  wire [2:0]  io_sw_ent, io_sw_word;
  wire [31:0] io_sw_data;
  wire [3:0]  i_slot;
  wire        i_act;
  wire [11:0] i_raddr, i_waddr;
  wire [47:0] i_rdata, i_wdata;
  wire [1:0]  i_wen;

  mlkem_io u_io (
    .clk      (clk),
    .rst      (rst),
    .start    (i_go),
    .op_in    (cmd[6:4]),
    .slot_in  (cmd[10:7]),
    .d_in     (cmd[14:11]),
    .fa_in    (cmd[15]),
    .fb_in    (cmd[16]),
    .sel_in   (cmd[18:17]),
    .addr_in  (cmd[29:19]),
    .addr2_in (cmd[40:30]),
    .ent_in   (cmd[43:41]),
    .ent2_in  (cmd[46:44]),
    .n_in     (cmd[50:47]),
    .diff_flag(diff),
    .busy     (i_busy),
    .bad_set  (io_bad_set),
    .diff_set (io_diff_set),
    .pa_addr  (ma_addr),
    .pa_we    (ma_we),
    .pa_wdata (ma_wdata),
    .pa_rdata (ma_rdata),
    .pb_addr  (io_pb_addr),
    .pb_we    (io_pb_we),
    .pb_wdata (io_pb_wdata),
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
    .i_act    (i_act),
    .i_raddr  (i_raddr),
    .i_rdata  (i_rdata),
    .i_waddr  (i_waddr),
    .i_wdata  (i_wdata),
    .i_wen    (i_wen)
  );

  // polynomial memory, 12 slots
  mlkem_polymem #(.NS(12)) u_pmem (
    .clk    (clk),
    .c_slot (c_slot),
    .c_act  (c_act),
    .c_raddr(c_raddr),
    .c_rdata(c_rdata),
    .c_waddr(c_waddr),
    .c_wdata(c_wdata),
    .c_wen  (c_wen),
    .a_slot (a_slot),
    .a_act  (a_act),
    .a_raddr(a_raddr),
    .a_rdata(a_rdata),
    .b_slot (b_slot),
    .b_act  (b_act),
    .b_raddr(b_raddr),
    .b_rdata(b_rdata),
    .s_slot (s_slot),
    .s_waddr(s_waddr),
    .s_wdata(s_wdata),
    .s_wen  (s_wen),
    .i_slot (i_slot),
    .i_act  (i_act),
    .i_raddr(i_raddr),
    .i_rdata(i_rdata),
    .i_waddr(i_waddr),
    .i_wdata(i_wdata),
    .i_wen  (i_wen)
  );

  // seed registers E0-E5
  mlkem_seedregs u_seed (
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

  // mailbox port B: the Keccak engine while its read stream is active
  assign mb_addr  = hs_mb_active ? hs_mb_addr : io_pb_addr;
  assign mb_we    = hs_mb_active ? 1'b0       : io_pb_we;
  assign mb_wdata = io_pb_wdata;

endmodule
