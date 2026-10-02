// -----------------------------------------------------------------------------
// mlkem2_ucode.v - microcode ROM of the v2 core: KeyGen, Encaps, Decaps.
//
// Combinational ROM, addr -> instruction; mlkem2_core.v registers the output
// (addressed with the next pc), which lets Quartus place it in block RAM.
//
// v2 needs no WAIT instructions for slot, seed-register or mailbox hazards:
// the sequencer checks every instruction against the operations still
// running on the other engines and holds it until it is safe. The order
// below only decides how well the engines overlap: it is a hand-made list
// schedule (the Keccak engine samples matrix entries into spare slots while
// the ALU runs NTTs; each XOF into a buffer is placed right after the ALU
// instruction whose issue proves the buffer's last reader has finished).
//
// Instruction word (80 bits):
//   [3:0] class: 0 END, 1 WAIT, 2 BR, 3 HASH, 4 ALU, 5 IO
//   END   [7:4] status          WAIT [4] hash [5] alu [6] io
//   BR    [16:8] target (taken if BAD; waits until the IO engine is idle)
//   HASH  as v1 (hw/manual/mlkem_rtl_core.v)
//   ALU   [6:4] op  [7] acc  [11:8] c  [15:12] a  [19:16] b
//         [21:20] fuse (INTT: 1 c = INTT(c) + a, 2 c = a - INTT(c))
//   IO    as v1, plus [51] acc (DEC: add into the slot)
//
// UNTESTED FIRST VERSION - see hw/manual_v2/README.md.
// -----------------------------------------------------------------------------
module mlkem2_ucode (
  input  wire [8:0]  addr,
  output reg  [79:0] ins
);
  localparam [3:0] C_END  = 4'd0, C_WAIT = 4'd1, C_BR = 4'd2,
                   C_HASH = 4'd3, C_ALU  = 4'd4, C_IO = 4'd5;
  localparam [2:0] WH = 3'b001, WA = 3'b010, WI = 3'b100;
  localparam [2:0] A_NTT = 3'd0, A_INTT = 3'd1, A_PWM = 3'd2, A_ADD = 3'd3, A_SUB = 3'd4;
  localparam [1:0] F_NONE = 2'd0, F_ADD = 2'd1, F_RSUB = 2'd2;
  localparam [2:0] I_DEC = 3'd0, I_ENC = 3'd1, I_S2M = 3'd2, I_M2M  = 3'd3,
                   I_M2S = 3'd4, I_CMP = 3'd5, I_SEL = 3'd6, I_ZERO = 3'd7;
  localparam [1:0] K_MB = 2'd0, K_MBDUAL = 2'd1, K_CMP = 2'd2, K_SEED = 2'd3;
  localparam [1:0] OM_SEED = 2'd0, OM_CBD = 2'd1, OM_SAMP = 2'd2;

  localparam [2:0] E0 = 3'd0, E1 = 3'd1, E2 = 3'd2, E3 = 3'd3, E4 = 3'd4, E5 = 3'd5;
  localparam [3:0] S0 = 4'd0, S1 = 4'd1, S2  = 4'd2,  S3  = 4'd3,
                   S4 = 4'd4, S5 = 4'd5, S6  = 4'd6,  S7  = 4'd7,
                   S8 = 4'd8, S9 = 4'd9, S10 = 4'd10, S11 = 4'd11;

  // mailbox word addresses (byte offset / 4; src/mlkem_accel.h)
  localparam [10:0] W_D        = 11'h000, W_Z        = 11'h008,
                    W_M        = 11'h010, W_SS       = 11'h018,
                    W_EK       = 11'h040, W_EK_T1    = 11'h0A0,
                    W_EK_T2    = 11'h100, W_EK_RHO   = 11'h160,
                    W_DK       = 11'h200, W_DK_S1    = 11'h260,
                    W_DK_S2    = 11'h2C0, W_DKEK     = 11'h320,
                    W_DKEK_T1  = 11'h380, W_DKEK_T2  = 11'h3E0,
                    W_DKEK_RHO = 11'h440, W_DK_H     = 11'h448,
                    W_DK_Z     = 11'h450, W_CT       = 11'h600,
                    W_CT_U1    = 11'h650, W_CT_U2    = 11'h6A0,
                    W_CT_V     = 11'h6F0;
  // 64-bit lane addresses
  localparam [9:0]  L_D    = 10'h000, L_M    = 10'h008, L_EK   = 10'h020,
                    L_DKEK = 10'h190, L_DK_H = 10'h224, L_DK_Z = 10'h228,
                    L_CT   = 10'h300;

  localparam [8:0] EN_FAIL = 9'd128 + 9'd49;
  localparam [8:0] DE_FAIL = 9'd256 + 9'd66;

  // --- instruction builders -------------------------------------------------
  function [79:0] U_END(input [3:0] status);
    begin
      U_END = 80'd0;  U_END[3:0] = C_END;  U_END[7:4] = status;
    end
  endfunction

  function [79:0] U_WAIT(input [2:0] mask);
    begin
      U_WAIT = 80'd0;  U_WAIT[3:0] = C_WAIT;  U_WAIT[6:4] = mask;
    end
  endfunction

  function [79:0] U_BR(input [8:0] target);
    begin
      U_BR = 80'd0;  U_BR[3:0] = C_BR;  U_BR[16:8] = target;
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

  // H: SHA3-256 of n mailbox lanes -> ent
  function [79:0] U_SHA3_256(input [9:0] lane, input [7:0] n, input [2:0] ent);
    U_SHA3_256 = U_HASH(2'd1, 1'b0, 1'b0, lane, n, 1'b0, 10'd0, 8'd0,
                        2'd0, 16'd0, OM_SEED, ent, 3'd0, 4'd4, 4'd0);
  endfunction

  // G: SHA3-512 of part 1 (4 lanes) || part 2 || suffix -> e0 (bytes 0-31), e1
  function [79:0] U_SHA3_512(input p1s, input [9:0] p1a, input p2s, input [9:0] p2a,
                             input [7:0] p2n, input [1:0] sfn, input [15:0] sfx,
                             input [2:0] e0, input [2:0] e1);
    U_SHA3_512 = U_HASH(2'd2, 1'b0, p1s, p1a, 8'd4, p2s, p2a, p2n,
                        sfn, sfx, OM_SEED, e0, e1, 4'd8, 4'd0);
  endfunction

  // J: SHAKE256(z || c) -> 32 bytes -> ent
  function [79:0] U_SHAKE_J(input [9:0] zl, input [9:0] cl, input [7:0] cn, input [2:0] ent);
    U_SHAKE_J = U_HASH(2'd1, 1'b1, 1'b0, zl, 8'd4, 1'b0, cl, cn,
                       2'd0, 16'd0, OM_SEED, ent, 3'd0, 4'd4, 4'd0);
  endfunction

  // slot = SamplePolyCBD_2(SHAKE256(seed ent || nonce, 128 B))
  function [79:0] U_CBD(input [3:0] slot, input [2:0] ent, input [7:0] nonce);
    U_CBD = U_HASH(2'd1, 1'b1, 1'b1, {7'd0, ent}, 8'd4, 1'b0, 10'd0, 8'd0,
                   2'd1, {8'd0, nonce}, OM_CBD, 3'd0, 3'd0, 4'd0, slot);
  endfunction

  // slot = SampleNTT(seed ent || b32 || b33)
  function [79:0] U_XOF(input [3:0] slot, input [2:0] ent, input [7:0] b32, input [7:0] b33);
    U_XOF = U_HASH(2'd0, 1'b1, 1'b1, {7'd0, ent}, 8'd4, 1'b0, 10'd0, 8'd0,
                   2'd2, {b33, b32}, OM_SAMP, 3'd0, 3'd0, 4'd0, slot);
  endfunction

  function [79:0] U_ALU(input [2:0] aop, input [3:0] c, input [3:0] a, input [3:0] b,
                        input acc, input [1:0] fuse);
    begin
      U_ALU        = 80'd0;
      U_ALU[3:0]   = C_ALU;
      U_ALU[6:4]   = aop;
      U_ALU[7]     = acc;
      U_ALU[11:8]  = c;
      U_ALU[15:12] = a;
      U_ALU[19:16] = b;
      U_ALU[21:20] = fuse;
    end
  endfunction

  function [79:0] U_NTT(input [3:0] c);
    U_NTT = U_ALU(A_NTT, c, 4'd0, 4'd0, 1'b0, F_NONE);
  endfunction
  function [79:0] U_INTT_ADD(input [3:0] c, input [3:0] a);     // c = INTT(c) + a
    U_INTT_ADD = U_ALU(A_INTT, c, a, 4'd0, 1'b0, F_ADD);
  endfunction
  function [79:0] U_INTT_RSUB(input [3:0] c, input [3:0] a);    // c = a - INTT(c)
    U_INTT_RSUB = U_ALU(A_INTT, c, a, 4'd0, 1'b0, F_RSUB);
  endfunction
  function [79:0] U_PWM(input [3:0] c, input [3:0] a, input [3:0] b, input acc);
    U_PWM = U_ALU(A_PWM, c, a, b, acc, F_NONE);
  endfunction

  function [79:0] U_IO(input [2:0] iop, input [3:0] slot, input [3:0] d,
                       input fa, input fb, input acc, input [1:0] sel,
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
      U_IO[51]    = acc;
    end
  endfunction

  // slot (+)= ByteDecode_d(mailbox addr | seed ent); check: flag >= q; decomp
  function [79:0] U_DEC(input [3:0] slot, input seedsrc, input [10:0] addr, input [2:0] ent,
                        input [3:0] d, input check, input decomp, input acc);
    U_DEC = U_IO(I_DEC, slot, d, check, decomp, acc, {1'b0, seedsrc}, addr, 11'd0,
                 ent, 3'd0, 4'd0);
  endfunction

  function [79:0] U_ENC(input [3:0] slot, input [1:0] sink, input [10:0] addr,
                        input [10:0] addr2, input [2:0] ent, input [3:0] d, input comp);
    U_ENC = U_IO(I_ENC, slot, d, comp, 1'b0, 1'b0, sink, addr, addr2, ent, 3'd0, 4'd0);
  endfunction

  function [79:0] U_WOP(input [2:0] iop, input [10:0] addr, input [10:0] addr2,
                        input [2:0] ent, input [2:0] ent2, input [3:0] n, input dual);
    U_WOP = U_IO(iop, 4'd0, 4'd0, dual, 1'b0, 1'b0, 2'd0, addr, addr2, ent, ent2, n);
  endfunction

  // --- KeyGen: (d, z) -> ek, dk --------------------------------------------------
  // S0-S2 s-hat, S5-S7 e-hat -> t-hat, S3 S4 S8 S9 S10 S11 matrix entries.
  // A[i][j] = SampleNTT(rho || j || i): U_XOF(slot, E5, j, i).
  function [79:0] prog_kg(input [6:0] k);
    case (k)
      7'd0:  prog_kg = U_SHA3_512(1'b0, L_D, 1'b0, 10'd0, 8'd0, 2'd1, 16'h0003, E5, E1);
      7'd1:  prog_kg = U_CBD(S0, E1, 8'd0);
      7'd2:  prog_kg = U_WOP(I_S2M, W_EK_RHO, W_DKEK_RHO, E5, E0, 4'd8, 1'b1);
      7'd3:  prog_kg = U_WOP(I_M2M, W_Z, W_DK_Z, E0, E0, 4'd8, 1'b0);
      7'd4:  prog_kg = U_CBD(S1, E1, 8'd1);
      7'd5:  prog_kg = U_NTT(S0);
      7'd6:  prog_kg = U_CBD(S2, E1, 8'd2);
      7'd7:  prog_kg = U_CBD(S5, E1, 8'd3);
      7'd8:  prog_kg = U_CBD(S6, E1, 8'd4);
      7'd9:  prog_kg = U_CBD(S7, E1, 8'd5);
      7'd10: prog_kg = U_XOF(S3,  E5, 8'd0, 8'd0);     // A[0][0]
      7'd11: prog_kg = U_NTT(S1);
      7'd12: prog_kg = U_ENC(S0, K_MB, W_DK, 11'd0, E0, 4'd12, 1'b0);
      7'd13: prog_kg = U_XOF(S4,  E5, 8'd1, 8'd0);     // A[0][1]
      7'd14: prog_kg = U_XOF(S8,  E5, 8'd2, 8'd0);     // A[0][2]
      7'd15: prog_kg = U_NTT(S2);
      7'd16: prog_kg = U_ENC(S1, K_MB, W_DK_S1, 11'd0, E0, 4'd12, 1'b0);
      7'd17: prog_kg = U_XOF(S9,  E5, 8'd0, 8'd1);     // A[1][0]
      7'd18: prog_kg = U_XOF(S10, E5, 8'd1, 8'd1);     // A[1][1]
      7'd19: prog_kg = U_NTT(S5);
      7'd20: prog_kg = U_ENC(S2, K_MB, W_DK_S2, 11'd0, E0, 4'd12, 1'b0);
      7'd21: prog_kg = U_XOF(S11, E5, 8'd2, 8'd1);     // A[1][2]
      7'd22: prog_kg = U_NTT(S6);
      7'd23: prog_kg = U_NTT(S7);
      7'd24: prog_kg = U_PWM(S5, S3,  S0, 1'b1);
      7'd25: prog_kg = U_PWM(S5, S4,  S1, 1'b1);
      7'd26: prog_kg = U_XOF(S3,  E5, 8'd0, 8'd2);     // A[2][0]
      7'd27: prog_kg = U_PWM(S5, S8,  S2, 1'b1);
      7'd28: prog_kg = U_XOF(S4,  E5, 8'd1, 8'd2);     // A[2][1]
      7'd29: prog_kg = U_PWM(S6, S9,  S0, 1'b1);
      7'd30: prog_kg = U_ENC(S5, K_MBDUAL, W_EK, W_DKEK, E0, 4'd12, 1'b0);        // t-hat[0]
      7'd31: prog_kg = U_PWM(S6, S10, S1, 1'b1);
      7'd32: prog_kg = U_XOF(S8,  E5, 8'd2, 8'd2);     // A[2][2]
      7'd33: prog_kg = U_PWM(S6, S11, S2, 1'b1);
      7'd34: prog_kg = U_PWM(S7, S3,  S0, 1'b1);
      7'd35: prog_kg = U_ENC(S6, K_MBDUAL, W_EK_T1, W_DKEK_T1, E0, 4'd12, 1'b0);  // t-hat[1]
      7'd36: prog_kg = U_PWM(S7, S4,  S1, 1'b1);
      7'd37: prog_kg = U_PWM(S7, S8,  S2, 1'b1);
      7'd38: prog_kg = U_ENC(S7, K_MBDUAL, W_EK_T2, W_DKEK_T2, E0, 4'd12, 1'b0);  // t-hat[2]
      7'd39: prog_kg = U_SHA3_256(L_EK, 8'd148, E2);                               // H(ek)
      7'd40: prog_kg = U_WOP(I_S2M, W_DK_H, 11'd0, E2, E0, 4'd8, 1'b0);
      7'd41: prog_kg = U_END(4'd0);
      default: prog_kg = U_END(4'hF);
    endcase
  endfunction

  // --- K-PKE.Encrypt from the first product of u[0] on (Encaps and Decaps) ----
  // Needs: y-hat in S0-S2, A[0][i] (i = 0..2) in S3-S5, e1[0] in S11, r in
  // E1, rho in E5, t-hat in S7-S9. A[j][i] = SampleNTT(rho || i || j):
  // U_XOF(slot, E5, i, j). u[0] -> S6, u[1] -> S10, u[2] -> S6, v -> S10,
  // e2 + mu -> S3.
  //   dec = 0: c written to the mailbox, mu from the mailbox (m)
  //   dec = 1: c' compared with the mailbox (DIFF), mu from E3 (m')
  function [79:0] tail(input [5:0] k, input dec);
    reg [1:0] snk;
    begin
      snk = dec ? K_CMP : K_MB;
      case (k)
        6'd0:  tail = U_PWM(S6, S3, S0, 1'b0);
        6'd1:  tail = U_PWM(S6, S4, S1, 1'b1);
        6'd2:  tail = U_XOF(S3, E5, 8'd1, 8'd0);         // A[0][1]
        6'd3:  tail = U_PWM(S6, S5, S2, 1'b1);
        6'd4:  tail = U_XOF(S4, E5, 8'd1, 8'd1);         // A[1][1]
        6'd5:  tail = U_INTT_ADD(S6, S11);               // u[0] = INTT(.) + e1[0]
        6'd6:  tail = U_XOF(S5, E5, 8'd1, 8'd2);         // A[2][1]
        6'd7:  tail = U_ENC(S6, snk, W_CT, 11'd0, E0, 4'd10, 1'b1);
        6'd8:  tail = U_CBD(S11, E1, 8'd4);              // e1[1]
        6'd9:  tail = U_PWM(S10, S3, S0, 1'b0);
        6'd10: tail = U_PWM(S10, S4, S1, 1'b1);
        6'd11: tail = U_XOF(S3, E5, 8'd2, 8'd0);         // A[0][2]
        6'd12: tail = U_PWM(S10, S5, S2, 1'b1);
        6'd13: tail = U_XOF(S4, E5, 8'd2, 8'd1);         // A[1][2]
        6'd14: tail = U_INTT_ADD(S10, S11);              // u[1]
        6'd15: tail = U_XOF(S5, E5, 8'd2, 8'd2);         // A[2][2]
        6'd16: tail = U_ENC(S10, snk, W_CT_U1, 11'd0, E0, 4'd10, 1'b1);
        6'd17: tail = U_CBD(S11, E1, 8'd5);              // e1[2]
        6'd18: tail = U_PWM(S6, S3, S0, 1'b0);
        6'd19: tail = U_PWM(S6, S4, S1, 1'b1);
        6'd20: tail = U_CBD(S3, E1, 8'd6);               // e2
        6'd21: tail = U_PWM(S6, S5, S2, 1'b1);
        6'd22: tail = U_DEC(S3, dec, W_M, E3, 4'd1, 1'b0, 1'b1, 1'b1);   // e2 + mu
        6'd23: tail = U_INTT_ADD(S6, S11);               // u[2]
        6'd24: tail = U_ENC(S6, snk, W_CT_U2, 11'd0, E0, 4'd10, 1'b1);
        6'd25: tail = U_PWM(S10, S7, S0, 1'b0);
        6'd26: tail = U_PWM(S10, S8, S1, 1'b1);
        6'd27: tail = U_PWM(S10, S9, S2, 1'b1);
        6'd28: tail = U_INTT_ADD(S10, S3);               // v = INTT(.) + e2 + mu
        6'd29: tail = U_ENC(S10, snk, W_CT_V, 11'd0, E0, 4'd4, 1'b1);
        default: tail = U_END(4'hF);
      endcase
    end
  endfunction

  // --- Encaps: (ek, m) -> c, K ------------------------------------------------------
  function [79:0] prog_en(input [6:0] k);
    begin
      if (k >= 7'd18 && k <= 7'd47)
        prog_en = tail(k[5:0] - 6'd18, 1'b0);
      else
        case (k)
          7'd0:  prog_en = U_SHA3_256(L_EK, 8'd148, E2);                        // H(ek)
          7'd1:  prog_en = U_DEC(S7, 1'b0, W_EK,    E0, 4'd12, 1'b1, 1'b0, 1'b0);   // + ek check
          7'd2:  prog_en = U_DEC(S8, 1'b0, W_EK_T1, E0, 4'd12, 1'b1, 1'b0, 1'b0);
          7'd3:  prog_en = U_SHA3_512(1'b0, L_M, 1'b1, {7'd0, E2}, 8'd4, 2'd0, 16'd0, E0, E1);
          7'd4:  prog_en = U_DEC(S9, 1'b0, W_EK_T2, E0, 4'd12, 1'b1, 1'b0, 1'b0);
          7'd5:  prog_en = U_CBD(S0, E1, 8'd0);
          7'd6:  prog_en = U_CBD(S1, E1, 8'd1);
          7'd7:  prog_en = U_NTT(S0);
          7'd8:  prog_en = U_WOP(I_M2S, W_EK_RHO, 11'd0, E5, E0, 4'd8, 1'b0);  // rho
          7'd9:  prog_en = U_CBD(S2, E1, 8'd2);
          7'd10: prog_en = U_XOF(S3, E5, 8'd0, 8'd0);                          // A[0][0]
          7'd11: prog_en = U_XOF(S4, E5, 8'd0, 8'd1);                          // A[1][0]
          7'd12: prog_en = U_NTT(S1);
          7'd13: prog_en = U_XOF(S5, E5, 8'd0, 8'd2);                          // A[2][0]
          7'd14: prog_en = U_NTT(S2);
          7'd15: prog_en = U_CBD(S11, E1, 8'd3);                               // e1[0]
          7'd16: prog_en = U_BR(EN_FAIL);                                      // before any mailbox write
          7'd17: prog_en = U_WOP(I_S2M, W_SS, 11'd0, E0, E0, 4'd8, 1'b0);      // K
          // 18-47: tail
          7'd48: prog_en = U_END(4'd0);
          7'd49: prog_en = U_END(4'd1);                                        // EN_FAIL
          default: prog_en = U_END(4'hF);
        endcase
    end
  endfunction

  // --- Decaps: (dk, c) -> K -----------------------------------------------------------
  // Decrypt: S3-S5 u' (NTT), S0-S2 s-hat, S6 accumulator -> w, S11 v'.
  function [79:0] prog_de(input [6:0] k);
    begin
      if (k >= 7'd34 && k <= 7'd63)
        prog_de = tail(k[5:0] - 6'd34, 1'b1);
      else
        case (k)
          7'd0:  prog_de = U_SHA3_256(L_DKEK, 8'd148, E2);                     // hash check
          7'd1:  prog_de = U_WOP(I_M2S, W_DKEK_RHO, 11'd0, E5, E0, 4'd8, 1'b0);
          7'd2:  prog_de = U_DEC(S3, 1'b0, W_CT,    E0, 4'd10, 1'b0, 1'b1, 1'b0);
          7'd3:  prog_de = U_DEC(S0, 1'b0, W_DK,    E0, 4'd12, 1'b0, 1'b0, 1'b0);
          7'd4:  prog_de = U_NTT(S3);
          7'd5:  prog_de = U_DEC(S4, 1'b0, W_CT_U1, E0, 4'd10, 1'b0, 1'b1, 1'b0);
          7'd6:  prog_de = U_SHAKE_J(L_DK_Z, L_CT, 8'd136, E4);               // K-bar
          7'd7:  prog_de = U_PWM(S6, S3, S0, 1'b0);
          7'd8:  prog_de = U_DEC(S1, 1'b0, W_DK_S1, E0, 4'd12, 1'b0, 1'b0, 1'b0);
          7'd9:  prog_de = U_NTT(S4);
          7'd10: prog_de = U_DEC(S5, 1'b0, W_CT_U2, E0, 4'd10, 1'b0, 1'b1, 1'b0);
          7'd11: prog_de = U_DEC(S2, 1'b0, W_DK_S2, E0, 4'd12, 1'b0, 1'b0, 1'b0);
          7'd12: prog_de = U_PWM(S6, S4, S1, 1'b1);
          7'd13: prog_de = U_DEC(S11, 1'b0, W_CT_V, E0, 4'd4, 1'b0, 1'b1, 1'b0);
          7'd14: prog_de = U_NTT(S5);
          7'd15: prog_de = U_WOP(I_CMP, W_DK_H, 11'd0, E2, E0, 4'd8, 1'b0);    // H(ek) = h ?
          7'd16: prog_de = U_BR(DE_FAIL);
          7'd17: prog_de = U_PWM(S6, S5, S2, 1'b1);
          7'd18: prog_de = U_INTT_RSUB(S6, S11);                              // w = v' - INTT(.)
          7'd19: prog_de = U_ENC(S6, K_SEED, 11'd0, 11'd0, E3, 4'd1, 1'b1);   // m'
          7'd20: prog_de = U_SHA3_512(1'b1, {7'd0, E3}, 1'b0, L_DK_H, 8'd4, 2'd0, 16'd0, E0, E1);
          7'd21: prog_de = U_DEC(S7, 1'b0, W_DKEK,    E0, 4'd12, 1'b0, 1'b0, 1'b0);
          7'd22: prog_de = U_CBD(S0, E1, 8'd0);
          7'd23: prog_de = U_CBD(S1, E1, 8'd1);
          7'd24: prog_de = U_NTT(S0);
          7'd25: prog_de = U_DEC(S8, 1'b0, W_DKEK_T1, E0, 4'd12, 1'b0, 1'b0, 1'b0);
          7'd26: prog_de = U_CBD(S2, E1, 8'd2);
          7'd27: prog_de = U_XOF(S3, E5, 8'd0, 8'd0);                          // A[0][0]
          7'd28: prog_de = U_XOF(S4, E5, 8'd0, 8'd1);                          // A[1][0]
          7'd29: prog_de = U_NTT(S1);
          7'd30: prog_de = U_DEC(S9, 1'b0, W_DKEK_T2, E0, 4'd12, 1'b0, 1'b0, 1'b0);
          7'd31: prog_de = U_XOF(S5, E5, 8'd0, 8'd2);                          // A[2][0]
          7'd32: prog_de = U_NTT(S2);
          7'd33: prog_de = U_CBD(S11, E1, 8'd3);                               // e1[0]
          // 34-63: tail (compare mode)
          7'd64: prog_de = U_WOP(I_SEL, W_SS, 11'd0, E0, E4, 4'd8, 1'b0);      // c = c' ? K' : K-bar
          7'd65: prog_de = U_END(4'd0);
          7'd66: prog_de = U_WOP(I_ZERO, W_SS, 11'd0, E0, E0, 4'd8, 1'b0);     // DE_FAIL
          7'd67: prog_de = U_END(4'd1);
          default: prog_de = U_END(4'hF);
        endcase
    end
  endfunction

  always @* begin
    case (addr[8:7])
      2'd0:    ins = prog_kg(addr[6:0]);
      2'd1:    ins = prog_en(addr[6:0]);
      2'd2:    ins = prog_de(addr[6:0]);
      default: ins = U_END(4'hF);
    endcase
  end
endmodule
