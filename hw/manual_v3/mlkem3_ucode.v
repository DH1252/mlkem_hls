// -----------------------------------------------------------------------------
// mlkem3_ucode.v - microcode ROM of the v3 core: KeyGen, Encaps, Decaps.
//
// Combinational ROM, addr -> instruction; mlkem3_core.v registers the output.
//
// The sequencer checks every instruction against the jobs running on the
// four engines and holds it until it is safe, so any order that is correct
// as a sequential program is correct in hardware. The order below is a
// hand-made list schedule: instructions appear roughly in the order they can
// start (estimated clock in the comments), so an instruction that has to wait
// does not hold back independent ones behind it.
//
// Instruction word (80 bits):
//   [3:0] class: 0 END, 1 WAIT, 2 BR, 3 HASH, 4 NTT, 5 IO, 6 PWM
//   END   [7:4] status          WAIT [4] hash [5] ntt [6] io [7] pwm
//   BR    [16:8] target (taken if BAD; waits until the IO engine is idle)
//   HASH  as v2
//   NTT   [6:4] op (0 NTT, 1 INTT)  [11:8] c  [15:12] a
//         [21:20] fuse (1: c = X(c) + a, 2: c = a - X(c))
//   PWM   [6:4] op (2 PWM, 3 ADD, 4 SUB)  [7] acc  [11:8] c  [15:12] a  [19:16] b
//         (c may equal a: in-place product, used to reuse matrix buffers
//         as accumulators)
//   IO    as v2 ([51] acc: DEC adds into the slot)
//
// Rules the sequencer relies on (not checked in hardware):
//   - a mailbox part of a HASH instruction, and the range an IO instruction
//     writes, must not cross a mailbox region boundary (the hazard check
//     looks at start addresses; regions in mlkem3_core.v)
//   - a fused NTT/INTT needs c != a (the engine reads a while it still
//     reads c); a PWM may use c == a (in-place product)
//
// UNTESTED FIRST VERSION of v3 - see hw/manual_v3/README.md.
// -----------------------------------------------------------------------------
module mlkem3_ucode (
  input  wire [8:0]  addr,
  output reg  [79:0] ins
);
  localparam [3:0] C_END = 4'd0, C_WAIT = 4'd1, C_BR  = 4'd2, C_HASH = 4'd3,
                   C_NTT = 4'd4, C_IO   = 4'd5, C_PWM = 4'd6;
  localparam [2:0] N_NTT = 3'd0, N_INTT = 3'd1;
  localparam [2:0] A_PWM = 3'd2, A_ADD = 3'd3, A_SUB = 3'd4;
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

  function [79:0] U_NTTOP(input [2:0] nop, input [3:0] c, input [3:0] a, input [1:0] fuse);
    begin
      U_NTTOP        = 80'd0;
      U_NTTOP[3:0]   = C_NTT;
      U_NTTOP[6:4]   = nop;
      U_NTTOP[11:8]  = c;
      U_NTTOP[15:12] = a;
      U_NTTOP[21:20] = fuse;
    end
  endfunction

  function [79:0] U_NTT(input [3:0] c);                           // c = NTT(c)
    U_NTT = U_NTTOP(N_NTT, c, 4'd0, F_NONE);
  endfunction
  function [79:0] U_NTT_ADD(input [3:0] c, input [3:0] a);        // c = NTT(c) + a
    U_NTT_ADD = U_NTTOP(N_NTT, c, a, F_ADD);
  endfunction
  function [79:0] U_INTT_ADD(input [3:0] c, input [3:0] a);       // c = INTT(c) + a
    U_INTT_ADD = U_NTTOP(N_INTT, c, a, F_ADD);
  endfunction
  function [79:0] U_INTT_RSUB(input [3:0] c, input [3:0] a);      // c = a - INTT(c)
    U_INTT_RSUB = U_NTTOP(N_INTT, c, a, F_RSUB);
  endfunction

  // c = (acc ? c : 0) + a o b
  function [79:0] U_PWM(input [3:0] c, input [3:0] a, input [3:0] b, input acc);
    begin
      U_PWM        = 80'd0;
      U_PWM[3:0]   = C_PWM;
      U_PWM[6:4]   = A_PWM;
      U_PWM[7]     = acc;
      U_PWM[11:8]  = c;
      U_PWM[15:12] = a;
      U_PWM[19:16] = b;
    end
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
  // S0-S2 s-hat; S5 S6 S7 e-hat -> t-hat; S11 = A[2][*] o s (fused into
  // NTT(e2)); matrix buffers S3 S4 S8 S9 S10.
  // A[i][j] = SampleNTT(rho || j || i): U_XOF(slot, E5, j, i).
  // NTT order s0 s1 e0 s2 e1 e2: row 0 accumulates onto e0-hat as soon as it
  // exists; row 2 is summed early in S11 and added by the last (fused) NTT.
  // ~1,390 clocks (v2: 2,867).
  function [79:0] prog_kg(input [6:0] k);
    case (k)
      7'd0:  prog_kg = U_SHA3_512(1'b0, L_D, 1'b0, 10'd0, 8'd0, 2'd1, 16'h0003, E5, E1); //    0 (rho, sigma)
      7'd1:  prog_kg = U_CBD(S0, E1, 8'd0);                                    //   31 s0
      7'd2:  prog_kg = U_WOP(I_S2M, W_EK_RHO, W_DKEK_RHO, E5, E0, 4'd8, 1'b1); //   31 rho -> ek, dk
      7'd3:  prog_kg = U_WOP(I_M2M, W_Z, W_DK_Z, E0, E0, 4'd8, 1'b0);          //   41 z -> dk
      7'd4:  prog_kg = U_CBD(S1, E1, 8'd1);                                    //   84 s1
      7'd5:  prog_kg = U_NTT(S0);                                              //   84
      7'd6:  prog_kg = U_CBD(S5, E1, 8'd3);                                    //  137 e0
      7'd7:  prog_kg = U_CBD(S2, E1, 8'd2);                                    //  190 s2
      7'd8:  prog_kg = U_NTT(S1);                                              //  225
      7'd9:  prog_kg = U_ENC(S0, K_MB, W_DK, 11'd0, E0, 4'd12, 1'b0);          //  225 dk: s0
      7'd10: prog_kg = U_CBD(S6, E1, 8'd4);                                    //  243 e1
      7'd11: prog_kg = U_CBD(S7, E1, 8'd5);                                    //  296 e2
      7'd12: prog_kg = U_XOF(S3, E5, 8'd0, 8'd0);                              //  349 A[0][0]
      7'd13: prog_kg = U_NTT(S5);                                              //  366 e0
      7'd14: prog_kg = U_ENC(S1, K_MB, W_DK_S1, 11'd0, E0, 4'd12, 1'b0);       //  366 dk: s1
      7'd15: prog_kg = U_XOF(S4, E5, 8'd1, 8'd0);                              //  413 A[0][1]
      7'd16: prog_kg = U_XOF(S8, E5, 8'd2, 8'd0);                              //  477 A[0][2]
      7'd17: prog_kg = U_NTT(S2);                                              //  507
      7'd18: prog_kg = U_PWM(S5, S3, S0, 1'b1);                                //  507 t0 += A00 s0
      7'd19: prog_kg = U_XOF(S9, E5, 8'd0, 8'd2);                              //  541 A[2][0]
      7'd20: prog_kg = U_PWM(S5, S4, S1, 1'b1);                                //  551 t0 += A01 s1
      7'd21: prog_kg = U_PWM(S11, S9, S0, 1'b0);                               //  605 T2  = A20 s0
      7'd22: prog_kg = U_XOF(S10, E5, 8'd1, 8'd2);                             //  605 A[2][1]
      7'd23: prog_kg = U_NTT(S6);                                              //  648 e1
      7'd24: prog_kg = U_PWM(S5, S8, S2, 1'b1);                                //  649 t0 += A02 s2
      7'd25: prog_kg = U_XOF(S3, E5, 8'd2, 8'd2);                              //  669 A[2][2]
      7'd26: prog_kg = U_ENC(S5, K_MBDUAL, W_EK, W_DKEK, E0, 4'd12, 1'b0);     //  693 t0 -> ek, dk
      7'd27: prog_kg = U_PWM(S11, S10, S1, 1'b1);                              //  693 T2 += A21 s1
      7'd28: prog_kg = U_XOF(S4, E5, 8'd0, 8'd1);                              //  733 A[1][0]
      7'd29: prog_kg = U_PWM(S11, S3, S2, 1'b1);                               //  737 T2 += A22 s2
      7'd30: prog_kg = U_NTT_ADD(S7, S11);                                     //  789 t2 = NTT(e2) + T2
      7'd31: prog_kg = U_XOF(S8, E5, 8'd1, 8'd1);                              //  797 A[1][1]
      7'd32: prog_kg = U_PWM(S6, S4, S0, 1'b1);                                //  797 t1 += A10 s0
      7'd33: prog_kg = U_XOF(S9, E5, 8'd2, 8'd1);                              //  861 A[1][2]
      7'd34: prog_kg = U_PWM(S6, S8, S1, 1'b1);                                //  861 t1 += A11 s1
      7'd35: prog_kg = U_PWM(S6, S9, S2, 1'b1);                                //  925 t1 += A12 s2
      7'd36: prog_kg = U_ENC(S7, K_MBDUAL, W_EK_T2, W_DKEK_T2, E0, 4'd12, 1'b0); // 930 t2
      7'd37: prog_kg = U_ENC(S6, K_MBDUAL, W_EK_T1, W_DKEK_T1, E0, 4'd12, 1'b0); // 1065 t1
      7'd38: prog_kg = U_SHA3_256(L_EK, 8'd148, E2);                           // 1200 H(ek)
      7'd39: prog_kg = U_ENC(S2, K_MB, W_DK_S2, 11'd0, E0, 4'd12, 1'b0);       // 1200 dk: s2 (region dk, beside H)
      7'd40: prog_kg = U_WOP(I_S2M, W_DK_H, 11'd0, E2, E0, 4'd8, 1'b0);        // 1380 H(ek) -> dk
      7'd41: prog_kg = U_END(4'd0);
      default: prog_kg = U_END(4'hF);
    endcase
  endfunction

  // --- Encaps: (ek, m) -> c, K ------------------------------------------------------
  // y-hat S0-S2; t-hat S7 S8 S9 (S7 then holds v); matrix buffers S3 S4 S5 S10
  // (and S9 later); u0 accumulates in S3, u1 in S10, u2 in S9 (the first
  // matrix entry of each column, multiplied in place); e1 in S6 S8 S6; e2 + mu
  // in S11. A[j][i] = SampleNTT(rho || i || j): U_XOF(slot, E5, i, j).
  // ~1,430 clocks (v2: 3,375).
  function [79:0] prog_en(input [6:0] k);
    case (k)
      7'd0:  prog_en = U_SHA3_256(L_EK, 8'd148, E2);                           //    0 H(ek)
      7'd1:  prog_en = U_WOP(I_M2S, W_EK_RHO, 11'd0, E5, E0, 4'd8, 1'b0);      //    0 rho
      7'd2:  prog_en = U_DEC(S7, 1'b0, W_EK,    E0, 4'd12, 1'b1, 1'b0, 1'b0);  //   10 t0 + ek check
      7'd3:  prog_en = U_DEC(S8, 1'b0, W_EK_T1, E0, 4'd12, 1'b1, 1'b0, 1'b0);  //  110 t1
      7'd4:  prog_en = U_SHA3_512(1'b0, L_M, 1'b1, {7'd0, E2}, 8'd4, 2'd0, 16'd0, E0, E1); // 180 (K, r)
      7'd5:  prog_en = U_DEC(S9, 1'b0, W_EK_T2, E0, 4'd12, 1'b1, 1'b0, 1'b0);  //  210 t2
      7'd6:  prog_en = U_CBD(S0, E1, 8'd0);                                    //  211 y0
      7'd7:  prog_en = U_CBD(S1, E1, 8'd1);                                    //  264 y1
      7'd8:  prog_en = U_NTT(S0);                                              //  264
      7'd9:  prog_en = U_BR(EN_FAIL);                                          //  310 before any mailbox write
      7'd10: prog_en = U_WOP(I_S2M, W_SS, 11'd0, E0, E0, 4'd8, 1'b0);          //  310 K
      7'd11: prog_en = U_CBD(S2, E1, 8'd2);                                    //  317 y2
      7'd12: prog_en = U_CBD(S11, E1, 8'd6);                                   //  370 e2
      7'd13: prog_en = U_NTT(S1);                                              //  405
      7'd14: prog_en = U_PWM(S7, S7, S0, 1'b0);                                //  405 V  = t0 y0
      7'd15: prog_en = U_XOF(S3, E5, 8'd0, 8'd0);                              //  423 A[0][0]
      7'd16: prog_en = U_DEC(S11, 1'b0, W_M, E0, 4'd1, 1'b0, 1'b1, 1'b1);      //  423 e2 + mu
      7'd17: prog_en = U_XOF(S4, E5, 8'd0, 8'd1);                              //  487 A[1][0]
      7'd18: prog_en = U_PWM(S3, S3, S0, 1'b0);                                //  487 U0 = A00 y0
      7'd19: prog_en = U_NTT(S2);                                              //  546
      7'd20: prog_en = U_XOF(S5, E5, 8'd0, 8'd2);                              //  551 A[2][0]
      7'd21: prog_en = U_PWM(S3, S4, S1, 1'b1);                                //  551 U0 += A10 y1
      7'd22: prog_en = U_PWM(S7, S8, S1, 1'b1);                                //  595 V  += t1 y1
      7'd23: prog_en = U_CBD(S6, E1, 8'd3);                                    //  615 e1[0]
      7'd24: prog_en = U_XOF(S10, E5, 8'd1, 8'd0);                             //  668 A[0][1]
      7'd25: prog_en = U_PWM(S3, S5, S2, 1'b1);                                //  687 U0 += A20 y2
      7'd26: prog_en = U_INTT_ADD(S3, S6);                                     //  731 u0 = INTT(U0) + e1[0]
      7'd27: prog_en = U_PWM(S7, S9, S2, 1'b1);                                //  731 V  += t2 y2
      7'd28: prog_en = U_XOF(S4, E5, 8'd1, 8'd1);                              //  732 A[1][1]
      7'd29: prog_en = U_PWM(S10, S10, S0, 1'b0);                              //  775 U1 = A01 y0
      7'd30: prog_en = U_XOF(S5, E5, 8'd1, 8'd2);                              //  796 A[2][1]
      7'd31: prog_en = U_PWM(S10, S4, S1, 1'b1);                               //  819 U1 += A11 y1
      7'd32: prog_en = U_CBD(S8, E1, 8'd4);                                    //  860 e1[1]
      7'd33: prog_en = U_PWM(S10, S5, S2, 1'b1);                               //  863 U1 += A21 y2
      7'd34: prog_en = U_ENC(S3, K_MB, W_CT, 11'd0, E0, 4'd10, 1'b1);          //  872 c: u0
      7'd35: prog_en = U_INTT_ADD(S7, S11);                                    //  872 v = INTT(V) + e2 + mu
      7'd36: prog_en = U_XOF(S9, E5, 8'd2, 8'd0);                              //  913 A[0][2]
      7'd37: prog_en = U_XOF(S4, E5, 8'd2, 8'd1);                              //  977 A[1][2]
      7'd38: prog_en = U_PWM(S9, S9, S0, 1'b0);                                //  977 U2 = A02 y0
      7'd39: prog_en = U_INTT_ADD(S10, S8);                                    // 1013 u1
      7'd40: prog_en = U_ENC(S7, K_MB, W_CT_V, 11'd0, E0, 4'd4, 1'b1);         // 1013 c: v
      7'd41: prog_en = U_XOF(S5, E5, 8'd2, 8'd2);                              // 1041 A[2][2]
      7'd42: prog_en = U_PWM(S9, S4, S1, 1'b1);                                // 1041 U2 += A12 y1
      7'd43: prog_en = U_CBD(S6, E1, 8'd5);                                    // 1105 e1[2]
      7'd44: prog_en = U_PWM(S9, S5, S2, 1'b1);                                // 1105 U2 += A22 y2
      7'd45: prog_en = U_ENC(S10, K_MB, W_CT_U1, 11'd0, E0, 4'd10, 1'b1);      // 1154 c: u1
      7'd46: prog_en = U_INTT_ADD(S9, S6);                                     // 1158 u2
      7'd47: prog_en = U_ENC(S9, K_MB, W_CT_U2, 11'd0, E0, 4'd10, 1'b1);       // 1299 c: u2
      7'd48: prog_en = U_END(4'd0);
      7'd49: prog_en = U_END(4'd1);                                            // EN_FAIL
      default: prog_en = U_END(4'hF);
    endcase
  endfunction

  // --- Decaps: (dk, c) -> K -----------------------------------------------------------
  // Decrypt: u' S3-S5 (NTT), s-hat S0-S2, W in S6 -> w, v' S11. While the IO
  // engine decodes, the Keccak engine (idle after H and J) already samples
  // A[0][0] A[1][0] A[2][0] A[0][1] for the re-encryption into S7-S10.
  // Re-encryption: y-hat S0-S2, t-hat S3-S5 (V accumulates in S3), u0 in S7,
  // u1 in S10, u2 in S5, e1 in S6 S9 S6, e2 + mu in S11; c' is compared with c.
  // ~2,070 clocks (v2: 4,737).
  function [79:0] prog_de(input [6:0] k);
    case (k)
      7'd0:  prog_de = U_SHA3_256(L_DKEK, 8'd148, E2);                         //    0 H(ek) (check)
      7'd1:  prog_de = U_WOP(I_M2S, W_DKEK_RHO, 11'd0, E5, E0, 4'd8, 1'b0);    //    0 rho
      7'd2:  prog_de = U_DEC(S3, 1'b0, W_CT,    E0, 4'd10, 1'b0, 1'b1, 1'b0);  //   10 u'0
      7'd3:  prog_de = U_DEC(S0, 1'b0, W_DK,    E0, 4'd12, 1'b0, 1'b0, 1'b0);  //   95 s0
      7'd4:  prog_de = U_NTT(S3);                                              //   95
      7'd5:  prog_de = U_SHAKE_J(L_DK_Z, L_CT, 8'd136, E4);                    //  180 K-bar
      7'd6:  prog_de = U_DEC(S4, 1'b0, W_CT_U1, E0, 4'd10, 1'b0, 1'b1, 1'b0);  //  195 u'1
      7'd7:  prog_de = U_PWM(S6, S3, S0, 1'b0);                                //  236 W  = u'0 s0
      7'd8:  prog_de = U_DEC(S1, 1'b0, W_DK_S1, E0, 4'd12, 1'b0, 1'b0, 1'b0);  //  280 s1
      7'd9:  prog_de = U_NTT(S4);                                              //  280
      7'd10: prog_de = U_XOF(S7, E5, 8'd0, 8'd0);                              //  360 A[0][0]
      7'd11: prog_de = U_DEC(S5, 1'b0, W_CT_U2, E0, 4'd10, 1'b0, 1'b1, 1'b0);  //  380 u'2
      7'd12: prog_de = U_PWM(S6, S4, S1, 1'b1);                                //  421 W += u'1 s1
      7'd13: prog_de = U_XOF(S8, E5, 8'd0, 8'd1);                              //  424 A[1][0]
      7'd14: prog_de = U_DEC(S2, 1'b0, W_DK_S2, E0, 4'd12, 1'b0, 1'b0, 1'b0);  //  465 s2
      7'd15: prog_de = U_NTT(S5);                                              //  465
      7'd16: prog_de = U_XOF(S9, E5, 8'd0, 8'd2);                              //  488 A[2][0]
      7'd17: prog_de = U_XOF(S10, E5, 8'd1, 8'd0);                             //  552 A[0][1]
      7'd18: prog_de = U_DEC(S11, 1'b0, W_CT_V, E0, 4'd4, 1'b0, 1'b1, 1'b0);   //  565 v'
      7'd19: prog_de = U_PWM(S6, S5, S2, 1'b1);                                //  606 W += u'2 s2
      7'd20: prog_de = U_WOP(I_CMP, W_DK_H, 11'd0, E2, E0, 4'd8, 1'b0);        //  635 H(ek) = h ?
      7'd21: prog_de = U_BR(DE_FAIL);                                          //  645
      7'd22: prog_de = U_INTT_RSUB(S6, S11);                                   //  650 w = v' - INTT(W)
      7'd23: prog_de = U_ENC(S6, K_SEED, 11'd0, 11'd0, E3, 4'd1, 1'b1);        //  791 m' -> E3
      7'd24: prog_de = U_SHA3_512(1'b1, {7'd0, E3}, 1'b0, L_DK_H, 8'd4, 2'd0, 16'd0, E0, E1); // 861 (K', r')
      7'd25: prog_de = U_DEC(S3, 1'b0, W_DKEK,    E0, 4'd12, 1'b0, 1'b0, 1'b0); // 861 t0
      7'd26: prog_de = U_CBD(S0, E1, 8'd0);                                    //  892 y0
      7'd27: prog_de = U_CBD(S1, E1, 8'd1);                                    //  945 y1
      7'd28: prog_de = U_NTT(S0);                                              //  945
      7'd29: prog_de = U_DEC(S4, 1'b0, W_DKEK_T1, E0, 4'd12, 1'b0, 1'b0, 1'b0); // 961 t1
      7'd30: prog_de = U_CBD(S2, E1, 8'd2);                                    //  998 y2
      7'd31: prog_de = U_CBD(S11, E1, 8'd6);                                   // 1051 e2
      7'd32: prog_de = U_DEC(S5, 1'b0, W_DKEK_T2, E0, 4'd12, 1'b0, 1'b0, 1'b0); // 1061 t2
      7'd33: prog_de = U_NTT(S1);                                              // 1086
      7'd34: prog_de = U_PWM(S7, S7, S0, 1'b0);                                // 1086 U0 = A00 y0
      7'd35: prog_de = U_CBD(S6, E1, 8'd3);                                    // 1104 e1[0]
      7'd36: prog_de = U_PWM(S3, S3, S0, 1'b0);                                // 1130 V  = t0 y0
      7'd37: prog_de = U_DEC(S11, 1'b1, W_M, E3, 4'd1, 1'b0, 1'b1, 1'b1);      // 1161 e2 + mu (m' in E3)
      7'd38: prog_de = U_PWM(S10, S10, S0, 1'b0);                              // 1174 U1 = A01 y0
      7'd39: prog_de = U_NTT(S2);                                              // 1227
      7'd40: prog_de = U_PWM(S7, S8, S1, 1'b1);                                // 1227 U0 += A10 y1
      7'd41: prog_de = U_XOF(S8, E5, 8'd1, 8'd1);                              // 1271 A[1][1]
      7'd42: prog_de = U_PWM(S3, S4, S1, 1'b1);                                // 1271 V  += t1 y1
      7'd43: prog_de = U_XOF(S4, E5, 8'd1, 8'd2);                              // 1335 A[2][1]
      7'd44: prog_de = U_PWM(S7, S9, S2, 1'b1);                                // 1368 U0 += A20 y2
      7'd45: prog_de = U_INTT_ADD(S7, S6);                                     // 1412 u0
      7'd46: prog_de = U_PWM(S3, S5, S2, 1'b1);                                // 1412 V  += t2 y2
      7'd47: prog_de = U_CBD(S9, E1, 8'd4);                                    // 1412 e1[1]
      7'd48: prog_de = U_PWM(S10, S8, S1, 1'b1);                               // 1456 U1 += A11 y1
      7'd49: prog_de = U_XOF(S5, E5, 8'd2, 8'd0);                              // 1465 A[0][2]
      7'd50: prog_de = U_PWM(S10, S4, S2, 1'b1);                               // 1500 U1 += A21 y2
      7'd51: prog_de = U_XOF(S8, E5, 8'd2, 8'd1);                              // 1529 A[1][2]
      7'd52: prog_de = U_PWM(S5, S5, S0, 1'b0);                                // 1544 U2 = A02 y0
      7'd53: prog_de = U_ENC(S7, K_CMP, W_CT, 11'd0, E0, 4'd10, 1'b1);         // 1553 u0 vs c
      7'd54: prog_de = U_INTT_ADD(S10, S9);                                    // 1553 u1
      7'd55: prog_de = U_XOF(S4, E5, 8'd2, 8'd2);                              // 1593 A[2][2]
      7'd56: prog_de = U_PWM(S5, S8, S1, 1'b1);                                // 1593 U2 += A12 y1
      7'd57: prog_de = U_CBD(S6, E1, 8'd5);                                    // 1657 e1[2]
      7'd58: prog_de = U_PWM(S5, S4, S2, 1'b1);                                // 1657 U2 += A22 y2
      7'd59: prog_de = U_ENC(S10, K_CMP, W_CT_U1, 11'd0, E0, 4'd10, 1'b1);     // 1694 u1 vs c
      7'd60: prog_de = U_INTT_ADD(S5, S6);                                     // 1710 u2
      7'd61: prog_de = U_INTT_ADD(S3, S11);                                    // 1851 v
      7'd62: prog_de = U_ENC(S5, K_CMP, W_CT_U2, 11'd0, E0, 4'd10, 1'b1);      // 1851 u2 vs c
      7'd63: prog_de = U_ENC(S3, K_CMP, W_CT_V, 11'd0, E0, 4'd4, 1'b1);        // 1992 v vs c
      7'd64: prog_de = U_WOP(I_SEL, W_SS, 11'd0, E0, E4, 4'd8, 1'b0);          // K = c == c' ? K' : K-bar
      7'd65: prog_de = U_END(4'd0);
      7'd66: prog_de = U_WOP(I_ZERO, W_SS, 11'd0, E0, E0, 4'd8, 1'b0);         // DE_FAIL
      7'd67: prog_de = U_END(4'd1);
      default: prog_de = U_END(4'hF);
    endcase
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
