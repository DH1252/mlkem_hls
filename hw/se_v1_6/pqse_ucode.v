// -----------------------------------------------------------------------------
// pqse_ucode.v - microcode ROM of the PQSE secure element v1.5 (96-bit words,
// 10-bit program counter; the programs use addresses 0 .. 500).
//
// The sequencer (pqse_core.v) runs one instruction at a time and waits for it
// to finish (one engine active at a time: smallest area, lowest peak power).
// Programs sit in segments at fixed addresses; unused addresses return
// END R_UNKNOWN.
//
// v1.5: ML-KEM-512, -768 and -1024 run the same programs. A vector of k
// polynomials is a loop (C_LOOP, counters i and j, limit k): the sequencer
// translates the logical slot codes (L_SI0 = share 0 of s^_i, L_YJ1 = share 1
// of y_j, ...), the d codes (D_DU, D_DV), buffer address modes (AM_*) and HASH
// modes (HM_*) of each instruction for the command's k (pqse_core.v). The
// table below is laid out by scripts/pqse_ucode_v15_gen.py (labels resolved
// to addresses; edit the program there and rerun it); v4's unrolled
// ML-KEM-768 programs took 793 words.
//
// Every secret is first-order masked from the moment it exists:
//   - TRNG seeds (d, z, m) are conditioned by the masked sponge and come out
//     as two Boolean shares
//   - s, e, y, e1, e2: the masked sponge writes the PRF output (both shares)
//     into the scratch seed entries E_CBD (10..15), then the masked CBD turns
//     it into arithmetic shares in random word order, so the NTT, PWM and
//     INTT run on each share separately
//   - G, PRF, J, KDF, KMAC (keystream, tags) run on the masked sponge
//   - the public results (t^, rho, the ciphertext, tags) are unmasked only at
//     the very end: t^ by adding its two shares, the ciphertext by the masked
//     compression (pqse_mcomp.v, mode 2)
// With hiding on, the sequencer draws a fresh Fisher-Yates permutation
// (pqse_perm.v) before every NTT / INTT / PWM / ADD / MSPLIT / Compress / mu /
// CBD instruction, which then runs its words in that order (the NTT / INTT
// draw a fresh order for every butterfly layer in the background).
//
//   0..8     failure exits (8: a KeyGen recompute check failed, result FAULT)
//   16       KEYGEN / KGWRAP: seeds from the TRNG (or injected in TEST); KGWRAP
//            first reconstructs the PUF key and derives the KEK (48)
//   32       UNWRAP: PUF -> KEK (48), tag check (masked), decrypt d, z (masked)
//   48       PUF key + check value (+ majority retries) -> KEK
//   80       KeyGen (masked): G(d || k); s_i, e_i each produced twice and
//            compared (PRF, masked CBD, NTT; SUB per share, ZCHK); G again
//            (XOR, must be 0); t^_i = e^_i + sum_j A^[i][j] o s^_j per share,
//            unmasked and encoded; H(ek); PCT (448); wrap (KGWRAP); wipe
//   160      ENCAPS (masked). The ciphertext goes over the peer ek in B_XIN:
//            the ek is checked and hashed, its rho copied to B_TMP, then v is
//            computed first (it reads t^ from the ek) and c2 written, then the
//            u_i and c1 (pqse_defs.vh)
//   240      DECAPS (masked; m' decoded twice and compared, ok copies
//            compared; K kept as the session key); key_k sets k
//   320      SEAL: secure message with the session key
//   352      OPEN
//   384      IMPORT (TEST/PERSO): s^ bytes + ek + H(ek) + z; the s^ bytes in
//            B_XIN are wiped afterwards
//   400      ENROLL (TEST/PERSO); 408 PUFRAW, 410 TRNGRAW (TEST, into B_XIN)
//   416      ZEROIZE
//   448      KeyGen pairwise consistency test (KEYGEN / KGWRAP, not UNWRAP):
//            a masked Encaps of a fresh random m to the new ek (the test
//            ciphertext into B_XIN), a Decaps of it with the new s^, K and K'
//            compared share-wise (IO_SEQ): a mismatch aborts with FAULT
//
// PUF key reconstruction, the session key and secure messaging are as in v4
// (hw/se/pqse_ucode.v).
// -----------------------------------------------------------------------------
module pqse_ucode (
  input  wire        clk,
  input  wire        en,         // read: q <= ROM[pc], one clock later
  input  wire [9:0]  pc,
  output reg  [95:0] q
);
  `include "pqse_defs.vh"

  // the table below (combinational) followed by the output register: synthesis
  // maps the pair to a ROM block (FPGA block RAM) instead of logic
  reg [95:0] ins;
  always @(posedge clk) if (en) q <= ins;

  // ---- instruction builders --------------------------------------------------------
  function [95:0] u_end(input [7:0] r);
    u_end = {C_END, 84'd0, r};
  endfunction
  function [95:0] u_br(input [3:0] c, input [9:0] t);
    u_br = {C_BR, c, t, 78'd0};
  endfunction
  // loop over i (w = 0) or j (w = 1) up to k (u_loop) or up to n (u_loopn)
  function [95:0] u_loop(input w, input [9:0] t);
    u_loop = {C_LOOP, w, 1'b0, 2'd0, t, 4'd0, 74'd0};
  endfunction
  function [95:0] u_loopn(input w, input [9:0] t, input [3:0] n);
    u_loopn = {C_LOOP, w, 1'b1, 2'd0, t, n, 74'd0};
  endfunction
  function [95:0] u_set(input [3:0] o);
    u_set = {C_SET, o, 88'd0};
  endfunction
  function [95:0] u_poly(input [3:0] o, input acc, input [3:0] c, input [3:0] a, input [3:0] b);
    u_poly = {C_POLY, o, acc, c, a, b, 1'b1, 74'd0};
  endfunction
  // [58]: slot bit 4 (pqse_core.v), [57:55]: buffer address mode
  function [95:0] u_io(input [3:0] o, input [1:0] dm, input [3:0] d, input cmp, input mchk,
                       input [8:0] ba, input [3:0] sl, input [3:0] e, input [3:0] e2,
                       input [2:0] am);
    u_io = {C_IO, o, dm, d, cmp, mchk, ba, sl, e, e2, 1'b0, am, 55'd0};
  endfunction
  // [56:55]: slot bits 4 (pqse_core.v), [54:52]: buffer address mode, [51]: CBD
  // with eta1 (eta 3 when k = 2), [50]: eta 3 (pqse_core.v)
  function [95:0] u_mask(input [3:0] o, input [3:0] d, input [3:0] sh0, input [3:0] sh1, input ng,
                         input [8:0] ba, input [3:0] e, input [3:0] e2, input acc,
                         input [2:0] am, input e1);
    u_mask = {C_MASK, o, d, sh0, sh1, ng, ba, e, e2, acc, 2'b00, am, e1, 51'd0};
  endfunction
  function [95:0] u_puf(input [3:0] o, input [3:0] e, input [8:0] hb);
    u_puf = {C_PUF, o, e, hb, 75'd0};
  endfunction
  // the os2 field [7:4] carries the HASH index mode (HM_*)
  function [95:0] u_hash(input [1:0] rate, input shake, input msk,
                         input [1:0] p1s, input [8:0] p1a, input [7:0] p1n,
                         input [1:0] p2s, input [8:0] p2a, input [7:0] p2n,
                         input [1:0] sfn, input [15:0] sfx, input [2:0] sink,
                         input [3:0] oe0, input [3:0] oe1, input [7:0] onl,
                         input [3:0] os, input [3:0] hm, input acc);
    u_hash = {C_HASH, rate, shake, msk, p1s, 1'b0, p1a, p1n, p2s, p2a, p2n, sfn, sfx,
              sink, oe0, oe1, onl, os, hm, acc, 3'd0};
  endfunction
  // KMAC256 job (pqse_sponge.v): J[2] = 1, J[1:0] = customization string,
  // J[85] = 1: KMACXOF256
  function [95:0] u_kmac(input [95:0] h, input xof, input [1:0] cs);
    u_kmac = {h[95:86], xof, h[84:3], 1'b1, cs};
  endfunction

  // ---- short forms ---------------------------------------------------------------------
  function [8:0] sa(input [3:0] e);            // seed entry as a part address
    sa = {3'd0, e, 2'd0};
  endfunction
  // SHA3-256(64 TRNG bytes) -> entry, masked (seed conditioning)
  function [95:0] h_trng(input [3:0] oe);
    h_trng = u_hash(RATE_136, 1'b0, 1'b1, SRC_TRNG, 9'd0, 8'd8, SRC_NONE, 9'd0, 8'd0,
                    2'd0, 16'd0, SNK_SEED, oe, 4'd0, 8'd4, 4'd0, HM_NONE, 1'b0);
  endfunction
  // H(ek) = SHA3-256 of an ek in the buffer (48 k + 4 lanes) -> entry
  function [95:0] h_hek(input [8:0] ba, input [3:0] oe);
    h_hek = u_hash(RATE_136, 1'b0, 1'b0, SRC_BUF, ba, 8'd0, SRC_NONE, 9'd0, 8'd0,
                   2'd0, 16'd0, SNK_SEED, oe, 4'd0, 8'd4, 4'd0, HM_HEK, 1'b0);
  endfunction
  // G = SHA3-512(e1 || e2) -> oe0 (32 bytes), oe1 (32 bytes), masked
  function [95:0] h_g(input [3:0] e1, input [3:0] e2, input [3:0] oe0, input [3:0] oe1);
    h_g = u_hash(RATE_72, 1'b0, 1'b1, SRC_SEED, sa(e1), 8'd4, SRC_SEED, sa(e2), 8'd4,
                 2'd0, 16'd0, SNK_SEED, oe0, oe1, 8'd8, 4'd0, HM_NONE, 1'b0);
  endfunction
  // (rho, sigma) = G(d || k) -> E_RHO, E_R (SNK_SEED), or XORed into them
  // (SNK_SXOR: the KeyGen check, both 0 if it agrees)
  function [95:0] h_gk(input [2:0] sink);
    h_gk = u_hash(RATE_72, 1'b0, 1'b1, SRC_SEED, sa(E_D), 8'd4, SRC_NONE, 9'd0, 8'd0,
                  2'd1, 16'd0, sink, E_RHO, E_R, 8'd8, 4'd0, HM_GK, 1'b0);
  endfunction
  // PRF_eta(e, nonce) = SHAKE256(e || nonce), 128 bytes (eta 2) or 192 (eta 3),
  // masked -> scratch entries E_CBD..; the mode picks the nonce and eta
  function [95:0] h_prf(input [3:0] e, input [7:0] n, input [3:0] hm);
    h_prf = u_hash(RATE_136, 1'b1, 1'b1, SRC_SEED, sa(e), 8'd4, SRC_NONE, 9'd0, 8'd0,
                   2'd1, {8'd0, n}, SNK_SEED, E_CBD, E_CBD + 4'd1, 8'd16, 4'd0, hm, 1'b0);
  endfunction
  // masked SamplePolyCBD of the PRF output in E_CBD -> slots os (share 0), os2
  // (share 1), random word order; acc: add to the slots; e1: eta1 (3 when k = 2)
  function [95:0] cbd(input [3:0] os, input [3:0] os2, input acc, input e1);
    cbd = u_mask(M_CBD, 4'd0, os, os2, 1'b0, 9'd0, E_CBD, 4'd0, acc, AM_NONE, e1);
  endfunction
  // XOF(rho || b0 || b1) -> SampleNTT into slot os; rho is public (buffer); the
  // mode puts (j, i) or (i, j) into the two bytes
  function [95:0] h_xof(input [8:0] a, input [3:0] hm, input [3:0] os);
    h_xof = u_hash(RATE_168, 1'b1, 1'b0, SRC_BUF, a, 8'd4, SRC_NONE, 9'd0, 8'd0,
                   2'd2, 16'd0, SNK_SNTT, 4'd0, 4'd0, 8'd0, os, hm, 1'b0);
  endfunction
  // KEK = SHA3-256(k_PUF || "K"), masked
  function [95:0] h_kek(input dummy);
    h_kek = u_hash(RATE_136, 1'b0, 1'b1, SRC_SEED, sa(E_PUF), 8'd4, SRC_NONE, 9'd0, 8'd0,
                   2'd1, 16'h004B, SNK_SEED, E_KEK, 4'd0, 8'd4, 4'd0, HM_NONE, 1'b0);
  endfunction
  // PUF key check value = SHA3-256(k_PUF || "C"), first lane only, masked -> entry oe
  function [95:0] h_kchk(input [3:0] e, input [3:0] oe);
    h_kchk = u_hash(RATE_136, 1'b0, 1'b1, SRC_SEED, sa(e), 8'd4, SRC_NONE, 9'd0, 8'd0,
                    2'd1, 16'h0043, SNK_SEED, oe, 4'd0, 8'd1, 4'd0, HM_NONE, 1'b0);
  endfunction
  // blob tag = SHA3-256(KEK || nonce || ct), masked; sink SEED (wrap) or MCMP (unwrap)
  function [95:0] h_tag(input [2:0] sink);
    h_tag = u_hash(RATE_136, 1'b0, 1'b1, SRC_SEED, sa(E_KEK), 8'd4, SRC_BUF, B_BLOB, 8'd10,
                   2'd0, 16'd0, sink, E_TAG, 4'd0, 8'd4, 4'd0, HM_NONE, 1'b0);
  endfunction
  // blob keystream = SHAKE256(KEK || nonce, 64 bytes), masked, XORed into oe0 | oe1
  function [95:0] h_ks(input [3:0] oe0, input [3:0] oe1);
    h_ks = u_hash(RATE_136, 1'b1, 1'b1, SRC_SEED, sa(E_KEK), 8'd4, SRC_BUF, B_BLOB_NONCE, 8'd2,
                  2'd0, 16'd0, SNK_SXOR, oe0, oe1, 8'd8, 4'd0, HM_NONE, 1'b0);
  endfunction
  // message keystream = KMACXOF256(SK, H, 1024 bits, "E1" / "E2"), masked; the
  // sink XORs it into the 16 message lanes
  function [95:0] h_kks(input [1:0] cs);
    h_kks = u_kmac(u_hash(RATE_136, 1'b1, 1'b1, SRC_SEED, sa(E_SK), 8'd4, SRC_BUF, B_SM_HDR, 8'd4,
                          2'd0, 16'd0, SNK_BXOR, 4'd0, 4'd0, 8'd16, 4'd0, HM_NONE, 1'b0),
                   1'b1, cs);
  endfunction
  // message tag = KMAC256(SK, H || C, 256, "T1" / "T2"), masked; sink SEED (SEAL,
  // -> E_TAG) or MCMP (OPEN: compared with the received tag, acc = 1)
  function [95:0] h_ktag(input [2:0] sink, input [1:0] cs);
    h_ktag = u_kmac(u_hash(RATE_136, 1'b0, 1'b1, SRC_SEED, sa(E_SK), 8'd4, SRC_BUF, B_SM, 8'd20,
                           2'd0, 16'd0, sink, E_TAG, 4'd0, 8'd4, 4'd0, HM_NONE,
                           (sink == SNK_MCMP)),
                    1'b0, cs);
  endfunction
  // K-bar = J(z || c) = SHAKE256(z || c, 32), masked; c is DU k + DV lanes
  function [95:0] h_j(input dummy);
    h_j = u_hash(RATE_136, 1'b1, 1'b1, SRC_SEED, sa(E_Z), 8'd4, SRC_BUF, B_XIN, 8'd0,
                 2'd0, 16'd0, SNK_SEED, E_KB, 4'd0, 8'd4, 4'd0, HM_JC, 1'b0);
  endfunction

  function [95:0] pwm(input acc, input [3:0] c, input [3:0] a, input [3:0] b);
    pwm = u_poly(P_PWM, acc, c, a, b);
  endfunction
  function [95:0] ntt(input [3:0] c);
    ntt = u_poly(P_NTT, 1'b0, c, 4'd0, 4'd0);
  endfunction
  function [95:0] intt(input [3:0] c);
    intt = u_poly(P_INTT, 1'b0, c, 4'd0, 4'd0);
  endfunction
  function [95:0] pzero(input [3:0] c);
    pzero = u_poly(P_ZERO, 1'b0, c, 4'd0, 4'd0);
  endfunction
  function [95:0] padd(input [3:0] c, input [3:0] a);
    padd = u_poly(P_ADD, 1'b0, c, a, 4'd0);
  endfunction
  function [95:0] psub(input [3:0] c, input [3:0] a);
    psub = u_poly(P_SUB, 1'b0, c, a, 4'd0);
  endfunction
  // FAULT unless c + a = 0 mod q everywhere (pqse_poly ZCHK); not shuffled
  function [95:0] pzchk(input [3:0] c, input [3:0] a);
    pzchk = {C_POLY, P_ZCHK, 1'b0, c, a, 4'd0, 1'b0, 74'd0};
  endfunction
  function [95:0] msplit(input [3:0] c, input [3:0] a);
    msplit = u_poly(P_MSPLIT, 1'b0, c, a, 4'd0);
  endfunction
  // decode d bits (d = 12, D_DU or D_DV) from buffer lane ba (+ mode) into slot sl
  function [95:0] dec(input [1:0] dm, input [3:0] d, input mchk, input [8:0] ba, input [3:0] sl,
                      input [2:0] am);
    dec = u_io(IO_DEC, dm, d, (d != 4'd12), mchk, ba, sl, 4'd0, 4'd0, am);
  endfunction
  function [95:0] enc12(input [3:0] sl, input [8:0] ba, input [2:0] am);
    enc12 = u_io(IO_ENC, DM_WR, 4'd12, 1'b0, 1'b0, ba, sl, 4'd0, 4'd0, am);
  endfunction
  function [95:0] s2b(input [3:0] e, input [8:0] ba, input [2:0] am);          // 4 lanes
    s2b = u_io(IO_S2B, DM_WR, 4'd0, 1'b0, 1'b0, ba, 4'd0, e, 4'd0, am);
  endfunction
  function [95:0] s2bn(input [3:0] e, input [8:0] ba, input [3:0] n);          // lanes 0..n-1
    s2bn = u_io(IO_S2B, DM_WR, n, 1'b0, 1'b0, ba, 4'd0, e, 4'd0, AM_NONE);
  endfunction
  function [95:0] b2s(input [8:0] ba, input [3:0] e, input [2:0] am);
    b2s = u_io(IO_B2S, DM_WR, 4'd0, 1'b0, 1'b0, ba, 4'd0, e, 4'd0, am);
  endfunction
  function [95:0] s2s(input [3:0] e, input [3:0] e2);
    s2s = u_io(IO_S2S, DM_WR, 4'd0, 1'b0, 1'b0, 9'd0, 4'd0, e, e2, AM_NONE);
  endfunction
  function [95:0] szero(input [3:0] e);
    szero = u_io(IO_SZERO, DM_WR, 4'd0, 1'b0, 1'b0, 9'd0, 4'd0, e, 4'd0, AM_NONE);
  endfunction
  function [95:0] sremask(input [3:0] e);
    sremask = u_io(IO_SREMASK, DM_WR, 4'd0, 1'b0, 1'b0, 9'd0, 4'd0, e, 4'd0, AM_NONE);
  endfunction
  function [95:0] scmpn(input [3:0] e, input [8:0] ba, input [3:0] n, input [2:0] am); // n = 0: 4 lanes
    scmpn = u_io(IO_SCMP, DM_WR, n, 1'b0, 1'b0, ba, 4'd0, e, 4'd0, am);
  endfunction
  function [95:0] seq(input [3:0] e, input [3:0] e2);         // FAULT if e != e2 (masked)
    seq = u_io(IO_SEQ, DM_WR, 4'd0, 1'b0, 1'b0, 9'd0, 4'd0, e, e2, AM_NONE);
  endfunction
  function [95:0] trunc(input chk);                            // chk: length check only
    trunc = u_io(IO_TRUNC, DM_WR, 4'd0, chk, 1'b0, B_SM_MSG, 4'd0, 4'd0, 4'd0, AM_NONE);
  endfunction
  function [95:0] ctr(input [3:0] o);                          // IO_CTRW / IO_CTRC
    ctr = u_io(o, DM_WR, 4'd0, 1'b0, 1'b0, B_SM_HDR, 4'd0, 4'd0, 4'd0, AM_NONE);
  endfunction
  function [95:0] m_op(input [3:0] o);          // OKINI / OKOUT / OKCHK
    m_op = u_mask(o, 4'd0, 4'd0, 4'd0, 1'b0, 9'd0, 4'd0, 4'd0, 1'b0, AM_NONE, 1'b0);
  endfunction
  function [95:0] cmprc(input [3:0] d, input [8:0] ba, input [2:0] am);   // compare with the ciphertext
    cmprc = u_mask(M_CMPRC, d, L_ACC0, L_ACC1, 1'b0, ba, 4'd0, 4'd0, 1'b0, am, 1'b0);
  endfunction
  function [95:0] cmpro(input [3:0] d, input [8:0] ba, input [2:0] am);   // write the ciphertext
    cmpro = u_mask(M_CMPRO, d, L_ACC0, L_ACC1, 1'b0, ba, 4'd0, 4'd0, 1'b0, am, 1'b0);
  endfunction
  function [95:0] cmpr1(input [3:0] e);                   // m' = Compress_1(w) -> entry e
    cmpr1 = u_mask(M_CMPR1, 4'd1, L_ACC0, L_ACC1, 1'b1, 9'd0, e, 4'd0, 1'b0, AM_NONE, 1'b0);
  endfunction
  function [95:0] mu(input [3:0] e);                      // + Decompress_1(m)
    mu = u_mask(M_MU, 4'd0, L_ACC0, L_ACC1, 1'b0, 9'd0, e, 4'd0, 1'b1, AM_NONE, 1'b0);
  endfunction

  always @* begin
    case (pc)
      // ---- generated by scripts/pqse_ucode_v15_gen.py: begin ----
      10'd0:    ins = u_end(R_BADIN);
      10'd1:    ins = u_end(R_NOKEY);
      10'd2:    ins = u_end(R_BADBLOB);
      10'd3:    ins = u_end(R_DENIED);
      10'd4:    ins = u_end(R_BADTAG);
      10'd5:    ins = u_end(R_NOSK);
      10'd6:    ins = u_end(R_REPLAY);
      10'd7:    ins = u_end(R_PUF);
      10'd8:    ins = u_end(R_FAULT);                                                // X_KGF: a KeyGen recompute check failed
      10'd16:   ins = u_set(ST_RESEED);
      10'd17:   ins = u_br(BC_WRAP, 10'd48);                                         // KGWRAP: KEK first (no key yet if it fails)
      10'd18:   ins = u_br(BC_INJ, 10'd22);
      10'd19:   ins = h_trng(E_D);
      10'd20:   ins = h_trng(E_Z);
      10'd21:   ins = u_br(BC_ALWAYS, 10'd80);
      10'd22:   ins = b2s(B_INJD, E_D, AM_NONE);                                     // TEST: injected d, z
      10'd23:   ins = sremask(E_D);
      10'd24:   ins = b2s(B_INJZ, E_Z, AM_NONE);
      10'd25:   ins = sremask(E_Z);
      10'd26:   ins = u_br(BC_ALWAYS, 10'd80);
      10'd32:   ins = u_set(ST_RESEED);
      10'd33:   ins = u_br(BC_ALWAYS, 10'd48);                                       // PUF key -> KEK, back to L_UWK
      10'd34:   ins = m_op(M_OKINI);
      10'd35:   ins = h_tag(SNK_MCMP);                                               // masked tag check
      10'd36:   ins = m_op(M_OKCHK);                                                 // the two ok copies must agree
      10'd37:   ins = m_op(M_OKOUT);
      10'd38:   ins = u_br(BC_BAD, 10'd44);
      10'd39:   ins = b2s(B_BLOB_CT, E_D, AM_NONE);
      10'd40:   ins = b2s(B_BLOB_CT + 9'd4, E_Z, AM_NONE);
      10'd41:   ins = h_ks(E_D, E_Z);                                                // d, z now masked plaintext
      10'd42:   ins = szero(E_KEK);
      10'd43:   ins = u_br(BC_ALWAYS, 10'd80);
      10'd44:   ins = szero(E_KEK);
      10'd45:   ins = u_br(BC_ALWAYS, 10'd2);
      10'd48:   ins = u_puf(PF_RECON, E_PUF, B_HELP);                                // one read per bit
      10'd49:   ins = h_kchk(E_PUF, E_TMP);
      10'd50:   ins = scmpn(E_TMP, B_HELP_CHK, 4'd1, AM_NONE);                       // 64-bit check value
      10'd51:   ins = u_br(BC_NBAD, 10'd62);
      10'd52:   ins = u_set(ST_BADC);
      10'd53:   ins = u_puf(PF_RECON3, E_PUF, B_HELP);                               // retry: majority of 3 reads
      10'd54:   ins = h_kchk(E_PUF, E_TMP);
      10'd55:   ins = scmpn(E_TMP, B_HELP_CHK, 4'd1, AM_NONE);
      10'd56:   ins = u_br(BC_NBAD, 10'd62);
      10'd57:   ins = u_set(ST_BADC);
      10'd58:   ins = u_puf(PF_RECON5, E_PUF, B_HELP);                               // retry: majority of 5 reads
      10'd59:   ins = h_kchk(E_PUF, E_TMP);
      10'd60:   ins = scmpn(E_TMP, B_HELP_CHK, 4'd1, AM_NONE);
      10'd61:   ins = u_br(BC_BAD, 10'd67);
      10'd62:   ins = szero(E_TMP);
      10'd63:   ins = h_kek(1'b0);
      10'd64:   ins = szero(E_PUF);
      10'd65:   ins = u_br(BC_WRAP, 10'd18);                                         // KGWRAP: on to KeyGen
      10'd66:   ins = u_br(BC_ALWAYS, 10'd34);                                       // UNWRAP: on to the tag check
      10'd67:   ins = szero(E_PUF);
      10'd68:   ins = szero(E_TMP);
      10'd69:   ins = u_br(BC_ALWAYS, 10'd7);
      10'd80:   ins = h_gk(SNK_SEED);                                                // (rho, sigma) = G(d || k) -> E_RHO, E_R
      10'd81:   ins = s2b(E_RHO, B_EKOWN, AM_48K);                                   // rho is public: after t^ in the own ek
      10'd82:   ins = s2b(E_RHO, B_TMP, AM_NONE);                                    // ... and where the XOF reads it
      10'd83:   ins = szero(E_KB);                                                   // all-zero reference entry (G check)
      10'd84:   ins = scmpn(E_RHO, B_EKOWN, 4'd0, AM_48K);                           // rho in the buffer = rho of G (public)
      10'd85:   ins = u_br(BC_BAD, 10'd8);
      10'd86:   ins = h_prf(E_R, 8'd0, HM_PI1);                                      // s_i: PRF(sigma, i), eta1
      10'd87:   ins = cbd(L_SI0, L_SI1, 1'b0, 1'b1);                                 // copy 1 (shares)
      10'd88:   ins = h_prf(E_R, 8'd0, HM_PI1);                                      // the PRF again
      10'd89:   ins = cbd(L_ACC0, L_ACC1, 1'b0, 1'b1);                               // copy 2: fresh masks, own order
      10'd90:   ins = ntt(L_SI0);
      10'd91:   ins = ntt(L_SI1);
      10'd92:   ins = ntt(L_ACC0);
      10'd93:   ins = ntt(L_ACC1);
      10'd94:   ins = psub(L_ACC0, L_SI0);                                           // share 0: y0 - x0
      10'd95:   ins = psub(L_ACC1, L_SI1);                                           // share 1: y1 - x1
      10'd96:   ins = pzchk(L_ACC0, L_ACC1);                                         // sum 0 everywhere, else FAULT
      10'd97:   ins = u_loop(1'b0, 10'd86);                                          // next i < k
      10'd98:   ins = h_prf(E_R, 8'd0, HM_PKI1);                                     // e_i: PRF(sigma, k + i), eta1
      10'd99:   ins = cbd(L_YI0, L_YI1, 1'b0, 1'b1);
      10'd100:  ins = h_prf(E_R, 8'd0, HM_PKI1);
      10'd101:  ins = cbd(L_ACC0, L_ACC1, 1'b0, 1'b1);
      10'd102:  ins = ntt(L_YI0);
      10'd103:  ins = ntt(L_YI1);
      10'd104:  ins = ntt(L_ACC0);
      10'd105:  ins = ntt(L_ACC1);
      10'd106:  ins = psub(L_ACC0, L_YI0);
      10'd107:  ins = psub(L_ACC1, L_YI1);
      10'd108:  ins = pzchk(L_ACC0, L_ACC1);
      10'd109:  ins = u_loop(1'b0, 10'd98);
      10'd110:  ins = h_gk(SNK_SXOR);                                                // G(d || k) again, XORed into rho, sigma
      10'd111:  ins = seq(E_RHO, E_KB);
      10'd112:  ins = seq(E_R, E_KB);                                                // (sigma is not needed after the PRFs)
      10'd113:  ins = h_xof(B_TMP, HM_XOF, L_T);                                     // A^[i][j] = SampleNTT(rho || j || i)
      10'd114:  ins = pwm(1'b1, L_YI0, L_T, L_SJ0);
      10'd115:  ins = pwm(1'b1, L_YI1, L_T, L_SJ1);
      10'd116:  ins = u_loop(1'b1, 10'd113);                                         // next j < k
      10'd117:  ins = padd(L_YI0, L_YI1);                                            // t^_i is public: unmask
      10'd118:  ins = enc12(L_YI0, B_EKOWN, AM_48I);
      10'd119:  ins = u_loop(1'b0, 10'd113);                                         // next i < k
      10'd120:  ins = h_hek(B_EKOWN, E_H);                                           // H(ek), 48 k + 4 lanes
      10'd121:  ins = u_br(BC_KGEN, 10'd448);                                        // KEYGEN / KGWRAP: PCT first
      10'd122:  ins = u_set(ST_KEYV);                                                // s^ and z stay masked; key_k := k
      10'd123:  ins = u_br(BC_WRAP, 10'd125);
      10'd124:  ins = u_br(BC_ALWAYS, 10'd137);
      10'd125:  ins = h_trng(E_TMP);
      10'd126:  ins = s2bn(E_TMP, B_BLOB_NONCE, 4'd2);                               // nonce (2 lanes)
      10'd127:  ins = s2s(E_D, E_W0);
      10'd128:  ins = s2s(E_Z, E_W1);
      10'd129:  ins = h_ks(E_W0, E_W1);
      10'd130:  ins = s2b(E_W0, B_BLOB_CT, AM_NONE);                                 // ciphertext is public
      10'd131:  ins = s2b(E_W1, B_BLOB_CT + 9'd4, AM_NONE);
      10'd132:  ins = h_tag(SNK_SEED);
      10'd133:  ins = s2b(E_TAG, B_BLOB_TAG, AM_NONE);
      10'd134:  ins = szero(E_W0);
      10'd135:  ins = szero(E_W1);
      10'd136:  ins = szero(E_KEK);
      10'd137:  ins = szero(E_D);
      10'd138:  ins = szero(E_R);
      10'd139:  ins = szero(E_RHO);
      10'd140:  ins = szero(E_CBD + 4'd0);                                           // PRF scratch (E_PUF, E_TMP, E_PH, E_W0, E_W1, E_TAG)
      10'd141:  ins = szero(E_CBD + 4'd1);
      10'd142:  ins = szero(E_CBD + 4'd2);
      10'd143:  ins = szero(E_CBD + 4'd3);
      10'd144:  ins = szero(E_CBD + 4'd4);
      10'd145:  ins = szero(E_CBD + 4'd5);
      10'd146:  ins = pzero(L_T);
      10'd147:  ins = pzero(L_ACC0);
      10'd148:  ins = pzero(L_ACC1);
      10'd149:  ins = pzero(L_YI0);
      10'd150:  ins = pzero(L_YI1);
      10'd151:  ins = u_loop(1'b0, 10'd149);
      10'd152:  ins = u_end(R_OK);
      10'd160:  ins = u_set(ST_RESEED);
      10'd161:  ins = pzero(L_Z);                                                    // the all-zero slot (precharge reads)
      10'd162:  ins = dec(DM_CHK, 4'd12, 1'b1, B_XIN, L_T, AM_48I);                  // ek modulus check, t^_i
      10'd163:  ins = u_loop(1'b0, 10'd162);
      10'd164:  ins = u_br(BC_BAD, 10'd0);
      10'd165:  ins = u_br(BC_INJ, 10'd168);
      10'd166:  ins = h_trng(E_M);
      10'd167:  ins = u_br(BC_ALWAYS, 10'd170);
      10'd168:  ins = b2s(B_INJM, E_M, AM_NONE);                                     // TEST: injected m
      10'd169:  ins = sremask(E_M);
      10'd170:  ins = h_hek(B_XIN, E_PH);                                            // H(ek)
      10'd171:  ins = h_g(E_M, E_PH, E_K1, E_R);                                     // (K, r) = G(m || H(ek))
      10'd172:  ins = b2s(B_XIN, E_TMP, AM_48K);                                     // rho of the key in use ...
      10'd173:  ins = s2b(E_TMP, B_TMP, AM_NONE);                                    // ... to where the XOF reads it
      10'd174:  ins = szero(E_TMP);
      10'd175:  ins = h_prf(E_R, 8'd0, HM_PI1);                                      // y_i: PRF(r, i), eta1
      10'd176:  ins = cbd(L_YI0, L_YI1, 1'b0, 1'b1);
      10'd177:  ins = ntt(L_YI0);
      10'd178:  ins = ntt(L_YI1);
      10'd179:  ins = u_loop(1'b0, 10'd175);
      10'd180:  ins = pzero(L_ACC0);
      10'd181:  ins = pzero(L_ACC1);
      10'd182:  ins = dec(DM_WR, 4'd12, 1'b0, B_XIN, L_T, AM_48J);                   // t^_j
      10'd183:  ins = pwm(1'b1, L_ACC0, L_T, L_YJ0);
      10'd184:  ins = pwm(1'b1, L_ACC1, L_T, L_YJ1);
      10'd185:  ins = u_loop(1'b1, 10'd182);
      10'd186:  ins = intt(L_ACC0);
      10'd187:  ins = intt(L_ACC1);
      10'd188:  ins = h_prf(E_R, 8'd0, HM_P2K2);                                     // + e2: PRF(r, 2k), eta2
      10'd189:  ins = cbd(L_ACC0, L_ACC1, 1'b1, 1'b0);
      10'd190:  ins = mu(E_M);                                                       // + mu (masked m)
      10'd191:  ins = cmpro(D_DV, B_XIN, AM_DUK);                                    // c2 = Compress_dv(v)
      10'd192:  ins = pzero(L_ACC0);
      10'd193:  ins = pzero(L_ACC1);
      10'd194:  ins = h_xof(B_TMP, HM_XOFT, L_T);                                    // A^[j][i] = SampleNTT(rho || i || j)
      10'd195:  ins = pwm(1'b1, L_ACC0, L_T, L_YJ0);
      10'd196:  ins = pwm(1'b1, L_ACC1, L_T, L_YJ1);
      10'd197:  ins = u_loop(1'b1, 10'd194);
      10'd198:  ins = intt(L_ACC0);
      10'd199:  ins = intt(L_ACC1);
      10'd200:  ins = h_prf(E_R, 8'd0, HM_PKI2);                                     // + e1_i: PRF(r, k + i), eta2
      10'd201:  ins = cbd(L_ACC0, L_ACC1, 1'b1, 1'b0);
      10'd202:  ins = cmpro(D_DU, B_XIN, AM_DUI);                                    // c1 part i = Compress_du(u_i)
      10'd203:  ins = u_loop(1'b0, 10'd192);
      10'd204:  ins = s2s(E_K1, E_SK);                                               // K -> session key (masked)
      10'd205:  ins = u_set(ST_SKV);                                                 // role: initiator
      10'd206:  ins = u_br(BC_KEXP, 10'd208);
      10'd207:  ins = u_br(BC_ALWAYS, 10'd209);
      10'd208:  ins = s2b(E_SK, B_K, AM_NONE);                                       // TEST / PERSO: K to the host
      10'd209:  ins = szero(E_M);
      10'd210:  ins = szero(E_R);
      10'd211:  ins = szero(E_K1);
      10'd212:  ins = szero(E_CBD + 4'd0);
      10'd213:  ins = szero(E_CBD + 4'd1);
      10'd214:  ins = szero(E_CBD + 4'd2);
      10'd215:  ins = szero(E_CBD + 4'd3);
      10'd216:  ins = szero(E_CBD + 4'd4);
      10'd217:  ins = szero(E_CBD + 4'd5);
      10'd218:  ins = pzero(L_T);
      10'd219:  ins = pzero(L_ACC0);
      10'd220:  ins = pzero(L_ACC1);
      10'd221:  ins = pzero(L_YI0);
      10'd222:  ins = pzero(L_YI1);
      10'd223:  ins = u_loop(1'b0, 10'd221);
      10'd224:  ins = u_end(R_OK);
      10'd240:  ins = u_br(BC_NOKEY, 10'd1);
      10'd241:  ins = u_set(ST_RESEED);
      10'd242:  ins = pzero(L_Z);                                                    // (TVLA traces start here)
      10'd243:  ins = m_op(M_OKINI);
      10'd244:  ins = b2s(B_EKOWN, E_TMP, AM_48K);                                   // rho of the key in use ...
      10'd245:  ins = s2b(E_TMP, B_TMP, AM_NONE);                                    // ... to where the XOF reads it
      10'd246:  ins = szero(E_TMP);
      10'd247:  ins = pzero(L_ACC0);
      10'd248:  ins = pzero(L_ACC1);
      10'd249:  ins = dec(DM_WR, D_DU, 1'b0, B_XIN, L_T, AM_DUI);                    // u'_i
      10'd250:  ins = ntt(L_T);
      10'd251:  ins = pwm(1'b1, L_ACC0, L_SI0, L_T);
      10'd252:  ins = pwm(1'b1, L_ACC1, L_SI1, L_T);
      10'd253:  ins = u_loop(1'b0, 10'd249);
      10'd254:  ins = intt(L_ACC0);
      10'd255:  ins = intt(L_ACC1);
      10'd256:  ins = dec(DM_RSUB, D_DV, 1'b0, B_XIN, L_ACC0, AM_DUK);               // w0 = v' - acc0
      10'd257:  ins = cmpr1(E_MP);                                                   // m' (fresh masks, fresh order) ...
      10'd258:  ins = cmpr1(E_CBD + 4'd1);                                           // ... again (scratch entry)
      10'd259:  ins = seq(E_MP, E_CBD + 4'd1);                                       // the two decodings must agree
      10'd260:  ins = h_g(E_MP, E_H, E_K1, E_R);                                     // (K', r') = G(m' || h)
      10'd261:  ins = h_j(1'b0);                                                     // K-bar = J(z || c), ciphertext lanes of k
      10'd262:  ins = h_prf(E_R, 8'd0, HM_PI1);                                      // y_i: PRF(r, i), eta1
      10'd263:  ins = cbd(L_YI0, L_YI1, 1'b0, 1'b1);
      10'd264:  ins = ntt(L_YI0);
      10'd265:  ins = ntt(L_YI1);
      10'd266:  ins = u_loop(1'b0, 10'd262);
      10'd267:  ins = pzero(L_ACC0);
      10'd268:  ins = pzero(L_ACC1);
      10'd269:  ins = h_xof(B_TMP, HM_XOFT, L_T);                                    // A^[j][i] = SampleNTT(rho || i || j)
      10'd270:  ins = pwm(1'b1, L_ACC0, L_T, L_YJ0);
      10'd271:  ins = pwm(1'b1, L_ACC1, L_T, L_YJ1);
      10'd272:  ins = u_loop(1'b1, 10'd269);
      10'd273:  ins = intt(L_ACC0);
      10'd274:  ins = intt(L_ACC1);
      10'd275:  ins = h_prf(E_R, 8'd0, HM_PKI2);                                     // + e1_i: PRF(r, k + i), eta2
      10'd276:  ins = cbd(L_ACC0, L_ACC1, 1'b1, 1'b0);
      10'd277:  ins = cmprc(D_DU, B_XIN, AM_DUI);                                    // c1 part i = Compress_du(u_i)
      10'd278:  ins = u_loop(1'b0, 10'd267);
      10'd279:  ins = pzero(L_ACC0);
      10'd280:  ins = pzero(L_ACC1);
      10'd281:  ins = dec(DM_WR, 4'd12, 1'b0, B_EKOWN, L_T, AM_48J);                 // t^_j
      10'd282:  ins = pwm(1'b1, L_ACC0, L_T, L_YJ0);
      10'd283:  ins = pwm(1'b1, L_ACC1, L_T, L_YJ1);
      10'd284:  ins = u_loop(1'b1, 10'd281);
      10'd285:  ins = intt(L_ACC0);
      10'd286:  ins = intt(L_ACC1);
      10'd287:  ins = h_prf(E_R, 8'd0, HM_P2K2);                                     // + e2: PRF(r, 2k), eta2
      10'd288:  ins = cbd(L_ACC0, L_ACC1, 1'b1, 1'b0);
      10'd289:  ins = mu(E_MP);                                                      // + mu (masked m)
      10'd290:  ins = cmprc(D_DV, B_XIN, AM_DUK);                                    // c2 = Compress_dv(v)
      10'd291:  ins = m_op(M_OKCHK);                                                 // the two ok copies must agree
      10'd292:  ins = u_mask(M_SEL, 4'd0, E_SK, 4'd0, 1'b0, B_K, E_K1, E_KB, 1'b1, AM_NONE, 1'b0); // K, kept masked
      10'd293:  ins = u_set(ST_SKVR);                                                // role: responder
      10'd294:  ins = u_br(BC_KEXP, 10'd296);
      10'd295:  ins = u_br(BC_ALWAYS, 10'd297);
      10'd296:  ins = s2b(E_SK, B_K, AM_NONE);                                       // TEST / PERSO: K to the host
      10'd297:  ins = szero(E_MP);
      10'd298:  ins = szero(E_K1);
      10'd299:  ins = szero(E_R);
      10'd300:  ins = szero(E_KB);
      10'd301:  ins = szero(E_CBD + 4'd0);
      10'd302:  ins = szero(E_CBD + 4'd1);
      10'd303:  ins = szero(E_CBD + 4'd2);
      10'd304:  ins = szero(E_CBD + 4'd3);
      10'd305:  ins = szero(E_CBD + 4'd4);
      10'd306:  ins = szero(E_CBD + 4'd5);
      10'd307:  ins = pzero(L_T);
      10'd308:  ins = pzero(L_ACC0);
      10'd309:  ins = pzero(L_ACC1);
      10'd310:  ins = pzero(L_YI0);
      10'd311:  ins = pzero(L_YI1);
      10'd312:  ins = u_loop(1'b0, 10'd310);
      10'd313:  ins = u_end(R_OK);
      10'd320:  ins = u_br(BC_NOSK, 10'd5);
      10'd321:  ins = trunc(1'b0);                                                   // L in 1..128? M bytes from L on := 0
      10'd322:  ins = u_br(BC_BAD, 10'd0);                                           // (no counter used up)
      10'd323:  ins = u_set(ST_RESEED);
      10'd324:  ins = ctr(IO_CTRW);                                                  // header: counter, L, 0, 0
      10'd325:  ins = u_set(ST_TXINC);                                               // counted before use: never reused
      10'd326:  ins = u_br(BC_ROLE, 10'd331);
      10'd327:  ins = h_kks(KC_E1);                                                  // initiator -> responder
      10'd328:  ins = trunc(1'b0);                                                   // C bytes from L on := 0
      10'd329:  ins = h_ktag(SNK_SEED, KC_T1);
      10'd330:  ins = u_br(BC_ALWAYS, 10'd334);
      10'd331:  ins = h_kks(KC_E2);                                                  // responder -> initiator
      10'd332:  ins = trunc(1'b0);
      10'd333:  ins = h_ktag(SNK_SEED, KC_T2);
      10'd334:  ins = s2b(E_TAG, B_SM_TAG, AM_NONE);
      10'd335:  ins = szero(E_TAG);
      10'd336:  ins = u_end(R_OK);
      10'd352:  ins = u_br(BC_NOSK, 10'd5);
      10'd353:  ins = ctr(IO_CTRC);                                                  // replay window check
      10'd354:  ins = u_br(BC_BAD, 10'd6);
      10'd355:  ins = trunc(1'b1);                                                   // length check only
      10'd356:  ins = u_br(BC_BAD, 10'd4);                                           // (a sender never seals such a length)
      10'd357:  ins = u_set(ST_RESEED);
      10'd358:  ins = m_op(M_OKINI);
      10'd359:  ins = u_br(BC_ROLE, 10'd362);
      10'd360:  ins = h_ktag(SNK_MCMP, KC_T2);                                       // initiator opens R -> I
      10'd361:  ins = u_br(BC_ALWAYS, 10'd363);
      10'd362:  ins = h_ktag(SNK_MCMP, KC_T1);                                       // responder opens I -> R
      10'd363:  ins = m_op(M_OKCHK);                                                 // the two ok copies must agree
      10'd364:  ins = m_op(M_OKOUT);
      10'd365:  ins = u_br(BC_BAD, 10'd4);                                           // stays encrypted, window unchanged
      10'd366:  ins = u_set(ST_RXACC);                                               // authentic: mark the counter
      10'd367:  ins = u_br(BC_ROLE, 10'd371);
      10'd368:  ins = h_kks(KC_E2);
      10'd369:  ins = trunc(1'b0);                                                   // plaintext bytes from L on := 0
      10'd370:  ins = u_end(R_OK);
      10'd371:  ins = h_kks(KC_E1);
      10'd372:  ins = trunc(1'b0);
      10'd373:  ins = u_end(R_OK);
      10'd384:  ins = u_set(ST_RESEED);
      10'd385:  ins = h_hek(B_EKOWN, E_H);
      10'd386:  ins = scmpn(E_H, B_INJH, 4'd0, AM_NONE);                             // dk hash check (4 lanes)
      10'd387:  ins = u_br(BC_BAD, 10'd0);
      10'd388:  ins = dec(DM_WR, 4'd12, 1'b0, B_XIN, L_SI0, AM_48I);                 // s^_i bytes
      10'd389:  ins = msplit(L_SI0, L_SI1);                                          // -> shares
      10'd390:  ins = u_loop(1'b0, 10'd388);
      10'd391:  ins = pzero(L_Z);
      10'd392:  ins = enc12(L_Z, B_XIN, AM_48I);                                     // wipe the s^ bytes (B_XIN becomes readable after ENCAPS)
      10'd393:  ins = u_loop(1'b0, 10'd392);
      10'd394:  ins = b2s(B_INJZ, E_Z, AM_NONE);
      10'd395:  ins = sremask(E_Z);
      10'd396:  ins = u_set(ST_KEYV);                                                // key_k := k
      10'd397:  ins = u_end(R_OK);
      10'd400:  ins = u_set(ST_RESEED);
      10'd401:  ins = h_trng(E_TMP);                                                 // k (masked)
      10'd402:  ins = u_puf(PF_ENROLL, E_TMP, B_HELP);                               // helper -> 15 lanes, k canonical
      10'd403:  ins = h_kchk(E_TMP, E_W0);
      10'd404:  ins = s2bn(E_W0, B_HELP_CHK, 4'd1);                                  // check value -> helper lane 15
      10'd405:  ins = szero(E_W0);
      10'd406:  ins = szero(E_TMP);
      10'd407:  ins = u_end(R_OK);
      10'd408:  ins = u_puf(PF_RAW, 4'd0, B_XIN);                                    // 960 bits -> 15 lanes
      10'd409:  ins = u_end(R_OK);
      10'd410:  ins = u_io(IO_T2B, DM_WR, 4'd0, 1'b0, 1'b0, B_XIN, 4'd0, 4'd0, 4'd0, AM_NONE); // 136 words
      10'd411:  ins = u_end(R_OK);
      10'd416:  ins = pzero(L_SI0);                                                  // slot 2i, i = 0..9: all 20 slots
      10'd417:  ins = pzero(L_SI1);
      10'd418:  ins = u_loopn(1'b0, 10'd416, 4'd10);
      10'd419:  ins = szero(4'd0);
      10'd420:  ins = szero(4'd1);
      10'd421:  ins = szero(4'd2);
      10'd422:  ins = szero(4'd3);
      10'd423:  ins = szero(4'd4);
      10'd424:  ins = szero(4'd5);
      10'd425:  ins = szero(4'd6);
      10'd426:  ins = szero(4'd7);
      10'd427:  ins = szero(4'd8);
      10'd428:  ins = szero(4'd9);
      10'd429:  ins = szero(4'd10);
      10'd430:  ins = szero(4'd11);
      10'd431:  ins = szero(4'd12);
      10'd432:  ins = szero(4'd13);
      10'd433:  ins = szero(4'd14);
      10'd434:  ins = szero(4'd15);
      10'd435:  ins = s2b(E_TMP, B_K, AM_NONE);                                      // E_TMP is 0 now
      10'd436:  ins = s2b(E_TMP, B_TMP, AM_NONE);
      10'd437:  ins = s2b(E_TMP, B_SM + 9'd0, AM_NONE);                              // secure-message window
      10'd438:  ins = s2b(E_TMP, B_SM + 9'd4, AM_NONE);
      10'd439:  ins = s2b(E_TMP, B_SM + 9'd8, AM_NONE);
      10'd440:  ins = s2b(E_TMP, B_SM + 9'd12, AM_NONE);
      10'd441:  ins = s2b(E_TMP, B_SM + 9'd16, AM_NONE);
      10'd442:  ins = s2b(E_TMP, B_SM + 9'd20, AM_NONE);
      10'd443:  ins = u_set(ST_KEYC);
      10'd444:  ins = u_set(ST_SKC);
      10'd445:  ins = u_end(R_OK);
      10'd448:  ins = pzero(L_Z);                                                    // the all-zero slot (precharge reads)
      10'd449:  ins = h_trng(E_M);                                                   // m (masked)
      10'd450:  ins = h_hek(B_EKOWN, E_PH);                                          // H(ek) of the published ek
      10'd451:  ins = h_g(E_M, E_PH, E_K1, E_R);                                     // (K, r) = G(m || H(ek))
      10'd452:  ins = h_prf(E_R, 8'd0, HM_PI1);                                      // y_i: PRF(r, i), eta1
      10'd453:  ins = cbd(L_YI0, L_YI1, 1'b0, 1'b1);
      10'd454:  ins = ntt(L_YI0);
      10'd455:  ins = ntt(L_YI1);
      10'd456:  ins = u_loop(1'b0, 10'd452);
      10'd457:  ins = pzero(L_ACC0);
      10'd458:  ins = pzero(L_ACC1);
      10'd459:  ins = dec(DM_WR, 4'd12, 1'b0, B_EKOWN, L_T, AM_48J);                 // t^_j
      10'd460:  ins = pwm(1'b1, L_ACC0, L_T, L_YJ0);
      10'd461:  ins = pwm(1'b1, L_ACC1, L_T, L_YJ1);
      10'd462:  ins = u_loop(1'b1, 10'd459);
      10'd463:  ins = intt(L_ACC0);
      10'd464:  ins = intt(L_ACC1);
      10'd465:  ins = h_prf(E_R, 8'd0, HM_P2K2);                                     // + e2: PRF(r, 2k), eta2
      10'd466:  ins = cbd(L_ACC0, L_ACC1, 1'b1, 1'b0);
      10'd467:  ins = mu(E_M);                                                       // + mu (masked m)
      10'd468:  ins = cmpro(D_DV, B_XIN, AM_DUK);                                    // c2 = Compress_dv(v)
      10'd469:  ins = pzero(L_ACC0);
      10'd470:  ins = pzero(L_ACC1);
      10'd471:  ins = h_xof(B_TMP, HM_XOFT, L_T);                                    // A^[j][i] = SampleNTT(rho || i || j)
      10'd472:  ins = pwm(1'b1, L_ACC0, L_T, L_YJ0);
      10'd473:  ins = pwm(1'b1, L_ACC1, L_T, L_YJ1);
      10'd474:  ins = u_loop(1'b1, 10'd471);
      10'd475:  ins = intt(L_ACC0);
      10'd476:  ins = intt(L_ACC1);
      10'd477:  ins = h_prf(E_R, 8'd0, HM_PKI2);                                     // + e1_i: PRF(r, k + i), eta2
      10'd478:  ins = cbd(L_ACC0, L_ACC1, 1'b1, 1'b0);
      10'd479:  ins = cmpro(D_DU, B_XIN, AM_DUI);                                    // c1 part i = Compress_du(u_i)
      10'd480:  ins = u_loop(1'b0, 10'd469);
      10'd481:  ins = pzero(L_ACC0);
      10'd482:  ins = pzero(L_ACC1);
      10'd483:  ins = dec(DM_WR, D_DU, 1'b0, B_XIN, L_T, AM_DUI);
      10'd484:  ins = ntt(L_T);
      10'd485:  ins = pwm(1'b1, L_ACC0, L_SI0, L_T);
      10'd486:  ins = pwm(1'b1, L_ACC1, L_SI1, L_T);
      10'd487:  ins = u_loop(1'b0, 10'd483);
      10'd488:  ins = intt(L_ACC0);
      10'd489:  ins = intt(L_ACC1);
      10'd490:  ins = dec(DM_RSUB, D_DV, 1'b0, B_XIN, L_ACC0, AM_DUK);               // w0 = v' - acc0
      10'd491:  ins = cmpr1(E_TMP);                                                  // m'
      10'd492:  ins = h_g(E_TMP, E_H, E_KB, E_R);                                    // (K', r') = G(m' || h), h of dk
      10'd493:  ins = seq(E_K1, E_KB);                                               // K' != K: FAULT (key never valid)
      10'd494:  ins = szero(E_M);
      10'd495:  ins = szero(E_TMP);
      10'd496:  ins = szero(E_K1);
      10'd497:  ins = szero(E_KB);
      10'd498:  ins = pzero(L_ACC0);
      10'd499:  ins = pzero(L_ACC1);
      10'd500:  ins = u_br(BC_ALWAYS, 10'd122);                                      // the rest is wiped at L_KGEND
      // ---- generated by scripts/pqse_ucode_v15_gen.py: end ----
      default: ins = u_end(R_UNKNOWN);
    endcase
  end
endmodule
