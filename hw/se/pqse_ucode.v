// -----------------------------------------------------------------------------
// pqse_ucode.v - microcode ROM of the PQSE secure element (1024 x 96 bit,
// 10-bit program counter).
//
// The sequencer (pqse_core.v) runs one instruction at a time and waits for it
// to finish (one engine active at a time: smallest area, lowest peak power).
// Programs sit in segments at fixed addresses; unused addresses return
// END R_UNKNOWN.
//
// Every secret is first-order masked from the moment it exists:
//   - TRNG seeds (d, z, m) are conditioned by the masked sponge and come out
//     as two Boolean shares
//   - s, e, y, e1, e2: the masked sponge writes the PRF output (both shares)
//     into the scratch seed entries E_CBD (12..15), then the masked CBD turns
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
//   0..7     failure exits
//   16       KEYGEN / KGWRAP: seeds from the TRNG (or injected in TEST); KGWRAP
//            first reconstructs the PUF key and derives the KEK (48)
//   32       UNWRAP: PUF -> KEK (48), tag check (masked), decrypt d, z (masked)
//   48       PUF key + check value (+ majority retries) -> KEK, shared by
//            KGWRAP and UNWRAP (returns on the WRAP flag)
//   80       KeyGen core (masked)
//   144      wrap (KGWRAP only): blob = nonce | Enc_KEK(d || z) | tag
//   156      KeyGen end: wipe temporaries
//   192      ENCAPS (masked)
//   320      DECAPS (masked; m' decoded twice and compared, ok copies
//            compared; K kept as the session key)
//   448      SEAL: secure message with the session key
//   480      OPEN
//   512      IMPORT (TEST/PERSO): s^ bytes + ek + H(ek) + z
//   528      ENROLL (TEST/PERSO): PUF helper data + key check value
//   544      PUFRAW (TEST): 960 raw PUF bits
//   548      TRNGRAW (TEST): 136 raw TRNG words
//   560      ZEROIZE
//
// PUF key reconstruction (48): the helper data's last lane holds the 64-bit
// check value H(k || "C") (first 8 bytes of SHA3-256, written by ENROLL). The
// key is decoded with one read per response bit; if its check value does not
// match, again with the majority of 3 reads, then of 5 reads; if that fails
// too, the command ends with R_PUF (12). The check value is public (helper
// data); the key and the comparison stay masked until the 64-bit hash.
//
// Session key (SK = the ML-KEM shared secret K, kept masked in seed entry
// E_SK) and secure messaging (messages of 1..128 bytes, buffer B_SM):
//   header H (32 bytes) = counter (64-bit LE) || length L (64-bit LE, set by
//          the host) || 16 zero bytes
//   SEAL   L must be 1..128 (else result 1); H's counter := the send
//          counter, which then counts up;
//          C = (M[0..L-1] xor KMACXOF256(SK, H, 1024, "E"d)[0..L-1]) || zeros
//          T = KMAC256(SK, H || C, 256, "T"d)              (NIST SP 800-185)
//   OPEN   rejects a counter that was already accepted or is more than 63
//          behind the newest accepted one (result 11), a length outside
//          1..128 or a wrong tag (result 9; masked compare, the two ok copies
//          are compared first); then marks the counter in the 64-message
//          window and decrypts (bytes from L on := 0)
//   d = "1" for messages from the initiator (the Encaps side) to the
//   responder (the Decaps side), "2" for the other direction, so a message
//   reflected back to its sender is rejected. A new session key (Encaps,
//   Decaps) restarts the counters. Messages may be lost or reordered (inside
//   the window), never replayed.
// scripts/pqse_sm_check.py recomputes C and T with an independent KMAC.
// -----------------------------------------------------------------------------
module pqse_ucode (
  input  wire        clk,
  input  wire        en,         // read: q <= ROM[pc], one clock later
  input  wire [9:0]  pc,
  output reg  [95:0] q
);
  `include "pqse_defs.vh"

  // the table below is a case statement inside the clocked block that loads q
  // (the synchronous-ROM template of GowinSynthesis, Yosys and Quartus), so it
  // maps to a ROM block (FPGA block RAM) instead of thousands of LUTs

  // ---- labels --------------------------------------------------------------------------
  localparam [9:0] X_BADIN = 10'd0, X_NOKEY = 10'd1, X_BADBLOB = 10'd2, X_DENIED = 10'd3,
                   X_BADTAG = 10'd4, X_NOSK = 10'd5, X_REPLAY = 10'd6, X_PUF = 10'd7;
  localparam [9:0] L_KGSEED = 10'd18,  L_KGINJ = 10'd24,  L_UWK = 10'd34, L_UWFAIL = 10'd44,
                   L_PREC   = 10'd48,  L_PROK  = 10'd62,  L_PFAIL = 10'd68,
                   L_KG     = 10'd80,  L_WRAP  = 10'd144, L_KGEND = 10'd156;

  // ---- instruction builders --------------------------------------------------------
  function [95:0] u_end(input [7:0] r);
    u_end = {C_END, 84'd0, r};
  endfunction
  function [95:0] u_br(input [3:0] c, input [9:0] t);
    u_br = {C_BR, c, t, 78'd0};
  endfunction
  function [95:0] u_set(input [3:0] o);
    u_set = {C_SET, o, 88'd0};
  endfunction
  function [95:0] u_poly(input [3:0] o, input acc, input [3:0] c, input [3:0] a, input [3:0] b);
    u_poly = {C_POLY, o, acc, c, a, b, 1'b1, 74'd0};
  endfunction
  function [95:0] u_io(input [3:0] o, input [1:0] dm, input [3:0] d, input cmp, input mchk,
                       input [8:0] ba, input [3:0] sl, input [3:0] e, input [3:0] e2);
    u_io = {C_IO, o, dm, d, cmp, mchk, ba, sl, e, e2, 59'd0};
  endfunction
  function [95:0] u_mask(input [3:0] o, input [3:0] d, input [3:0] sh0, input [3:0] sh1, input ng,
                         input [8:0] ba, input [3:0] e, input [3:0] e2, input acc);
    u_mask = {C_MASK, o, d, sh0, sh1, ng, ba, e, e2, acc, 57'd0};
  endfunction
  function [95:0] u_puf(input [3:0] o, input [3:0] e, input [8:0] hb);
    u_puf = {C_PUF, o, e, hb, 75'd0};
  endfunction
  function [95:0] u_hash(input [1:0] rate, input shake, input msk,
                         input [1:0] p1s, input [8:0] p1a, input [7:0] p1n,
                         input [1:0] p2s, input [8:0] p2a, input [7:0] p2n,
                         input [1:0] sfn, input [15:0] sfx, input [2:0] sink,
                         input [3:0] oe0, input [3:0] oe1, input [7:0] onl,
                         input [3:0] os, input [3:0] os2, input acc);
    u_hash = {C_HASH, rate, shake, msk, p1s, 1'b0, p1a, p1n, p2s, p2a, p2n, sfn, sfx,
              sink, oe0, oe1, onl, os, os2, acc, 3'd0};
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
                    2'd0, 16'd0, SNK_SEED, oe, 4'd0, 8'd4, 4'd0, 4'd0, 1'b0);
  endfunction
  // H = SHA3-256 over public buffer lanes -> entry
  function [95:0] h_hbuf(input [8:0] ba, input [7:0] n, input [3:0] oe);
    h_hbuf = u_hash(RATE_136, 1'b0, 1'b0, SRC_BUF, ba, n, SRC_NONE, 9'd0, 8'd0,
                    2'd0, 16'd0, SNK_SEED, oe, 4'd0, 8'd4, 4'd0, 4'd0, 1'b0);
  endfunction
  // G = SHA3-512(e1 || e2) -> oe0 (32 bytes), oe1 (32 bytes), masked
  function [95:0] h_g(input [3:0] e1, input [3:0] e2, input [3:0] oe0, input [3:0] oe1);
    h_g = u_hash(RATE_72, 1'b0, 1'b1, SRC_SEED, sa(e1), 8'd4, SRC_SEED, sa(e2), 8'd4,
                 2'd0, 16'd0, SNK_SEED, oe0, oe1, 8'd8, 4'd0, 4'd0, 1'b0);
  endfunction
  // PRF_2(e, n) = SHAKE256(e || n, 128 bytes), masked -> scratch entries E_CBD..E_CBD+3
  function [95:0] h_prf(input [3:0] e, input [7:0] n);
    h_prf = u_hash(RATE_136, 1'b1, 1'b1, SRC_SEED, sa(e), 8'd4, SRC_NONE, 9'd0, 8'd0,
                   2'd1, {8'd0, n}, SNK_SEED, E_CBD, E_CBD + 4'd1, 8'd16, 4'd0, 4'd0, 1'b0);
  endfunction
  // masked SamplePolyCBD_2 of the PRF output in E_CBD -> slots os (share 0), os2
  // (share 1), random word order; acc: add to the slots
  function [95:0] cbd(input [3:0] os, input [3:0] os2, input acc);
    cbd = u_mask(M_CBD, 4'd0, os, os2, 1'b0, 9'd0, E_CBD, 4'd0, acc);
  endfunction
  // XOF(rho || b0 || b1) -> SampleNTT into slot os; rho is public (buffer)
  function [95:0] h_xof(input [8:0] a, input [7:0] b0, input [7:0] b1, input [3:0] os);
    h_xof = u_hash(RATE_168, 1'b1, 1'b0, SRC_BUF, a, 8'd4, SRC_NONE, 9'd0, 8'd0,
                   2'd2, {b1, b0}, SNK_SNTT, 4'd0, 4'd0, 8'd0, os, 4'd0, 1'b0);
  endfunction
  // KEK = SHA3-256(k_PUF || "K"), masked
  function [95:0] h_kek(input dummy);
    h_kek = u_hash(RATE_136, 1'b0, 1'b1, SRC_SEED, sa(E_PUF), 8'd4, SRC_NONE, 9'd0, 8'd0,
                   2'd1, 16'h004B, SNK_SEED, E_KEK, 4'd0, 8'd4, 4'd0, 4'd0, 1'b0);
  endfunction
  // PUF key check value = SHA3-256(k_PUF || "C"), first lane only, masked -> entry oe
  // (unmasked only by the 64-bit compare / the ENROLL output: it is public helper data)
  function [95:0] h_kchk(input [3:0] e, input [3:0] oe);
    h_kchk = u_hash(RATE_136, 1'b0, 1'b1, SRC_SEED, sa(e), 8'd4, SRC_NONE, 9'd0, 8'd0,
                    2'd1, 16'h0043, SNK_SEED, oe, 4'd0, 8'd1, 4'd0, 4'd0, 1'b0);
  endfunction
  // blob tag = SHA3-256(KEK || nonce || ct), masked; sink SEED (wrap) or MCMP (unwrap)
  function [95:0] h_tag(input [2:0] sink);
    h_tag = u_hash(RATE_136, 1'b0, 1'b1, SRC_SEED, sa(E_KEK), 8'd4, SRC_BUF, B_BLOB, 8'd10,
                   2'd0, 16'd0, sink, E_TAG, 4'd0, 8'd4, 4'd0, 4'd0, 1'b0);
  endfunction
  // blob keystream = SHAKE256(KEK || nonce, 64 bytes), masked, XORed into oe0 | oe1
  function [95:0] h_ks(input [3:0] oe0, input [3:0] oe1);
    h_ks = u_hash(RATE_136, 1'b1, 1'b1, SRC_SEED, sa(E_KEK), 8'd4, SRC_BUF, B_BLOB_NONCE, 8'd2,
                  2'd0, 16'd0, SNK_SXOR, oe0, oe1, 8'd8, 4'd0, 4'd0, 1'b0);
  endfunction
  // message keystream = KMACXOF256(SK, H, 1024 bits, "E1" / "E2"), masked; the
  // sink XORs it into the 16 message lanes
  function [95:0] h_kks(input [1:0] cs);
    h_kks = u_kmac(u_hash(RATE_136, 1'b1, 1'b1, SRC_SEED, sa(E_SK), 8'd4, SRC_BUF, B_SM_HDR, 8'd4,
                          2'd0, 16'd0, SNK_BXOR, 4'd0, 4'd0, 8'd16, 4'd0, 4'd0, 1'b0),
                   1'b1, cs);
  endfunction
  // message tag = KMAC256(SK, H || C, 256, "T1" / "T2"), masked; sink SEED (SEAL,
  // -> E_TAG) or MCMP (OPEN: compared with the received tag, acc = 1)
  function [95:0] h_ktag(input [2:0] sink, input [1:0] cs);
    h_ktag = u_kmac(u_hash(RATE_136, 1'b0, 1'b1, SRC_SEED, sa(E_SK), 8'd4, SRC_BUF, B_SM, 8'd20,
                           2'd0, 16'd0, sink, E_TAG, 4'd0, 8'd4, 4'd0, 4'd0,
                           (sink == SNK_MCMP)),
                    1'b0, cs);
  endfunction
  // K-bar = J(z || c) = SHAKE256(z || c, 32), masked
  function [95:0] h_j(input dummy);
    h_j = u_hash(RATE_136, 1'b1, 1'b1, SRC_SEED, sa(E_Z), 8'd4, SRC_BUF, B_XIN, 8'd136,
                 2'd0, 16'd0, SNK_SEED, E_KB, 4'd0, 8'd4, 4'd0, 4'd0, 1'b0);
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
  function [95:0] msplit(input [3:0] c, input [3:0] a);
    msplit = u_poly(P_MSPLIT, 1'b0, c, a, 4'd0);
  endfunction
  // decode d bits from buffer lane ba into slot (mode dm, decompress if d < 12)
  function [95:0] dec(input [1:0] dm, input [3:0] d, input mchk, input [8:0] ba, input [3:0] sl);
    dec = u_io(IO_DEC, dm, d, (d != 4'd12), mchk, ba, sl, 4'd0, 4'd0);
  endfunction
  function [95:0] enc12(input [3:0] sl, input [8:0] ba);
    enc12 = u_io(IO_ENC, DM_WR, 4'd12, 1'b0, 1'b0, ba, sl, 4'd0, 4'd0);
  endfunction
  function [95:0] s2b(input [3:0] e, input [8:0] ba);          // 4 lanes
    s2b = u_io(IO_S2B, DM_WR, 4'd0, 1'b0, 1'b0, ba, 4'd0, e, 4'd0);
  endfunction
  function [95:0] s2bn(input [3:0] e, input [8:0] ba, input [3:0] n);   // lanes 0..n-1
    s2bn = u_io(IO_S2B, DM_WR, n, 1'b0, 1'b0, ba, 4'd0, e, 4'd0);
  endfunction
  function [95:0] b2s(input [8:0] ba, input [3:0] e);
    b2s = u_io(IO_B2S, DM_WR, 4'd0, 1'b0, 1'b0, ba, 4'd0, e, 4'd0);
  endfunction
  function [95:0] s2s(input [3:0] e, input [3:0] e2);
    s2s = u_io(IO_S2S, DM_WR, 4'd0, 1'b0, 1'b0, 9'd0, 4'd0, e, e2);
  endfunction
  function [95:0] szero(input [3:0] e);
    szero = u_io(IO_SZERO, DM_WR, 4'd0, 1'b0, 1'b0, 9'd0, 4'd0, e, 4'd0);
  endfunction
  function [95:0] sremask(input [3:0] e);
    sremask = u_io(IO_SREMASK, DM_WR, 4'd0, 1'b0, 1'b0, 9'd0, 4'd0, e, 4'd0);
  endfunction
  function [95:0] scmpn(input [3:0] e, input [8:0] ba, input [3:0] n); // n = 0: 4 lanes
    scmpn = u_io(IO_SCMP, DM_WR, n, 1'b0, 1'b0, ba, 4'd0, e, 4'd0);
  endfunction
  function [95:0] seq(input [3:0] e, input [3:0] e2);         // FAULT if e != e2 (masked)
    seq = u_io(IO_SEQ, DM_WR, 4'd0, 1'b0, 1'b0, 9'd0, 4'd0, e, e2);
  endfunction
  function [95:0] trunc(input chk);                            // chk: length check only
    trunc = u_io(IO_TRUNC, DM_WR, 4'd0, chk, 1'b0, B_SM_MSG, 4'd0, 4'd0, 4'd0);
  endfunction
  function [95:0] ctr(input [3:0] o);                          // IO_CTRW / IO_CTRC
    ctr = u_io(o, DM_WR, 4'd0, 1'b0, 1'b0, B_SM_HDR, 4'd0, 4'd0, 4'd0);
  endfunction
  function [95:0] m_op(input [3:0] o);          // OKINI / OKOUT / OKCHK
    m_op = u_mask(o, 4'd0, 4'd0, 4'd0, 1'b0, 9'd0, 4'd0, 4'd0, 1'b0);
  endfunction
  function [95:0] cmprc(input [3:0] d, input [8:0] ba);   // compare with the ciphertext
    cmprc = u_mask(M_CMPRC, d, S_ACC0, S_ACC1, 1'b0, ba, 4'd0, 4'd0, 1'b0);
  endfunction
  function [95:0] cmpro(input [3:0] d, input [8:0] ba);   // write the ciphertext
    cmpro = u_mask(M_CMPRO, d, S_ACC0, S_ACC1, 1'b0, ba, 4'd0, 4'd0, 1'b0);
  endfunction
  function [95:0] cmpr1(input [3:0] e);                   // m' = Compress_1(w) -> entry e
    cmpr1 = u_mask(M_CMPR1, 4'd1, S_ACC0, S_ACC1, 1'b1, 9'd0, e, 4'd0, 1'b0);
  endfunction
  function [95:0] mu(input [3:0] e);                      // + Decompress_1(m)
    mu = u_mask(M_MU, 4'd0, S_ACC0, S_ACC1, 1'b0, 9'd0, e, 4'd0, 1'b1);
  endfunction

  // slots: s^_j shares S(2j), S(2j+1); y_j / e_i / t_i shares Y_j, Y_jB
  localparam [3:0] S0 = 4'd0, S1 = 4'd1, S2 = 4'd2, S3 = 4'd3, S4 = 4'd4, S5 = 4'd5,
                   Y0 = 4'd10, Y0B = 4'd11, Y1 = 4'd12, Y1B = 4'd13, Y2 = 4'd14, Y2B = 4'd15;
  localparam [8:0] RHO_OWN = B_EKOWN + 9'd144, RHO_PEER = B_XIN + 9'd144;

  always @(posedge clk) begin
    if (en) case (pc)
      // ---------------- failure exits ----------------
      10'd0:   q <= u_end(R_BADIN);
      10'd1:   q <= u_end(R_NOKEY);
      10'd2:   q <= u_end(R_BADBLOB);
      10'd3:   q <= u_end(R_DENIED);
      10'd4:   q <= u_end(R_BADTAG);
      10'd5:   q <= u_end(R_NOSK);
      10'd6:   q <= u_end(R_REPLAY);
      10'd7:   q <= u_end(R_PUF);

      // ---------------- KEYGEN / KGWRAP (16) ----------------
      10'd16:  q <= u_set(ST_RESEED);
      10'd17:  q <= u_br(BC_WRAP, L_PREC);                   // KGWRAP: KEK first (no key yet if it fails)
      10'd18:  q <= u_br(BC_INJ, L_KGINJ);                   // L_KGSEED
      10'd19:  q <= h_trng(E_D);
      10'd20:  q <= h_trng(E_Z);
      10'd21:  q <= u_br(BC_ALWAYS, L_KG);
      10'd24:  q <= b2s(B_INJD, E_D);                        // TEST: injected d, z
      10'd25:  q <= sremask(E_D);
      10'd26:  q <= b2s(B_INJZ, E_Z);
      10'd27:  q <= sremask(E_Z);
      10'd28:  q <= u_br(BC_ALWAYS, L_KG);

      // ---------------- UNWRAP (32) ----------------
      10'd32:  q <= u_set(ST_RESEED);
      10'd33:  q <= u_br(BC_ALWAYS, L_PREC);                 // PUF key -> KEK, back to L_UWK
      10'd34:  q <= m_op(M_OKINI);                           // L_UWK
      10'd35:  q <= h_tag(SNK_MCMP);                         // masked tag check
      10'd36:  q <= m_op(M_OKCHK);                           // the two ok copies must agree
      10'd37:  q <= m_op(M_OKOUT);
      10'd38:  q <= u_br(BC_BAD, L_UWFAIL);
      10'd39:  q <= b2s(B_BLOB_CT, E_D);
      10'd40:  q <= b2s(B_BLOB_CT + 9'd4, E_Z);
      10'd41:  q <= h_ks(E_D, E_Z);                          // d, z now masked plaintext
      10'd42:  q <= szero(E_KEK);
      10'd43:  q <= u_br(BC_ALWAYS, L_KG);
      10'd44:  q <= szero(E_KEK);                            // L_UWFAIL
      10'd45:  q <= u_br(BC_ALWAYS, X_BADBLOB);

      // ---------------- PUF key + check value -> KEK (48), KGWRAP and UNWRAP ----------------
      10'd48:  q <= u_puf(PF_RECON, E_PUF, B_HELP);          // L_PREC: one read per bit
      10'd49:  q <= h_kchk(E_PUF, E_TMP);
      10'd50:  q <= scmpn(E_TMP, B_HELP_CHK, 4'd1);          // 64-bit check value
      10'd51:  q <= u_br(BC_NBAD, L_PROK);
      10'd52:  q <= u_set(ST_BADC);
      10'd53:  q <= u_puf(PF_RECON3, E_PUF, B_HELP);         // retry: majority of 3 reads
      10'd54:  q <= h_kchk(E_PUF, E_TMP);
      10'd55:  q <= scmpn(E_TMP, B_HELP_CHK, 4'd1);
      10'd56:  q <= u_br(BC_NBAD, L_PROK);
      10'd57:  q <= u_set(ST_BADC);
      10'd58:  q <= u_puf(PF_RECON5, E_PUF, B_HELP);         // retry: majority of 5 reads
      10'd59:  q <= h_kchk(E_PUF, E_TMP);
      10'd60:  q <= scmpn(E_TMP, B_HELP_CHK, 4'd1);
      10'd61:  q <= u_br(BC_BAD, L_PFAIL);
      10'd62:  q <= szero(E_TMP);                            // L_PROK
      10'd63:  q <= h_kek(1'b0);
      10'd64:  q <= szero(E_PUF);
      10'd65:  q <= u_br(BC_WRAP, L_KGSEED);                 // KGWRAP: on to KeyGen
      10'd66:  q <= u_br(BC_ALWAYS, L_UWK);                  // UNWRAP: on to the tag check
      10'd68:  q <= szero(E_PUF);                            // L_PFAIL
      10'd69:  q <= szero(E_TMP);
      10'd70:  q <= u_br(BC_ALWAYS, X_PUF);

      // ---------------- KeyGen core (80), masked ----------------
      10'd80:  q <= u_hash(RATE_72, 1'b0, 1'b1, SRC_SEED, sa(E_D), 8'd4, SRC_NONE, 9'd0, 8'd0,
                            2'd1, 16'h0003, SNK_SEED, E_RHO, E_R, 8'd8, 4'd0, 4'd0, 1'b0); // (rho, sigma) = G(d || 3)
      10'd81:  q <= s2b(E_RHO, RHO_OWN);                     // rho is public
      10'd82:  q <= h_prf(E_R, 8'd0);                        // s_0 (shares)
      10'd83:  q <= cbd(S0, S1, 1'b0);
      10'd84:  q <= ntt(S0);
      10'd85:  q <= ntt(S1);
      10'd86:  q <= h_prf(E_R, 8'd1);                        // s_1
      10'd87:  q <= cbd(S2, S3, 1'b0);
      10'd88:  q <= ntt(S2);
      10'd89:  q <= ntt(S3);
      10'd90:  q <= h_prf(E_R, 8'd2);                        // s_2
      10'd91:  q <= cbd(S4, S5, 1'b0);
      10'd92:  q <= ntt(S4);
      10'd93:  q <= ntt(S5);
      10'd94:  q <= h_prf(E_R, 8'd3);                        // e_0
      10'd95:  q <= cbd(Y0, Y0B, 1'b0);
      10'd96:  q <= ntt(Y0);
      10'd97:  q <= ntt(Y0B);
      10'd98:  q <= h_prf(E_R, 8'd4);                        // e_1
      10'd99:  q <= cbd(Y1, Y1B, 1'b0);
      10'd100: q <= ntt(Y1);
      10'd101: q <= ntt(Y1B);
      10'd102: q <= h_prf(E_R, 8'd5);                        // e_2
      10'd103: q <= cbd(Y2, Y2B, 1'b0);
      10'd104: q <= ntt(Y2);
      10'd105: q <= ntt(Y2B);
      // t^_i = e^_i + sum_j A^[i][j] o s^_j, per share; A^[i][j] = SampleNTT(rho || j || i)
      10'd106: q <= h_xof(RHO_OWN, 8'd0, 8'd0, S_T);
      10'd107: q <= pwm(1'b1, Y0,  S_T, S0);
      10'd108: q <= pwm(1'b1, Y0B, S_T, S1);
      10'd109: q <= h_xof(RHO_OWN, 8'd1, 8'd0, S_T);
      10'd110: q <= pwm(1'b1, Y0,  S_T, S2);
      10'd111: q <= pwm(1'b1, Y0B, S_T, S3);
      10'd112: q <= h_xof(RHO_OWN, 8'd2, 8'd0, S_T);
      10'd113: q <= pwm(1'b1, Y0,  S_T, S4);
      10'd114: q <= pwm(1'b1, Y0B, S_T, S5);
      10'd115: q <= padd(Y0, Y0B);                           // t^_0 is public: unmask
      10'd116: q <= enc12(Y0, B_EKOWN);
      10'd117: q <= h_xof(RHO_OWN, 8'd0, 8'd1, S_T);
      10'd118: q <= pwm(1'b1, Y1,  S_T, S0);
      10'd119: q <= pwm(1'b1, Y1B, S_T, S1);
      10'd120: q <= h_xof(RHO_OWN, 8'd1, 8'd1, S_T);
      10'd121: q <= pwm(1'b1, Y1,  S_T, S2);
      10'd122: q <= pwm(1'b1, Y1B, S_T, S3);
      10'd123: q <= h_xof(RHO_OWN, 8'd2, 8'd1, S_T);
      10'd124: q <= pwm(1'b1, Y1,  S_T, S4);
      10'd125: q <= pwm(1'b1, Y1B, S_T, S5);
      10'd126: q <= padd(Y1, Y1B);
      10'd127: q <= enc12(Y1, B_EKOWN + 9'd48);
      10'd128: q <= h_xof(RHO_OWN, 8'd0, 8'd2, S_T);
      10'd129: q <= pwm(1'b1, Y2,  S_T, S0);
      10'd130: q <= pwm(1'b1, Y2B, S_T, S1);
      10'd131: q <= h_xof(RHO_OWN, 8'd1, 8'd2, S_T);
      10'd132: q <= pwm(1'b1, Y2,  S_T, S2);
      10'd133: q <= pwm(1'b1, Y2B, S_T, S3);
      10'd134: q <= h_xof(RHO_OWN, 8'd2, 8'd2, S_T);
      10'd135: q <= pwm(1'b1, Y2,  S_T, S4);
      10'd136: q <= pwm(1'b1, Y2B, S_T, S5);
      10'd137: q <= padd(Y2, Y2B);
      10'd138: q <= enc12(Y2, B_EKOWN + 9'd96);
      10'd139: q <= h_hbuf(B_EKOWN, 8'd148, E_H);            // H(ek)
      10'd140: q <= u_set(ST_KEYV);                          // s^ (S0..S5) and z stay masked
      10'd141: q <= u_br(BC_WRAP, L_WRAP);
      10'd142: q <= u_br(BC_ALWAYS, L_KGEND);

      // ---------------- wrap (144), KGWRAP only: the KEK is already in E_KEK ----------------
      10'd144: q <= h_trng(E_TMP);
      10'd145: q <= s2bn(E_TMP, B_BLOB_NONCE, 4'd2);         // nonce (2 lanes)
      10'd146: q <= s2s(E_D, E_W0);
      10'd147: q <= s2s(E_Z, E_W1);
      10'd148: q <= h_ks(E_W0, E_W1);
      10'd149: q <= s2b(E_W0, B_BLOB_CT);                    // ciphertext is public
      10'd150: q <= s2b(E_W1, B_BLOB_CT + 9'd4);
      10'd151: q <= h_tag(SNK_SEED);
      10'd152: q <= s2b(E_TAG, B_BLOB_TAG);
      10'd153: q <= szero(E_W0);
      10'd154: q <= szero(E_W1);
      10'd155: q <= szero(E_KEK);

      // ---------------- KeyGen end (156) ----------------
      10'd156: q <= szero(E_D);
      10'd157: q <= szero(E_R);
      10'd158: q <= szero(E_RHO);
      10'd159: q <= szero(E_TMP);
      10'd160: q <= szero(E_CBD);                            // PRF scratch (and E_TAG)
      10'd161: q <= szero(E_CBD + 4'd1);
      10'd162: q <= szero(E_CBD + 4'd2);
      10'd163: q <= szero(E_CBD + 4'd3);
      10'd164: q <= pzero(S_T);
      10'd165: q <= pzero(Y0);
      10'd166: q <= pzero(Y0B);
      10'd167: q <= pzero(Y1);
      10'd168: q <= pzero(Y1B);
      10'd169: q <= pzero(Y2);
      10'd170: q <= pzero(Y2B);
      10'd171: q <= u_end(R_OK);

      // ---------------- ENCAPS (192), masked ----------------
      10'd192: q <= u_set(ST_RESEED);
      10'd193: q <= pzero(S_Z);                              // the all-zero slot (precharge reads)
      10'd194: q <= dec(DM_CHK, 4'd12, 1'b1, B_XIN,          S_T);   // ek modulus check
      10'd195: q <= dec(DM_CHK, 4'd12, 1'b1, B_XIN + 9'd48,  S_T);
      10'd196: q <= dec(DM_CHK, 4'd12, 1'b1, B_XIN + 9'd96,  S_T);
      10'd197: q <= u_br(BC_BAD, X_BADIN);
      10'd198: q <= u_br(BC_INJ, 10'd201);
      10'd199: q <= h_trng(E_M);
      10'd200: q <= u_br(BC_ALWAYS, 10'd203);
      10'd201: q <= b2s(B_INJM, E_M);                        // TEST: injected m
      10'd202: q <= sremask(E_M);
      10'd203: q <= h_hbuf(B_XIN, 8'd148, E_PH);             // H(ek)
      10'd204: q <= h_g(E_M, E_PH, E_K1, E_R);               // (K, r) = G(m || H(ek))
      10'd205: q <= h_prf(E_R, 8'd0);                        // y_0 (E_PH is scratch from here)
      10'd206: q <= cbd(Y0, Y0B, 1'b0);
      10'd207: q <= ntt(Y0);
      10'd208: q <= ntt(Y0B);
      10'd209: q <= h_prf(E_R, 8'd1);                        // y_1
      10'd210: q <= cbd(Y1, Y1B, 1'b0);
      10'd211: q <= ntt(Y1);
      10'd212: q <= ntt(Y1B);
      10'd213: q <= h_prf(E_R, 8'd2);                        // y_2
      10'd214: q <= cbd(Y2, Y2B, 1'b0);
      10'd215: q <= ntt(Y2);
      10'd216: q <= ntt(Y2B);
      // u_i = INTT(sum_j A^[j][i] o y^_j) + e1_i, A^[j][i] = SampleNTT(rho || i || j)
      10'd217: q <= h_xof(RHO_PEER, 8'd0, 8'd0, S_T);
      10'd218: q <= pwm(1'b0, S_ACC0, S_T, Y0);
      10'd219: q <= pwm(1'b0, S_ACC1, S_T, Y0B);
      10'd220: q <= h_xof(RHO_PEER, 8'd0, 8'd1, S_T);
      10'd221: q <= pwm(1'b1, S_ACC0, S_T, Y1);
      10'd222: q <= pwm(1'b1, S_ACC1, S_T, Y1B);
      10'd223: q <= h_xof(RHO_PEER, 8'd0, 8'd2, S_T);
      10'd224: q <= pwm(1'b1, S_ACC0, S_T, Y2);
      10'd225: q <= pwm(1'b1, S_ACC1, S_T, Y2B);
      10'd226: q <= intt(S_ACC0);
      10'd227: q <= intt(S_ACC1);
      10'd228: q <= h_prf(E_R, 8'd3);                        // + e1_0
      10'd229: q <= cbd(S_ACC0, S_ACC1, 1'b1);
      10'd230: q <= cmpro(4'd10, B_XOUT);                    // c1 part 0
      10'd231: q <= h_xof(RHO_PEER, 8'd1, 8'd0, S_T);
      10'd232: q <= pwm(1'b0, S_ACC0, S_T, Y0);
      10'd233: q <= pwm(1'b0, S_ACC1, S_T, Y0B);
      10'd234: q <= h_xof(RHO_PEER, 8'd1, 8'd1, S_T);
      10'd235: q <= pwm(1'b1, S_ACC0, S_T, Y1);
      10'd236: q <= pwm(1'b1, S_ACC1, S_T, Y1B);
      10'd237: q <= h_xof(RHO_PEER, 8'd1, 8'd2, S_T);
      10'd238: q <= pwm(1'b1, S_ACC0, S_T, Y2);
      10'd239: q <= pwm(1'b1, S_ACC1, S_T, Y2B);
      10'd240: q <= intt(S_ACC0);
      10'd241: q <= intt(S_ACC1);
      10'd242: q <= h_prf(E_R, 8'd4);                        // + e1_1
      10'd243: q <= cbd(S_ACC0, S_ACC1, 1'b1);
      10'd244: q <= cmpro(4'd10, B_XOUT + 9'd40);
      10'd245: q <= h_xof(RHO_PEER, 8'd2, 8'd0, S_T);
      10'd246: q <= pwm(1'b0, S_ACC0, S_T, Y0);
      10'd247: q <= pwm(1'b0, S_ACC1, S_T, Y0B);
      10'd248: q <= h_xof(RHO_PEER, 8'd2, 8'd1, S_T);
      10'd249: q <= pwm(1'b1, S_ACC0, S_T, Y1);
      10'd250: q <= pwm(1'b1, S_ACC1, S_T, Y1B);
      10'd251: q <= h_xof(RHO_PEER, 8'd2, 8'd2, S_T);
      10'd252: q <= pwm(1'b1, S_ACC0, S_T, Y2);
      10'd253: q <= pwm(1'b1, S_ACC1, S_T, Y2B);
      10'd254: q <= intt(S_ACC0);
      10'd255: q <= intt(S_ACC1);
      10'd256: q <= h_prf(E_R, 8'd5);                        // + e1_2
      10'd257: q <= cbd(S_ACC0, S_ACC1, 1'b1);
      10'd258: q <= cmpro(4'd10, B_XOUT + 9'd80);
      // v = INTT(sum_j t^_j o y^_j) + e2 + Decompress_1(m)
      10'd259: q <= dec(DM_WR, 4'd12, 1'b0, B_XIN,         S_T);
      10'd260: q <= pwm(1'b0, S_ACC0, S_T, Y0);
      10'd261: q <= pwm(1'b0, S_ACC1, S_T, Y0B);
      10'd262: q <= dec(DM_WR, 4'd12, 1'b0, B_XIN + 9'd48, S_T);
      10'd263: q <= pwm(1'b1, S_ACC0, S_T, Y1);
      10'd264: q <= pwm(1'b1, S_ACC1, S_T, Y1B);
      10'd265: q <= dec(DM_WR, 4'd12, 1'b0, B_XIN + 9'd96, S_T);
      10'd266: q <= pwm(1'b1, S_ACC0, S_T, Y2);
      10'd267: q <= pwm(1'b1, S_ACC1, S_T, Y2B);
      10'd268: q <= intt(S_ACC0);
      10'd269: q <= intt(S_ACC1);
      10'd270: q <= h_prf(E_R, 8'd6);                        // + e2
      10'd271: q <= cbd(S_ACC0, S_ACC1, 1'b1);
      10'd272: q <= mu(E_M);                                 // + mu (masked m)
      10'd273: q <= cmpro(4'd4, B_XOUT + 9'd120);            // c2
      10'd274: q <= s2s(E_K1, E_SK);                         // K -> session key (masked)
      10'd275: q <= u_set(ST_SKV);                           // role: initiator
      10'd276: q <= u_br(BC_KEXP, 10'd278);
      10'd277: q <= u_br(BC_ALWAYS, 10'd279);
      10'd278: q <= s2b(E_SK, B_K);                          // TEST / PERSO: K to the host
      10'd279: q <= szero(E_M);
      10'd280: q <= szero(E_R);
      10'd281: q <= szero(E_K1);
      10'd282: q <= szero(E_CBD);
      10'd283: q <= szero(E_CBD + 4'd1);
      10'd284: q <= szero(E_CBD + 4'd2);
      10'd285: q <= szero(E_CBD + 4'd3);
      10'd286: q <= pzero(S_ACC0);
      10'd287: q <= pzero(S_ACC1);
      10'd288: q <= pzero(Y0);
      10'd289: q <= pzero(Y0B);
      10'd290: q <= pzero(Y1);
      10'd291: q <= pzero(Y1B);
      10'd292: q <= pzero(Y2);
      10'd293: q <= pzero(Y2B);
      10'd294: q <= u_end(R_OK);

      // ---------------- DECAPS (320), masked ----------------
      10'd320: q <= u_br(BC_NOKEY, X_NOKEY);
      10'd321: q <= u_set(ST_RESEED);
      10'd322: q <= pzero(S_Z);                              // (TVLA traces start here)
      10'd323: q <= m_op(M_OKINI);
      // w = v' - INTT(s^T o NTT(u')), each share of s on its own
      10'd324: q <= dec(DM_WR, 4'd10, 1'b0, B_XIN,         S_T);
      10'd325: q <= ntt(S_T);
      10'd326: q <= pwm(1'b0, S_ACC0, S0, S_T);
      10'd327: q <= pwm(1'b0, S_ACC1, S1, S_T);
      10'd328: q <= dec(DM_WR, 4'd10, 1'b0, B_XIN + 9'd40, S_T);
      10'd329: q <= ntt(S_T);
      10'd330: q <= pwm(1'b1, S_ACC0, S2, S_T);
      10'd331: q <= pwm(1'b1, S_ACC1, S3, S_T);
      10'd332: q <= dec(DM_WR, 4'd10, 1'b0, B_XIN + 9'd80, S_T);
      10'd333: q <= ntt(S_T);
      10'd334: q <= pwm(1'b1, S_ACC0, S4, S_T);
      10'd335: q <= pwm(1'b1, S_ACC1, S5, S_T);
      10'd336: q <= intt(S_ACC0);
      10'd337: q <= intt(S_ACC1);
      10'd338: q <= dec(DM_RSUB, 4'd4, 1'b0, B_XIN + 9'd120, S_ACC0);   // w0 = v' - acc0
      // m' is decoded twice, each time with fresh masks and a fresh word order, and the
      // two results are compared share-wise (a fault in one decoding -> R_FAULT)
      10'd339: q <= cmpr1(E_MP);                             // m'
      10'd340: q <= cmpr1(E_CBD + 4'd1);                     // m' again (scratch entry)
      10'd341: q <= seq(E_MP, E_CBD + 4'd1);
      10'd342: q <= h_g(E_MP, E_H, E_K1, E_R);               // (K', r') = G(m' || h)
      10'd343: q <= h_j(1'b0);                               // K-bar = J(z || c)
      // re-encryption with masked y, e1, e2
      10'd344: q <= h_prf(E_R, 8'd0);
      10'd345: q <= cbd(Y0, Y0B, 1'b0);
      10'd346: q <= ntt(Y0);
      10'd347: q <= ntt(Y0B);
      10'd348: q <= h_prf(E_R, 8'd1);
      10'd349: q <= cbd(Y1, Y1B, 1'b0);
      10'd350: q <= ntt(Y1);
      10'd351: q <= ntt(Y1B);
      10'd352: q <= h_prf(E_R, 8'd2);
      10'd353: q <= cbd(Y2, Y2B, 1'b0);
      10'd354: q <= ntt(Y2);
      10'd355: q <= ntt(Y2B);
      // u_0
      10'd356: q <= h_xof(RHO_OWN, 8'd0, 8'd0, S_T);
      10'd357: q <= pwm(1'b0, S_ACC0, S_T, Y0);
      10'd358: q <= pwm(1'b0, S_ACC1, S_T, Y0B);
      10'd359: q <= h_xof(RHO_OWN, 8'd0, 8'd1, S_T);
      10'd360: q <= pwm(1'b1, S_ACC0, S_T, Y1);
      10'd361: q <= pwm(1'b1, S_ACC1, S_T, Y1B);
      10'd362: q <= h_xof(RHO_OWN, 8'd0, 8'd2, S_T);
      10'd363: q <= pwm(1'b1, S_ACC0, S_T, Y2);
      10'd364: q <= pwm(1'b1, S_ACC1, S_T, Y2B);
      10'd365: q <= intt(S_ACC0);
      10'd366: q <= intt(S_ACC1);
      10'd367: q <= h_prf(E_R, 8'd3);                        // + e1_0
      10'd368: q <= cbd(S_ACC0, S_ACC1, 1'b1);
      10'd369: q <= cmprc(4'd10, B_XIN);
      // u_1
      10'd370: q <= h_xof(RHO_OWN, 8'd1, 8'd0, S_T);
      10'd371: q <= pwm(1'b0, S_ACC0, S_T, Y0);
      10'd372: q <= pwm(1'b0, S_ACC1, S_T, Y0B);
      10'd373: q <= h_xof(RHO_OWN, 8'd1, 8'd1, S_T);
      10'd374: q <= pwm(1'b1, S_ACC0, S_T, Y1);
      10'd375: q <= pwm(1'b1, S_ACC1, S_T, Y1B);
      10'd376: q <= h_xof(RHO_OWN, 8'd1, 8'd2, S_T);
      10'd377: q <= pwm(1'b1, S_ACC0, S_T, Y2);
      10'd378: q <= pwm(1'b1, S_ACC1, S_T, Y2B);
      10'd379: q <= intt(S_ACC0);
      10'd380: q <= intt(S_ACC1);
      10'd381: q <= h_prf(E_R, 8'd4);                        // + e1_1
      10'd382: q <= cbd(S_ACC0, S_ACC1, 1'b1);
      10'd383: q <= cmprc(4'd10, B_XIN + 9'd40);
      // u_2
      10'd384: q <= h_xof(RHO_OWN, 8'd2, 8'd0, S_T);
      10'd385: q <= pwm(1'b0, S_ACC0, S_T, Y0);
      10'd386: q <= pwm(1'b0, S_ACC1, S_T, Y0B);
      10'd387: q <= h_xof(RHO_OWN, 8'd2, 8'd1, S_T);
      10'd388: q <= pwm(1'b1, S_ACC0, S_T, Y1);
      10'd389: q <= pwm(1'b1, S_ACC1, S_T, Y1B);
      10'd390: q <= h_xof(RHO_OWN, 8'd2, 8'd2, S_T);
      10'd391: q <= pwm(1'b1, S_ACC0, S_T, Y2);
      10'd392: q <= pwm(1'b1, S_ACC1, S_T, Y2B);
      10'd393: q <= intt(S_ACC0);
      10'd394: q <= intt(S_ACC1);
      10'd395: q <= h_prf(E_R, 8'd5);                        // + e1_2
      10'd396: q <= cbd(S_ACC0, S_ACC1, 1'b1);
      10'd397: q <= cmprc(4'd10, B_XIN + 9'd80);
      // v
      10'd398: q <= dec(DM_WR, 4'd12, 1'b0, B_EKOWN,         S_T);
      10'd399: q <= pwm(1'b0, S_ACC0, S_T, Y0);
      10'd400: q <= pwm(1'b0, S_ACC1, S_T, Y0B);
      10'd401: q <= dec(DM_WR, 4'd12, 1'b0, B_EKOWN + 9'd48, S_T);
      10'd402: q <= pwm(1'b1, S_ACC0, S_T, Y1);
      10'd403: q <= pwm(1'b1, S_ACC1, S_T, Y1B);
      10'd404: q <= dec(DM_WR, 4'd12, 1'b0, B_EKOWN + 9'd96, S_T);
      10'd405: q <= pwm(1'b1, S_ACC0, S_T, Y2);
      10'd406: q <= pwm(1'b1, S_ACC1, S_T, Y2B);
      10'd407: q <= intt(S_ACC0);
      10'd408: q <= intt(S_ACC1);
      10'd409: q <= h_prf(E_R, 8'd6);                        // + e2
      10'd410: q <= cbd(S_ACC0, S_ACC1, 1'b1);
      10'd411: q <= mu(E_MP);                                // + mu
      10'd412: q <= cmprc(4'd4, B_XIN + 9'd120);
      10'd413: q <= m_op(M_OKCHK);                           // the two ok copies must agree
      10'd414: q <= u_mask(M_SEL, 4'd0, E_SK, 4'd0, 1'b0, B_K, E_K1, E_KB, 1'b1); // K, kept masked
      10'd415: q <= u_set(ST_SKVR);                          // role: responder
      10'd416: q <= u_br(BC_KEXP, 10'd418);
      10'd417: q <= u_br(BC_ALWAYS, 10'd419);
      10'd418: q <= s2b(E_SK, B_K);                          // TEST / PERSO: K to the host
      10'd419: q <= szero(E_MP);
      10'd420: q <= szero(E_K1);
      10'd421: q <= szero(E_R);
      10'd422: q <= szero(E_KB);
      10'd423: q <= szero(E_CBD);
      10'd424: q <= szero(E_CBD + 4'd1);
      10'd425: q <= szero(E_CBD + 4'd2);
      10'd426: q <= szero(E_CBD + 4'd3);
      10'd427: q <= pzero(S_ACC0);
      10'd428: q <= pzero(S_ACC1);
      10'd429: q <= pzero(Y0);
      10'd430: q <= pzero(Y0B);
      10'd431: q <= pzero(Y1);
      10'd432: q <= pzero(Y1B);
      10'd433: q <= pzero(Y2);
      10'd434: q <= pzero(Y2B);
      10'd435: q <= u_end(R_OK);

      // ---------------- SEAL (448) ----------------
      10'd448: q <= u_br(BC_NOSK, X_NOSK);
      10'd449: q <= trunc(1'b0);                             // L in 1..128? M bytes from L on := 0
      10'd450: q <= u_br(BC_BAD, X_BADIN);                   // (no counter used up)
      10'd451: q <= u_set(ST_RESEED);
      10'd452: q <= ctr(IO_CTRW);                            // header: counter, L, 0, 0
      10'd453: q <= u_set(ST_TXINC);                         // counted before use: never reused
      10'd454: q <= u_br(BC_ROLE, 10'd459);
      10'd455: q <= h_kks(KC_E1);                            // initiator -> responder
      10'd456: q <= trunc(1'b0);                             // C bytes from L on := 0
      10'd457: q <= h_ktag(SNK_SEED, KC_T1);
      10'd458: q <= u_br(BC_ALWAYS, 10'd462);
      10'd459: q <= h_kks(KC_E2);                            // responder -> initiator
      10'd460: q <= trunc(1'b0);
      10'd461: q <= h_ktag(SNK_SEED, KC_T2);
      10'd462: q <= s2b(E_TAG, B_SM_TAG);
      10'd463: q <= szero(E_TAG);
      10'd464: q <= u_end(R_OK);

      // ---------------- OPEN (480) ----------------
      10'd480: q <= u_br(BC_NOSK, X_NOSK);
      10'd481: q <= ctr(IO_CTRC);                            // replay window check
      10'd482: q <= u_br(BC_BAD, X_REPLAY);
      10'd483: q <= trunc(1'b1);                             // length check only
      10'd484: q <= u_br(BC_BAD, X_BADTAG);                  // (a sender never seals such a length)
      10'd485: q <= u_set(ST_RESEED);
      10'd486: q <= m_op(M_OKINI);
      10'd487: q <= u_br(BC_ROLE, 10'd490);
      10'd488: q <= h_ktag(SNK_MCMP, KC_T2);                 // initiator opens R -> I
      10'd489: q <= u_br(BC_ALWAYS, 10'd491);
      10'd490: q <= h_ktag(SNK_MCMP, KC_T1);                 // responder opens I -> R
      10'd491: q <= m_op(M_OKCHK);                           // the two ok copies must agree
      10'd492: q <= m_op(M_OKOUT);
      10'd493: q <= u_br(BC_BAD, X_BADTAG);                  // stays encrypted, window unchanged
      10'd494: q <= u_set(ST_RXACC);                         // authentic: mark the counter
      10'd495: q <= u_br(BC_ROLE, 10'd499);
      10'd496: q <= h_kks(KC_E2);
      10'd497: q <= trunc(1'b0);                             // plaintext bytes from L on := 0
      10'd498: q <= u_end(R_OK);
      10'd499: q <= h_kks(KC_E1);
      10'd500: q <= trunc(1'b0);
      10'd501: q <= u_end(R_OK);

      // ---------------- IMPORT (512): TEST / PERSO ----------------
      10'd512: q <= u_set(ST_RESEED);
      10'd513: q <= h_hbuf(B_EKOWN, 8'd148, E_H);
      10'd514: q <= scmpn(E_H, B_INJH, 4'd0);                // dk hash check (4 lanes)
      10'd515: q <= u_br(BC_BAD, X_BADIN);
      10'd516: q <= dec(DM_WR, 4'd12, 1'b0, B_XIN,         S0);
      10'd517: q <= msplit(S0, S1);                          // s^_0 -> shares S0, S1
      10'd518: q <= dec(DM_WR, 4'd12, 1'b0, B_XIN + 9'd48, S2);
      10'd519: q <= msplit(S2, S3);
      10'd520: q <= dec(DM_WR, 4'd12, 1'b0, B_XIN + 9'd96, S4);
      10'd521: q <= msplit(S4, S5);
      10'd522: q <= b2s(B_INJZ, E_Z);
      10'd523: q <= sremask(E_Z);
      10'd524: q <= u_set(ST_KEYV);
      10'd525: q <= u_end(R_OK);

      // ---------------- ENROLL (528): TEST / PERSO ----------------
      10'd528: q <= u_set(ST_RESEED);
      10'd529: q <= h_trng(E_TMP);                           // k (masked)
      10'd530: q <= u_puf(PF_ENROLL, E_TMP, B_HELP);         // helper -> 15 lanes, k canonical
      10'd531: q <= h_kchk(E_TMP, E_W0);
      10'd532: q <= s2bn(E_W0, B_HELP_CHK, 4'd1);            // check value -> helper lane 15
      10'd533: q <= szero(E_W0);
      10'd534: q <= szero(E_TMP);
      10'd535: q <= u_end(R_OK);

      // ---------------- PUFRAW (544) / TRNGRAW (548): TEST ----------------
      10'd544: q <= u_puf(PF_RAW, 4'd0, B_XOUT);             // 960 bits -> 15 lanes
      10'd545: q <= u_end(R_OK);
      10'd548: q <= u_io(IO_T2B, DM_WR, 4'd0, 1'b0, 1'b0, B_XOUT, 4'd0, 4'd0, 4'd0); // 136 words
      10'd549: q <= u_end(R_OK);

      // ---------------- ZEROIZE (560) ----------------
      10'd560: q <= pzero(4'd0);   10'd561: q <= pzero(4'd1);   10'd562: q <= pzero(4'd2);
      10'd563: q <= pzero(4'd3);   10'd564: q <= pzero(4'd4);   10'd565: q <= pzero(4'd5);
      10'd566: q <= pzero(4'd6);   10'd567: q <= pzero(4'd7);   10'd568: q <= pzero(4'd8);
      10'd569: q <= pzero(4'd9);   10'd570: q <= pzero(4'd10);  10'd571: q <= pzero(4'd11);
      10'd572: q <= pzero(4'd12);  10'd573: q <= pzero(4'd13);  10'd574: q <= pzero(4'd14);
      10'd575: q <= pzero(4'd15);
      10'd576: q <= szero(4'd0);   10'd577: q <= szero(4'd1);   10'd578: q <= szero(4'd2);
      10'd579: q <= szero(4'd3);   10'd580: q <= szero(4'd4);   10'd581: q <= szero(4'd5);
      10'd582: q <= szero(4'd6);   10'd583: q <= szero(4'd7);   10'd584: q <= szero(4'd8);
      10'd585: q <= szero(4'd9);   10'd586: q <= szero(4'd10);  10'd587: q <= szero(4'd11);
      10'd588: q <= szero(4'd12);  10'd589: q <= szero(4'd13);  10'd590: q <= szero(4'd14);
      10'd591: q <= szero(4'd15);
      10'd592: q <= s2b(E_TMP, B_K);                         // E_TMP is 0 now
      10'd593: q <= s2b(E_TMP, B_TMP);
      10'd594: q <= s2b(E_TMP, B_SM);                        // secure-message window
      10'd595: q <= s2b(E_TMP, B_SM + 9'd4);
      10'd596: q <= s2b(E_TMP, B_SM + 9'd8);
      10'd597: q <= s2b(E_TMP, B_SM + 9'd12);
      10'd598: q <= s2b(E_TMP, B_SM + 9'd16);
      10'd599: q <= s2b(E_TMP, B_SM + 9'd20);
      10'd600: q <= u_set(ST_KEYC);
      10'd601: q <= u_set(ST_SKC);
      10'd602: q <= u_end(R_OK);

      default: q <= u_end(R_UNKNOWN);
    endcase
  end
endmodule
