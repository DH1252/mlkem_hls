#!/usr/bin/env python3
"""Microcode of the PQSE secure element v1.5: the programs with labels, laid out
at fixed segment addresses, written into the case table of
hw/se_v1_5/pqse_ucode.v (between the "generated" markers).

  python3 scripts/pqse_ucode_v15_gen.py

The entry points must match the EP_* constants in hw/se_v1_5/pqse_defs.vh (the
script checks that), and the fault-injection addresses at the top of
hw/sim/tb_pqse_v15.sv must be updated by hand if the layout moves.
The instruction builders (h_prf, cbd, dec, ...) are Verilog functions in
pqse_ucode.v; this script only writes their calls.
"""
import re
import sys

prog = []          # (addr, expr, comment)
labels = {}
pc = 0

def org(a):
    global pc
    assert a >= pc, (hex(a), hex(pc))
    pc = a

def L(name):
    assert name not in labels, name
    labels[name] = pc

def I(expr, comment=""):
    global pc
    prog.append((pc, expr, comment))
    pc += 1

def ref(name):
    return "{%s}" % name

# ---------------------------------------------------------------- failure exits
org(0)
for r in ["R_BADIN", "R_NOKEY", "R_BADBLOB", "R_DENIED", "R_BADTAG", "R_NOSK", "R_REPLAY", "R_PUF"]:
    I("u_end(%s)" % r)
I("u_end(R_FAULT)", "X_KGF: a KeyGen recompute check failed")
X = dict(X_BADIN=0, X_NOKEY=1, X_BADBLOB=2, X_DENIED=3, X_BADTAG=4, X_NOSK=5, X_REPLAY=6, X_PUF=7, X_KGF=8)
labels.update(X)

# ---------------------------------------------------------------- KEYGEN / KGWRAP (16)
org(16); L("EP_KEYGEN")
I("u_set(ST_RESEED)")
I("u_br(BC_WRAP, %s)" % ref("L_PREC"), "KGWRAP: KEK first (no key yet if it fails)")
L("L_KGSEED")
I("u_br(BC_INJ, %s)" % ref("L_KGINJ"))
I("h_trng(E_D)")
I("h_trng(E_Z)")
I("u_br(BC_ALWAYS, %s)" % ref("L_KG"))
L("L_KGINJ")
I("b2s(B_INJD, E_D, AM_NONE)", "TEST: injected d, z")
I("sremask(E_D)")
I("b2s(B_INJZ, E_Z, AM_NONE)")
I("sremask(E_Z)")
I("u_br(BC_ALWAYS, %s)" % ref("L_KG"))

# ---------------------------------------------------------------- UNWRAP (32)
org(32); L("EP_UNWRAP")
I("u_set(ST_RESEED)")
I("u_br(BC_ALWAYS, %s)" % ref("L_PREC"), "PUF key -> KEK, back to L_UWK")
L("L_UWK")
I("m_op(M_OKINI)")
I("h_tag(SNK_MCMP)", "masked tag check")
I("m_op(M_OKCHK)", "the two ok copies must agree")
I("m_op(M_OKOUT)")
I("u_br(BC_BAD, %s)" % ref("L_UWFAIL"))
I("b2s(B_BLOB_CT, E_D, AM_NONE)")
I("b2s(B_BLOB_CT + 9'd4, E_Z, AM_NONE)")
I("h_ks(E_D, E_Z)", "d, z now masked plaintext")
I("szero(E_KEK)")
I("u_br(BC_ALWAYS, %s)" % ref("L_KG"))
L("L_UWFAIL")
I("szero(E_KEK)")
I("u_br(BC_ALWAYS, %s)" % ref("X_BADBLOB"))

# ---------------------------------------------------------------- PUF key -> KEK (48)
org(48); L("L_PREC")
I("u_puf(PF_RECON, E_PUF, B_HELP)", "one read per bit")
I("h_kchk(E_PUF, E_TMP)")
I("scmpn(E_TMP, B_HELP_CHK, 4'd1, AM_NONE)", "64-bit check value")
I("u_br(BC_NBAD, %s)" % ref("L_PROK"))
I("u_set(ST_BADC)")
I("u_puf(PF_RECON3, E_PUF, B_HELP)", "retry: majority of 3 reads")
I("h_kchk(E_PUF, E_TMP)")
I("scmpn(E_TMP, B_HELP_CHK, 4'd1, AM_NONE)")
I("u_br(BC_NBAD, %s)" % ref("L_PROK"))
I("u_set(ST_BADC)")
I("u_puf(PF_RECON5, E_PUF, B_HELP)", "retry: majority of 5 reads")
I("h_kchk(E_PUF, E_TMP)")
I("scmpn(E_TMP, B_HELP_CHK, 4'd1, AM_NONE)")
I("u_br(BC_BAD, %s)" % ref("L_PFAIL"))
L("L_PROK")
I("szero(E_TMP)")
I("h_kek(1'b0)")
I("szero(E_PUF)")
I("u_br(BC_WRAP, %s)" % ref("L_KGSEED"), "KGWRAP: on to KeyGen")
I("u_br(BC_ALWAYS, %s)" % ref("L_UWK"), "UNWRAP: on to the tag check")
L("L_PFAIL")
I("szero(E_PUF)")
I("szero(E_TMP)")
I("u_br(BC_ALWAYS, %s)" % ref("X_PUF"))

# ---------------------------------------------------------------- KeyGen core (80)
org(80); L("L_KG")
I("h_gk(SNK_SEED)", "(rho, sigma) = G(d || k) -> E_RHO, E_R")
I("s2b(E_RHO, B_EKOWN, AM_48K)", "rho is public: after t^ in the own ek")
I("s2b(E_RHO, B_TMP, AM_NONE)", "... and where the XOF reads it")
I("szero(E_KB)", "all-zero reference entry (G check)")
I("scmpn(E_RHO, B_EKOWN, 4'd0, AM_48K)", "rho in the buffer = rho of G (public)")
I("u_br(BC_BAD, %s)" % ref("X_KGF"))
# s_i, computed twice and compared
L("L_KGS")
I("h_prf(E_R, 8'd0, HM_PI1)", "s_i: PRF(sigma, i), eta1")
I("cbd(L_SI0, L_SI1, 1'b0, 1'b1)", "copy 1 (shares)")
I("h_prf(E_R, 8'd0, HM_PI1)", "the PRF again")
I("cbd(L_ACC0, L_ACC1, 1'b0, 1'b1)", "copy 2: fresh masks, own order")
I("ntt(L_SI0)"); I("ntt(L_SI1)"); I("ntt(L_ACC0)"); I("ntt(L_ACC1)")
I("psub(L_ACC0, L_SI0)", "share 0: y0 - x0")
I("psub(L_ACC1, L_SI1)", "share 1: y1 - x1")
I("pzchk(L_ACC0, L_ACC1)", "sum 0 everywhere, else FAULT")
I("u_loop(1'b0, %s)" % ref("L_KGS"), "next i < k")
L("L_KGE")
I("h_prf(E_R, 8'd0, HM_PKI1)", "e_i: PRF(sigma, k + i), eta1")
I("cbd(L_YI0, L_YI1, 1'b0, 1'b1)")
I("h_prf(E_R, 8'd0, HM_PKI1)")
I("cbd(L_ACC0, L_ACC1, 1'b0, 1'b1)")
I("ntt(L_YI0)"); I("ntt(L_YI1)"); I("ntt(L_ACC0)"); I("ntt(L_ACC1)")
I("psub(L_ACC0, L_YI0)")
I("psub(L_ACC1, L_YI1)")
I("pzchk(L_ACC0, L_ACC1)")
I("u_loop(1'b0, %s)" % ref("L_KGE"))
I("h_gk(SNK_SXOR)", "G(d || k) again, XORed into rho, sigma")
I("seq(E_RHO, E_KB)")
I("seq(E_R, E_KB)", "(sigma is not needed after the PRFs)")
# t^_i = e^_i + sum_j A^[i][j] o s^_j, per share
L("L_KGA")
I("h_xof(B_TMP, HM_XOF, L_T)", "A^[i][j] = SampleNTT(rho || j || i)")
I("pwm(1'b1, L_YI0, L_T, L_SJ0)")
I("pwm(1'b1, L_YI1, L_T, L_SJ1)")
I("u_loop(1'b1, %s)" % ref("L_KGA"), "next j < k")
I("padd(L_YI0, L_YI1)", "t^_i is public: unmask")
I("enc12(L_YI0, B_EKOWN, AM_48I)")
I("u_loop(1'b0, %s)" % ref("L_KGA"), "next i < k")
I("h_hek(B_EKOWN, E_H)", "H(ek), 48 k + 4 lanes")
I("u_br(BC_KGEN, %s)" % ref("L_PCT"), "KEYGEN / KGWRAP: PCT first")
L("L_KGV")
I("u_set(ST_KEYV)", "s^ and z stay masked; key_k := k")
I("u_br(BC_WRAP, %s)" % ref("L_WRAP"))
I("u_br(BC_ALWAYS, %s)" % ref("L_KGEND"))
L("L_WRAP")
I("h_trng(E_TMP)")
I("s2bn(E_TMP, B_BLOB_NONCE, 4'd2)", "nonce (2 lanes)")
I("s2s(E_D, E_W0)")
I("s2s(E_Z, E_W1)")
I("h_ks(E_W0, E_W1)")
I("s2b(E_W0, B_BLOB_CT, AM_NONE)", "ciphertext is public")
I("s2b(E_W1, B_BLOB_CT + 9'd4, AM_NONE)")
I("h_tag(SNK_SEED)")
I("s2b(E_TAG, B_BLOB_TAG, AM_NONE)")
I("szero(E_W0)")
I("szero(E_W1)")
I("szero(E_KEK)")
L("L_KGEND")
I("szero(E_D)"); I("szero(E_R)"); I("szero(E_RHO)")
for k in range(6):
    I("szero(E_CBD + 4'd%d)" % k, "PRF scratch (E_PUF, E_TMP, E_PH, E_W0, E_W1, E_TAG)" if k == 0 else "")
I("pzero(L_T)"); I("pzero(L_ACC0)"); I("pzero(L_ACC1)")
L("L_KGZ")
I("pzero(L_YI0)"); I("pzero(L_YI1)")
I("u_loop(1'b0, %s)" % ref("L_KGZ"))
I("u_end(R_OK)")

def y_loop(tag):
    L(tag)
    I("h_prf(E_R, 8'd0, HM_PI1)", "y_i: PRF(r, i), eta1")
    I("cbd(L_YI0, L_YI1, 1'b0, 1'b1)")
    I("ntt(L_YI0)")
    I("ntt(L_YI1)")
    I("u_loop(1'b0, %s)" % ref(tag))

def v_part(tag, ek, m, cmpr):
    # v = INTT(sum_j t^_j o y^_j) + e2 + Decompress_1(m)
    I("pzero(L_ACC0)")
    I("pzero(L_ACC1)")
    L(tag)
    I("dec(DM_WR, 4'd12, 1'b0, %s, L_T, AM_48J)" % ek, "t^_j")
    I("pwm(1'b1, L_ACC0, L_T, L_YJ0)")
    I("pwm(1'b1, L_ACC1, L_T, L_YJ1)")
    I("u_loop(1'b1, %s)" % ref(tag))
    I("intt(L_ACC0)"); I("intt(L_ACC1)")
    I("h_prf(E_R, 8'd0, HM_P2K2)", "+ e2: PRF(r, 2k), eta2")
    I("cbd(L_ACC0, L_ACC1, 1'b1, 1'b0)")
    I("mu(%s)" % m, "+ mu (masked m)")
    I("%s(D_DV, B_XIN, AM_DUK)" % cmpr, "c2 = Compress_dv(v)")

def u_part(tag, cmpr):
    # u_i = INTT(sum_j A^[j][i] o y^_j) + e1_i
    L(tag)
    I("pzero(L_ACC0)")
    I("pzero(L_ACC1)")
    L(tag + "J")
    I("h_xof(B_TMP, HM_XOFT, L_T)", "A^[j][i] = SampleNTT(rho || i || j)")
    I("pwm(1'b1, L_ACC0, L_T, L_YJ0)")
    I("pwm(1'b1, L_ACC1, L_T, L_YJ1)")
    I("u_loop(1'b1, %s)" % ref(tag + "J"))
    I("intt(L_ACC0)"); I("intt(L_ACC1)")
    I("h_prf(E_R, 8'd0, HM_PKI2)", "+ e1_i: PRF(r, k + i), eta2")
    I("cbd(L_ACC0, L_ACC1, 1'b1, 1'b0)")
    I("%s(D_DU, B_XIN, AM_DUI)" % cmpr, "c1 part i = Compress_du(u_i)")
    I("u_loop(1'b0, %s)" % ref(tag))

def rho_copy(ek):
    I("b2s(%s, E_TMP, AM_48K)" % ek, "rho of the key in use ...")
    I("s2b(E_TMP, B_TMP, AM_NONE)", "... to where the XOF reads it")
    I("szero(E_TMP)")

# ---------------------------------------------------------------- ENCAPS
org((pc + 15) // 16 * 16); L("EP_ENCAPS")
I("u_set(ST_RESEED)")
I("pzero(L_Z)", "the all-zero slot (precharge reads)")
L("L_ENCHK")
I("dec(DM_CHK, 4'd12, 1'b1, B_XIN, L_T, AM_48I)", "ek modulus check, t^_i")
I("u_loop(1'b0, %s)" % ref("L_ENCHK"))
I("u_br(BC_BAD, %s)" % ref("X_BADIN"))
I("u_br(BC_INJ, %s)" % ref("L_ENINJ"))
I("h_trng(E_M)")
I("u_br(BC_ALWAYS, %s)" % ref("L_ENM"))
L("L_ENINJ")
I("b2s(B_INJM, E_M, AM_NONE)", "TEST: injected m")
I("sremask(E_M)")
L("L_ENM")
I("h_hek(B_XIN, E_PH)", "H(ek)")
I("h_g(E_M, E_PH, E_K1, E_R)", "(K, r) = G(m || H(ek))")
rho_copy("B_XIN")
y_loop("L_ENY")
# v first: the ciphertext is written over the peer ek, whose t^ is read here
v_part("L_ENV", "B_XIN", "E_M", "cmpro")
u_part("L_ENU", "cmpro")
I("s2s(E_K1, E_SK)", "K -> session key (masked)")
I("u_set(ST_SKV)", "role: initiator")
I("u_br(BC_KEXP, %s)" % ref("L_ENKX"))
I("u_br(BC_ALWAYS, %s)" % ref("L_ENW"))
L("L_ENKX")
I("s2b(E_SK, B_K, AM_NONE)", "TEST / PERSO: K to the host")
L("L_ENW")
I("szero(E_M)"); I("szero(E_R)"); I("szero(E_K1)")
for k in range(6):
    I("szero(E_CBD + 4'd%d)" % k)
I("pzero(L_T)"); I("pzero(L_ACC0)"); I("pzero(L_ACC1)")
L("L_ENZ")
I("pzero(L_YI0)"); I("pzero(L_YI1)")
I("u_loop(1'b0, %s)" % ref("L_ENZ"))
I("u_end(R_OK)")

# ---------------------------------------------------------------- DECAPS
org((pc + 15) // 16 * 16); L("EP_DECAPS")
I("u_br(BC_NOKEY, %s)" % ref("X_NOKEY"))
I("u_set(ST_RESEED)")
I("pzero(L_Z)", "(TVLA traces start here)")
I("m_op(M_OKINI)")
rho_copy("B_EKOWN")
# w = v' - INTT(s^T o NTT(u')), each share of s on its own
I("pzero(L_ACC0)")
I("pzero(L_ACC1)")
L("L_DEW")
I("dec(DM_WR, D_DU, 1'b0, B_XIN, L_T, AM_DUI)", "u'_i")
I("ntt(L_T)")
I("pwm(1'b1, L_ACC0, L_SI0, L_T)")
I("pwm(1'b1, L_ACC1, L_SI1, L_T)")
I("u_loop(1'b0, %s)" % ref("L_DEW"))
I("intt(L_ACC0)"); I("intt(L_ACC1)")
I("dec(DM_RSUB, D_DV, 1'b0, B_XIN, L_ACC0, AM_DUK)", "w0 = v' - acc0")
I("cmpr1(E_MP)", "m' (fresh masks, fresh order) ...")
I("cmpr1(E_CBD + 4'd1)", "... again (scratch entry)")
I("seq(E_MP, E_CBD + 4'd1)", "the two decodings must agree")
I("h_g(E_MP, E_H, E_K1, E_R)", "(K', r') = G(m' || h)")
I("h_j(1'b0)", "K-bar = J(z || c), ciphertext lanes of k")
y_loop("L_DEY")
u_part("L_DEU", "cmprc")
v_part("L_DEV", "B_EKOWN", "E_MP", "cmprc")
I("m_op(M_OKCHK)", "the two ok copies must agree")
I("u_mask(M_SEL, 4'd0, E_SK, 4'd0, 1'b0, B_K, E_K1, E_KB, 1'b1, AM_NONE, 1'b0)", "K, kept masked")
I("u_set(ST_SKVR)", "role: responder")
I("u_br(BC_KEXP, %s)" % ref("L_DEKX"))
I("u_br(BC_ALWAYS, %s)" % ref("L_DEW2"))
L("L_DEKX")
I("s2b(E_SK, B_K, AM_NONE)", "TEST / PERSO: K to the host")
L("L_DEW2")
I("szero(E_MP)"); I("szero(E_K1)"); I("szero(E_R)"); I("szero(E_KB)")
for k in range(6):
    I("szero(E_CBD + 4'd%d)" % k)
I("pzero(L_T)"); I("pzero(L_ACC0)"); I("pzero(L_ACC1)")
L("L_DEZ")
I("pzero(L_YI0)"); I("pzero(L_YI1)")
I("u_loop(1'b0, %s)" % ref("L_DEZ"))
I("u_end(R_OK)")

# ---------------------------------------------------------------- SEAL
org((pc + 15) // 16 * 16); L("EP_SEAL")
I("u_br(BC_NOSK, %s)" % ref("X_NOSK"))
I("trunc(1'b0)", "L in 1..128? M bytes from L on := 0")
I("u_br(BC_BAD, %s)" % ref("X_BADIN"), "(no counter used up)")
I("u_set(ST_RESEED)")
I("ctr(IO_CTRW)", "header: counter, L, 0, 0")
I("u_set(ST_TXINC)", "counted before use: never reused")
I("u_br(BC_ROLE, %s)" % ref("L_SER"))
I("h_kks(KC_E1)", "initiator -> responder")
I("trunc(1'b0)", "C bytes from L on := 0")
I("h_ktag(SNK_SEED, KC_T1)")
I("u_br(BC_ALWAYS, %s)" % ref("L_SET"))
L("L_SER")
I("h_kks(KC_E2)", "responder -> initiator")
I("trunc(1'b0)")
I("h_ktag(SNK_SEED, KC_T2)")
L("L_SET")
I("s2b(E_TAG, B_SM_TAG, AM_NONE)")
I("szero(E_TAG)")
I("u_end(R_OK)")

# ---------------------------------------------------------------- OPEN
org((pc + 15) // 16 * 16); L("EP_OPEN")
I("u_br(BC_NOSK, %s)" % ref("X_NOSK"))
I("ctr(IO_CTRC)", "replay window check")
I("u_br(BC_BAD, %s)" % ref("X_REPLAY"))
I("trunc(1'b1)", "length check only")
I("u_br(BC_BAD, %s)" % ref("X_BADTAG"), "(a sender never seals such a length)")
I("u_set(ST_RESEED)")
I("m_op(M_OKINI)")
I("u_br(BC_ROLE, %s)" % ref("L_OPR"))
I("h_ktag(SNK_MCMP, KC_T2)", "initiator opens R -> I")
I("u_br(BC_ALWAYS, %s)" % ref("L_OPC"))
L("L_OPR")
I("h_ktag(SNK_MCMP, KC_T1)", "responder opens I -> R")
L("L_OPC")
I("m_op(M_OKCHK)", "the two ok copies must agree")
I("m_op(M_OKOUT)")
I("u_br(BC_BAD, %s)" % ref("X_BADTAG"), "stays encrypted, window unchanged")
I("u_set(ST_RXACC)", "authentic: mark the counter")
I("u_br(BC_ROLE, %s)" % ref("L_OPD"))
I("h_kks(KC_E2)")
I("trunc(1'b0)", "plaintext bytes from L on := 0")
I("u_end(R_OK)")
L("L_OPD")
I("h_kks(KC_E1)")
I("trunc(1'b0)")
I("u_end(R_OK)")

# ---------------------------------------------------------------- IMPORT
org((pc + 15) // 16 * 16); L("EP_IMPORT")
I("u_set(ST_RESEED)")
I("h_hek(B_EKOWN, E_H)")
I("scmpn(E_H, B_INJH, 4'd0, AM_NONE)", "dk hash check (4 lanes)")
I("u_br(BC_BAD, %s)" % ref("X_BADIN"))
L("L_IMS")
I("dec(DM_WR, 4'd12, 1'b0, B_XIN, L_SI0, AM_48I)", "s^_i bytes")
I("msplit(L_SI0, L_SI1)", "-> shares")
I("u_loop(1'b0, %s)" % ref("L_IMS"))
I("pzero(L_Z)")
L("L_IMW")
I("enc12(L_Z, B_XIN, AM_48I)", "wipe the s^ bytes (B_XIN becomes readable after ENCAPS)")
I("u_loop(1'b0, %s)" % ref("L_IMW"))
I("b2s(B_INJZ, E_Z, AM_NONE)")
I("sremask(E_Z)")
I("u_set(ST_KEYV)", "key_k := k")
I("u_end(R_OK)")

# ---------------------------------------------------------------- ENROLL / PUFRAW / TRNGRAW
org((pc + 15) // 16 * 16); L("EP_ENROLL")
I("u_set(ST_RESEED)")
I("h_trng(E_TMP)", "k (masked)")
I("u_puf(PF_ENROLL, E_TMP, B_HELP)", "helper -> 15 lanes, k canonical")
I("h_kchk(E_TMP, E_W0)")
I("s2bn(E_W0, B_HELP_CHK, 4'd1)", "check value -> helper lane 15")
I("szero(E_W0)")
I("szero(E_TMP)")
I("u_end(R_OK)")
L("EP_PUFRAW")
I("u_puf(PF_RAW, 4'd0, B_XIN)", "960 bits -> 15 lanes")
I("u_end(R_OK)")
L("EP_TRNGRAW")
I("u_io(IO_T2B, DM_WR, 4'd0, 1'b0, 1'b0, B_XIN, 4'd0, 4'd0, 4'd0, AM_NONE)", "136 words")
I("u_end(R_OK)")

# ---------------------------------------------------------------- ZEROIZE
org((pc + 15) // 16 * 16); L("EP_ZEROIZE")
L("L_ZP")
I("pzero(L_SI0)", "slot 2i, i = 0..9: all 20 slots")
I("pzero(L_SI1)")
I("u_loopn(1'b0, %s, 4'd10)" % ref("L_ZP"))
for e in range(16):
    I("szero(4'd%d)" % e)
I("s2b(E_TMP, B_K, AM_NONE)", "E_TMP is 0 now")
I("s2b(E_TMP, B_TMP, AM_NONE)")
for k in range(6):
    I("s2b(E_TMP, B_SM + 9'd%d, AM_NONE)" % (4 * k), "secure-message window" if k == 0 else "")
I("u_set(ST_KEYC)")
I("u_set(ST_SKC)")
I("u_end(R_OK)")

# ---------------------------------------------------------------- PCT
org((pc + 15) // 16 * 16); L("L_PCT")
I("pzero(L_Z)", "the all-zero slot (precharge reads)")
I("h_trng(E_M)", "m (masked)")
I("h_hek(B_EKOWN, E_PH)", "H(ek) of the published ek")
I("h_g(E_M, E_PH, E_K1, E_R)", "(K, r) = G(m || H(ek))")
y_loop("L_PCY")
v_part("L_PCV", "B_EKOWN", "E_M", "cmpro")
u_part("L_PCU", "cmpro")
# Decaps of the test ciphertext (in B_XIN) with the new s^
I("pzero(L_ACC0)")
I("pzero(L_ACC1)")
L("L_PCW")
I("dec(DM_WR, D_DU, 1'b0, B_XIN, L_T, AM_DUI)")
I("ntt(L_T)")
I("pwm(1'b1, L_ACC0, L_SI0, L_T)")
I("pwm(1'b1, L_ACC1, L_SI1, L_T)")
I("u_loop(1'b0, %s)" % ref("L_PCW"))
I("intt(L_ACC0)"); I("intt(L_ACC1)")
I("dec(DM_RSUB, D_DV, 1'b0, B_XIN, L_ACC0, AM_DUK)", "w0 = v' - acc0")
I("cmpr1(E_TMP)", "m'")
I("h_g(E_TMP, E_H, E_KB, E_R)", "(K', r') = G(m' || h), h of dk")
I("seq(E_K1, E_KB)", "K' != K: FAULT (key never valid)")
I("szero(E_M)"); I("szero(E_TMP)"); I("szero(E_K1)"); I("szero(E_KB)")
I("pzero(L_ACC0)"); I("pzero(L_ACC1)")
I("u_br(BC_ALWAYS, %s)" % ref("L_KGV"), "the rest is wiped at L_KGEND")

end = pc
# ---------------------------------------------------------------- output
def fmt(expr):
    return re.sub(r"\{(\w+)\}", lambda m: "10'd%d" % labels[m.group(1)], expr)

out = []
for a, e, c in prog:
    line = "      10'd%d:%s ins = %s;" % (a, " " * (4 - len(str(a))), fmt(e))
    if c:
        line = line.ljust(84) + " // " + c
    out.append(line)

root = sys.argv[1] if len(sys.argv) > 1 else "."
defs = open(root + "/hw/se_v1_5/pqse_defs.vh").read()
for ep in ["EP_KEYGEN", "EP_UNWRAP", "EP_ENCAPS", "EP_DECAPS", "EP_SEAL", "EP_OPEN", "EP_IMPORT",
           "EP_ENROLL", "EP_PUFRAW", "EP_TRNGRAW", "EP_ZEROIZE"]:
    m = re.search(ep + r"\s*=\s*10'd(\d+)", defs)
    if not m or int(m.group(1)) != labels[ep]:
        sys.exit("pqse_defs.vh: %s must be 10'd%d" % (ep, labels[ep]))
assert pc <= 512, "the programs no longer fit 512 words"

path = root + "/hw/se_v1_5/pqse_ucode.v"
src = open(path).read()
b = "      // ---- generated by scripts/pqse_ucode_v15_gen.py: begin ----\n"
e = "\n      // ---- generated by scripts/pqse_ucode_v15_gen.py: end ----"
i, j = src.index(b) + len(b), src.index(e)
open(path, "w").write(src[:i] + "\n".join(out) + src[j:])
print("%s: %d instructions, addresses 0 .. %d" % (path, len(prog), pc - 1))
