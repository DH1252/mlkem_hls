// -----------------------------------------------------------------------------
// pqse_defs.vh - shared constants of the PQSE secure element
// (post-quantum secure element: ML-KEM-768, fully masked, PUF key wrapping,
// secure messaging, fault detection).
//
// Included inside module bodies: `include "pqse_defs.vh"
// Everything here is a localparam, so including it in several modules is safe.
// -----------------------------------------------------------------------------

localparam [11:0] Q = 12'd3329;

// ---- I/O buffer: 512 lanes x 64 bit (4 KB), lane addresses ------------------
// Host access rules are enforced in pqse_host.v (R = host read, W = host write).
localparam [8:0] B_EKOWN  = 9'd0;     // 148 lanes  own ek = t^ (144) || rho (4)    R, W in TEST/PERSO
localparam [8:0] B_HELP   = 9'd148;   //  16 lanes  PUF helper data (960 bits) + key check value  R W
localparam [8:0] B_XIN    = 9'd164;   // 148 lanes  peer ek / ciphertext / s^ bytes  W
localparam [8:0] B_XOUT   = 9'd312;   // 136 lanes  ciphertext out, raw dumps       R
localparam [8:0] B_K      = 9'd448;   //   4 lanes  shared secret K (TEST/PERSO)   R
localparam [8:0] B_INJD   = 9'd452;   //   4 lanes  injected d (TEST only)          W
localparam [8:0] B_INJZ   = 9'd456;   //   4 lanes  injected z (TEST/PERSO)         W
localparam [8:0] B_INJM   = 9'd460;   //   4 lanes  injected m (TEST only)          W
localparam [8:0] B_INJH   = 9'd464;   //   4 lanes  injected H(ek) (TEST/PERSO)     W
localparam [8:0] B_BLOB   = 9'd468;   //  14 lanes  wrapped key: nonce 2 | ct 8 | tag 4   R W
localparam [8:0] B_SM     = 9'd484;   //  24 lanes  secure message: header 4 | msg 16 | tag 4  R W
                                      //            header = message counter (lane 0), length in
                                      //            bytes 1..128 (lane 1, set by the host), 0, 0
localparam [8:0] B_TMP    = 9'd508;   //   4 lanes  internal scratch (never host-visible)

localparam [8:0] B_HELP_CHK   = B_HELP + 9'd15;  // 64-bit PUF key check value
localparam [8:0] B_BLOB_NONCE = B_BLOB;
localparam [8:0] B_BLOB_CT    = B_BLOB + 9'd2;
localparam [8:0] B_BLOB_TAG   = B_BLOB + 9'd10;
localparam [8:0] B_SM_HDR     = B_SM;          // header: counter, length, 0, 0
localparam [8:0] B_SM_MSG     = B_SM + 9'd4;
localparam [8:0] B_SM_TAG     = B_SM + 9'd20;

// ---- polynomial slots (16 x 128 words x 24 bit) -----------------------------
// Even slots live in RAM 0 (share 0 and public data), odd slots in RAM 1
// (share 1): the two shares of a secret never share a RAM array, bit line or
// output register.
// S0..S5   long-term key: s^_j share 0 = S(2j), share 1 = S(2j+1)
// S6       T   (matrix entry / decoded public polynomial)
// S7       Z   all-zero slot (precharge reads between share 0 and share 1)
// S8, S9   ACC share 0 / share 1
// S10..S15 y_j (Encrypt) or e_i / t_i (KeyGen): share 0 = S(10+2j), share 1 = S(11+2j)
localparam [3:0] S_T = 4'd6, S_Z = 4'd7, S_ACC0 = 4'd8, S_ACC1 = 4'd9;

// ---- seed register entries (16 x 256 bit x 2 Boolean shares) -----------------
localparam [3:0] E_D    = 4'd0;   // d (KeyGen seed)
localparam [3:0] E_Z    = 4'd1;   // z (implicit-rejection key)
localparam [3:0] E_H    = 4'd2;   // H(ek) of the own key
localparam [3:0] E_M    = 4'd3;   // m (Encaps) / m' (Decaps)
localparam [3:0] E_MP   = 4'd3;
localparam [3:0] E_K1   = 4'd4;   // K' (Decaps) / K (Encaps)
localparam [3:0] E_R    = 4'd5;   // r' / r / sigma
localparam [3:0] E_KB   = 4'd6;   // K-bar = J(z || c)
localparam [3:0] E_RHO  = 4'd7;   // rho (KeyGen, before it is unmasked into the buffer)
localparam [3:0] E_SK   = 4'd8;   // session key (shared secret kept inside)
localparam [3:0] E_KEK  = 4'd9;   // key-encryption key from the PUF
localparam [3:0] E_PUF  = 4'd10;  // PUF key (180 bits in lanes 0..2)
localparam [3:0] E_TMP  = 4'd11;  // TRNG seed / nonce
localparam [3:0] E_PH   = 4'd12;  // H(ek) of a peer key (Encaps)
localparam [3:0] E_W0   = 4'd13;  // wrap scratch
localparam [3:0] E_W1   = 4'd14;  // wrap scratch
localparam [3:0] E_TAG  = 4'd15;  // tag scratch
// E_CBD: entries 12..15 (16 lanes) hold one PRF output (1024 bits, both shares)
// while the masked CBD (M_CBD) turns it into a polynomial in random word order.
// They are free while PRFs run (E_PH is consumed by G before, wrap / SEAL / OPEN
// use 13..15 only outside KeyGen / Encaps / Decaps' sampling) and wiped after.
localparam [3:0] E_CBD  = 4'd12;

// ---- instruction format (96 bit) ----------------------------------------------
localparam [3:0] C_END  = 4'd0;
localparam [3:0] C_BR   = 4'd1;
localparam [3:0] C_HASH = 4'd2;
localparam [3:0] C_POLY = 4'd3;
localparam [3:0] C_IO   = 4'd4;
localparam [3:0] C_MASK = 4'd5;
localparam [3:0] C_PUF  = 4'd6;
localparam [3:0] C_SET  = 4'd7;

// HASH sources and sinks
localparam [1:0] SRC_NONE = 2'd0, SRC_SEED = 2'd1, SRC_BUF = 2'd2, SRC_TRNG = 2'd3;
localparam [2:0] SNK_SEED = 3'd0;   // write lanes to seed entries oe0 (lanes 0-3), oe1 (4-7),
                                    // then oe0 + 2, oe0 + 3 (lanes 8-15; PRF -> E_CBD)
localparam [2:0] SNK_SXOR = 3'd1;   // XOR lanes into seed entries
localparam [2:0] SNK_SNTT = 3'd2;   // SampleNTT into slot oslot (public)
localparam [2:0] SNK_CBD  = 3'd3;   // SamplePolyCBD_2 unmasked into slot oslot (reference build)
localparam [2:0] SNK_MB2A = 3'd4;   // masked CBD: shares into oslot / oslot2 (acc: add)
localparam [2:0] SNK_MCMP = 3'd5;   // masked compare with a buffer tag (acc: 0 blob tag, 1 message tag)
localparam [2:0] SNK_BXOR = 3'd6;   // XOR (unmasked) into the message lanes B_SM_MSG (keystream)

// rates
localparam [1:0] RATE_168 = 2'd0, RATE_136 = 2'd1, RATE_72 = 2'd2;

// POLY ops
localparam [3:0] P_NTT = 4'd0, P_INTT = 4'd1, P_PWM = 4'd2, P_ADD = 4'd3,
                 P_SUB = 4'd4, P_MSPLIT = 4'd5, P_ZERO = 4'd6;

// IO ops
localparam [3:0] IO_DEC = 4'd0, IO_ENC = 4'd1, IO_S2B = 4'd2, IO_B2S = 4'd3,
                 IO_S2S = 4'd4, IO_SZERO = 4'd5, IO_SREMASK = 4'd6, IO_SCMP = 4'd7,
                 IO_T2B = 4'd8,     // raw TRNG words -> buffer (TEST only, entropy assessment)
                 IO_CTRW = 4'd9,    // message header lanes 0, 2, 3 := counter, 0, 0     (SEAL)
                 IO_CTRC = 4'd10,   // BAD := header counter replayed / too old          (OPEN)
                 IO_SEQ  = 4'd11,   // FAULT := masked seed entries e, e2 differ (share-wise)
                 IO_TRUNC = 4'd12;  // BAD := length not 1..128, else zero message bytes >= L
localparam [1:0] DM_WR = 2'd0, DM_ADD = 2'd1, DM_RSUB = 2'd2, DM_CHK = 2'd3;

// MASK ops
localparam [3:0] M_CMPR1 = 4'd0;    // masked Compress_1 -> m' Boolean shares into a seed entry
localparam [3:0] M_CMPRC = 4'd1;    // masked Compress_d, compared bit by bit with the ciphertext
localparam [3:0] M_MU    = 4'd2;    // mu = Decompress_1(m) from a masked seed entry, added to the shares
localparam [3:0] M_SEL   = 4'd3;    // K = ok ? K' : K-bar (acc = 1: kept masked in seed entry s0 field)
localparam [3:0] M_OKINI = 4'd4;    // ok := 1 (both copies)
localparam [3:0] M_OKOUT = 4'd5;    // BAD := NOT ok (unmasks ok: tag checks only)
localparam [3:0] M_STRM  = 4'd6;    // bit stream from the sponge (HASH sinks MB2A / MCMP)
localparam [3:0] M_CMPRO = 4'd7;    // masked Compress_d, ciphertext bits written to the buffer
localparam [3:0] M_OKCHK = 4'd8;    // FAULT if the two ok copies differ
localparam [3:0] M_CBD   = 4'd9;    // masked CBD from a PRF output in seed entries e..e+3, in
                                    // random word order -> slots s0 / s1 (acc: add)

// PUF ops: reconstruction with 1, 3 or 5 reads per response bit (majority);
// the microcode starts with one read and retries with more when the key check
// value does not match
localparam [3:0] PF_ENROLL = 4'd0, PF_RECON = 4'd1, PF_RAW = 4'd2,
                 PF_RECON3 = 4'd3, PF_RECON5 = 4'd4;

// SET ops
// ST_SKV: session key loaded, this side is the initiator (Encaps);
// ST_SKVR: loaded, this side is the responder (Decaps). The role picks the
// direction (the KMAC customization string) of secure messaging, so a sealed
// message cannot be reflected back to its sender. Both also reset the message
// counters.
// ST_TXINC: send counter + 1 (SEAL, before the keystream is made);
// ST_RXACC: mark the received counter as accepted in the 64-message replay
// window (OPEN, only after the tag checked out).
localparam [3:0] ST_KEYV = 4'd0, ST_KEYC = 4'd1, ST_BADC = 4'd2, ST_RESEED = 4'd3,
                 ST_SKV  = 4'd4, ST_SKC  = 4'd5, ST_SKVR = 4'd6, ST_TXINC = 4'd7,
                 ST_RXACC = 4'd8;

// branch conditions (BR: [91:88] condition, [87:78] target pc)
localparam [3:0] BC_ALWAYS = 4'd0, BC_BAD = 4'd1, BC_NBAD = 4'd2, BC_INJ = 4'd3, BC_NOKEY = 4'd4,
                 BC_NINJ = 4'd5, BC_WRAP = 4'd6, BC_KEXP = 4'd7, BC_NOSK = 4'd8, BC_ROLE = 4'd9;

// secure-messaging KMAC customization strings S (HASH J[1:0], pqse_sponge.v):
// keystream "E1" / "E2", tag "T1" / "T2"; 1 = initiator -> responder,
// 2 = responder -> initiator
localparam [1:0] KC_E1 = 2'd0, KC_E2 = 2'd1, KC_T1 = 2'd2, KC_T2 = 2'd3;

// microcode entry points (pqse_ucode.v; 10-bit program counter, 1024 x 96 ROM)
localparam [9:0] EP_KEYGEN  = 10'd16,  EP_UNWRAP  = 10'd32,  EP_ENCAPS  = 10'd192,
                 EP_DECAPS  = 10'd320, EP_SEAL    = 10'd448, EP_OPEN    = 10'd480,
                 EP_IMPORT  = 10'd512, EP_ENROLL  = 10'd528, EP_PUFRAW  = 10'd544,
                 EP_TRNGRAW = 10'd548, EP_ZEROIZE = 10'd560;

// result codes (STATUS[15:8])
localparam [7:0] R_OK = 8'd0, R_BADIN = 8'd1, R_DENIED = 8'd2, R_NOKEY = 8'd3,
                 R_BADBLOB = 8'd4, R_RNGFAIL = 8'd5, R_UNKNOWN = 8'd6, R_KILLED = 8'd7,
                 R_FAULT = 8'd8, R_BADTAG = 8'd9, R_NOSK = 8'd10, R_REPLAY = 8'd11,
                 R_PUF = 8'd12;    // the PUF key could not be reconstructed (check value)

// commands (CTRL[7:0]); CTRL[8] = use injected seeds (TEST only)
localparam [7:0] CMD_KEYGEN = 8'd1, CMD_ENCAPS = 8'd2, CMD_DECAPS = 8'd3,
                 CMD_IMPORT = 8'd4, CMD_ENROLL = 8'd5, CMD_KGWRAP = 8'd6,
                 CMD_UNWRAP = 8'd7, CMD_ZEROIZE = 8'd8, CMD_SEAL = 8'd9,
                 CMD_OPEN = 8'd10, CMD_PUFRAW = 8'd11, CMD_TRNGRAW = 8'd12;
localparam [7:0] CMD_LAST = 8'd12;

// lifecycle states (forward only)
localparam [1:0] LC_TEST = 2'd0, LC_PERSO = 2'd1, LC_USER = 2'd2, LC_KILLED = 2'd3;

// PUF fuzzy extractor: Reed-Muller RM(1,5) [32, 6, 16] code offset
localparam integer PUF_NB  = 30;            // blocks of 32 response bits
localparam integer PUF_NR  = 960;           // response bits = helper bits (15 lanes)
