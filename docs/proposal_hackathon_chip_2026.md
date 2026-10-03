# PROPOSAL PESERTA HACKATHON CHIP 2026

Kategori: IC Chip Design & FPGA Implementation

> Isi dokumen ini mengikuti urutan bagian pada template resmi. Salin tiap bagian ke template; bagian bertanda **[isi]** perlu dilengkapi oleh tim. Angka hasil berasal dari simulasi dan analisis yang sudah dijalankan pada repositori; angka yang masih berupa estimasi ditandai jelas beserta dasarnya.

## Identitas Tim

**Judul Ide Desain Chip:** PQSE: Secure Element Pasca-Kuantum ML-KEM-768 Berdaya Rendah dengan Proteksi Side-Channel dan Fault

**Nama Tim:** [isi]

**Anggota Tim (2–4 orang):**
- **Ketua:** [Nama] – [Institusi] – [Email/HP]
- **Anggota 1:** [Nama] – [Institusi] – [Email/HP]
- **Anggota 2:** [Nama] – [Institusi] – [Email/HP]

**Dosen Pembimbing:** [Nama & Gelar] – [Institusi]

---

## 1. Ringkasan Ide (Executive Summary)

**Masalah yang Diangkat:**
Kartu identitas elektronik, e-paspor, kartu pembayaran dan perangkat IoT mengamankan komunikasinya dengan RSA atau kurva eliptik. Komputer kuantum skala besar akan mampu memecahkan keduanya, dan data yang disadap hari ini dapat didekripsi di kemudian hari (*harvest now, decrypt later*). NIST menetapkan pengganti tahan-kuantum, **ML-KEM (FIPS 203, 2024)**, tetapi algoritma ini jauh lebih berat: kunci 1–2 KB dan ratusan ribu operasi aritmetika. Perangkat tanpa baterai seperti kartu nirkontak hanya menerima daya beberapa miliwatt dari medan pembaca. Selain itu, perangkat yang berada di tangan penyerang rentan terhadap **serangan side-channel** (pengukuran daya/EM) dan **serangan fault** (glitch tegangan/clock, laser). Implementasi perangkat lunak biasa tidak tahan terhadap keduanya.

**Solusi yang Ditawarkan:**
**PQSE**, sebuah *secure element* (IP core / chip) untuk ML-KEM-768 yang dirancang dari awal untuk tiga prioritas:
1. **Area kecil**: satu engine aktif pada satu waktu di bawah kendali mikrokode, satu pengali modular, Keccak lane-serial dengan state di RAM.
2. **Energi sangat rendah**: clock enable/gating di semua register, operand isolation.
3. **Ketahanan serangan fisik**:
   - *masking* orde-1 untuk setiap rahasia, terverifikasi dalam model *robust probing* (glitch dan transisi);
   - *hiding* (urutan acak + siklus dummy);
   - deteksi fault (komputasi ganda + pembandingan, shadow register, paritas, watchdog, uji konsistensi pasangan kunci).

Chip juga menyimpan kunci tanpa memori non-volatil melalui **PUF**, memakai kunci bersama untuk **pesan aman** (KMAC256), dan memiliki *lifecycle* TEST → PERSO → USER → KILLED.

**Implementasi pada DE10-Nano:**
Inti PQSE (Verilog) dipetakan ke fabric FPGA Cyclone V (5CSEBA6U23I7) sebagai slave Avalon-MM:
- seluruh RAM internal dipetakan ke blok M10K/MLAB;
- pengali modular ke blok DSP;
- sel PUF ke sel logika.

Desain mandiri (`quartus/jtag`, `build.tcl se`) dikendalikan dari PC melalui JTAG-to-Avalon master (System Console). Pin yang dipakai: KEY1 sebagai input tamper, GPIO_0[0] sebagai trigger pengukuran untuk uji side-channel dengan osiloskop, LED sebagai indikator. Komponen Platform Designer (`pqse_avalon_hw.tcl`) memungkinkan inti dihubungkan ke HPS (ARM Cortex-A9) melalui lightweight HPS-to-FPGA bridge, sehingga program Linux di ARM memakai PQSE sebagai koprosesor kriptografi aman.

**Kebaruan & Keunggulan:**
- **Proteksi di level hardware, bukan hanya akselerasi.** Akselerator ML-KEM pada FPGA umumnya tidak terproteksi. PQSE melindungi *KeyGen, Encaps dan Decaps* sekaligus dengan masking, hiding dan deteksi fault, dan setiap gadget masking diverifikasi secara formal-exhaustif.
- **Hasil keamanan terukur:**
  - TVLA (dua run independen): tidak ada kebocoran orde-1 yang terkonfirmasi;
  - kampanye injeksi fault acak 400 run: **0 hasil salah yang lolos tanpa terdeteksi** dan 0 hang.
- **Hemat energi untuk kartu nirkontak:** sekitar **73,5 µJ per KeyGen**, rata-rata **0,45 mW** pada clock 3,39 MHz (analisis gate-level SkyWater 130 nm).
- **Kunci tidak pernah keluar chip:** kunci bersama disimpan termasking sebagai kunci sesi; kunci jangka panjang dibungkus dengan kunci dari PUF.
- **Waktu konstan:** tidak ada percabangan atau alamat yang bergantung pada rahasia, berbeda dengan perangkat lunak pada mikrokontroler yang rentan terhadap serangan timing dan cache.

---

## 2. Latar Belakang & Rumusan Masalah (Problem Statement)

**Latar Belakang:**
Migrasi ke kriptografi pasca-kuantum sudah dimulai. Standar NIST FIPS 203 (ML-KEM) terbit tahun 2024, dan lembaga keamanan di berbagai negara menargetkan migrasi sistem kritis dalam dekade ini. Perangkat identitas dan kepercayaan digital (KTP-el, e-paspor, kartu pembayaran, token tanda tangan, identitas IoT) bergantung pada *secure element*, yaitu chip kecil yang menyimpan kunci dan menjalankan kriptografi di dalamnya. Chip semacam ini harus:
- cukup kecil dan hemat daya untuk catu dari medan RF pembaca (beberapa mW);
- tahan terhadap penyerang yang memegang perangkatnya.

Literatur menunjukkan bahwa implementasi Kyber/ML-KEM tanpa proteksi dapat dipecahkan dengan analisis daya. Contohnya serangan single-trace pada NTT, serangan *plaintext-checking oracle* pada dekripsi/re-enkripsi, dan serangan fault yang melompati pembandingan FO. Oleh karena itu dibutuhkan IP core ML-KEM yang dirancang khusus sebagai secure element.

**Rumusan Masalah & Perancangan:**
1. **Batasan area dan energi:** bagaimana menjalankan ML-KEM-768 dengan area kecil dan energi per operasi rendah, dengan menukar kecepatan (yang masih dapat diterima oleh pembaca nirkontak) demi area dan daya?
2. **Side-channel:** bagaimana melindungi *setiap* nilai rahasia (seed, s, e, y, m′, K, perbandingan FO) dengan masking orde-1 yang tetap aman meskipun ada glitch dan transisi, serta membuktikannya?
3. **Fault:** bagaimana mendeteksi gangguan pada jalur kendali, memori, generator acak dan aritmetika, termasuk fault yang menghasilkan pasangan kunci "valid tetapi salah", lalu merespons dengan aman (hapus kunci, hitung, matikan permanen setelah tiga kali)?
4. **Penyimpanan kunci tanpa NVM:** bagaimana mengikat kunci ke chip tertentu (PUF + fuzzy extractor) dan menjaga status keamanan (lifecycle, penghitung fault) tetap persisten?
5. **Verifikasi:** bagaimana memastikan kebenaran fungsional (vektor uji NIST), ketiadaan kebocoran (TVLA, pemeriksaan probing) dan ketahanan fault (kampanye injeksi fault) sebelum implementasi di FPGA/silikon?

---

## 3. Proposed Chip Design

## 3.1 Solusi & Arsitektur Sistem

**[Diagram Blok Sistem]**

```
        SPI / Avalon-MM (DE10-Nano: JTAG master / HPS bridge)   tamper (KEY1)   trigger (GPIO_0[0])
                              |                                     |               ^
   +--------------------------v-------------------------------------v---------------+---+
   | pqse_host: register CSR, lifecycle (+ shadow), jendela buffer, kebijakan perintah, |
   |            penghitung fault, watchdog, penyimpanan persisten, penghapusan kunci    |
   +---------------+-------------------------------------------+-----------------------+
                   | perintah / selesai / hasil                 | akses buffer (saat idle)
   +---------------v-------------------------------------------v-----------------------+
   | pqse_core: sequencer mikrokode (ROM 1024 x 96, pc + ~pc, paritas instruksi)       |
   |                                                                                    |
   |  [Keccak termasking]  [unit polinomial]  [gadget termasking]  [unit I/O]  [PUF]   |
   |   SHA-3/SHAKE/KMAC     NTT/INTT/PWM       CBD, Compress,       encode/     RM(1,5) |
   |   state di 2 RAM       1 pengali, 1 BFU   pembanding FO        decode      fuzzy   |
   |   (1 RAM per share)    urutan acak        2 salinan "ok"       SEQ         extract.|
   |                                                                                    |
   |  TRNG (ring osc. + uji kesehatan SP 800-90B) -> PRNG Trivium (masker)              |
   |  Fisher-Yates (urutan acak)                                                        |
   |  RAM polinomial 2 x 1024 x 25 | RAM seed 2 x 64 x 65 | buffer I/O 4 KB             |
   |  (share 0 dan share 1 selalu di RAM yang berbeda)                                  |
   +------------------------------------------------------------------------------------+
```

**[Rincian Modul RTL]**

| Modul (hw/se) | Fungsi |
|---|---|
| `pqse_top.v` | top chip (SPI, IRQ, tamper, trigger), wrapper Avalon-MM untuk FPGA, sistem |
| `pqse_host.v` | register CSR, lifecycle TEST→PERSO→USER→KILLED dengan shadow terkomplemen, jendela akses buffer, kebijakan ekspor K, penghitung fault, watchdog perintah, penyimpanan persisten (`pqse_nvm`), penghapusan saat power-on/fault/tamper |
| `pqse_core.v` | sequencer mikrokode dengan deteksi fault (pc + shadow, paritas instruksi, cek engine), RAM ber-paritas per share, TRNG/PRNG, multiplexer port |
| `pqse_ucode.v` | program mikrokode: KeyGen (+ komputasi ganda dan uji konsistensi pasangan kunci), Encaps, Decaps, Import, Enroll, Wrap/Unwrap, SEAL/OPEN, Zeroize |
| `pqse_keccak.v`, `pqse_sponge.v` | Keccak-f[1600] termasking (DOM), lane-serial 64-bit, state di RAM; sponge, padding, KMAC, sink |
| `pqse_poly.v`, `pqse_arith.v` | NTT/INTT/PWM/ADD/SUB/MSPLIT/ZCHK dengan satu pengali Barrett dan satu butterfly, urutan kata acak per instruksi dan per lapis NTT |
| `pqse_perm.v` | permutasi acak Fisher–Yates (register file 128 × 7) |
| `pqse_masked.v`, `pqse_mcomp.v` | CBD termasking (B2A), μ, Compress_d termasking, pembanding FO dengan dua akumulator "ok", seleksi termasking (implicit rejection) |
| `pqse_io.v`, `pqse_sample.v` | encode/decode, operasi register seed (termasuk SEQ), header dan jendela replay pesan; SampleNTT |
| `pqse_puf.v` | PUF sel-SRAM (960 sel), fuzzy extractor RM(1,5) dengan dekoding termasking, nilai cek + pembacaan ulang mayoritas |
| `pqse_rng.v` | TRNG ring-oscillator dengan uji kesehatan, PRNG Trivium dengan cek kesegaran masker |
| `pqse_mem.v` | model RAM (M10K/MLAB di Cyclone V, makro SRAM di ASIC) |

Kinerja (simulasi Verilator, hiding aktif):

| Perintah | Siklus clock | @ 50 MHz (DE10-Nano) | @ 3,39 MHz (kartu nirkontak) |
|---|---|---|---|
| KeyGen (termasuk cek ganda + uji konsistensi) | 545.344 | 10,9 ms | 161 ms |
| Encaps | 267.964 | 5,4 ms | 79 ms |
| Decaps | 298.465–304.526 | 6,0–6,1 ms | 88–90 ms |
| SEAL/OPEN 128 byte | 22.550 | 0,45 ms | 6,7 ms |

**[Estimasi Penggunaan Resource FPGA]**

| Komponen Resource | Estimasi Penggunaan | Kapasitas DE10-Nano |
|---|---|---|
| Logic Elements / LUT | ≈ 7.000–12.000 ALM (≈ 17–29 %)¹ | 110.000 LEs / 41.910 ALMs |
| Registers / Flip-Flops (FF) | ≈ 7.800² | 415.000 |
| Block RAM (M10K) | ≈ 24 blok, ≈ 186 Kbit (≈ 3,4 %)³ | 5.570 Kbits |
| DSP Blocks | ≈ 5–15⁴ | 112 DSP |
| MLAB (LUTRAM) | RAM seed 2 × 64 × 65 + tabel permutasi 128 × 7 | — |
| Clock | target 50 MHz (clock board) | — |

Catatan estimasi:
1. **ALM.** Hasil *place & route* terukur pada FPGA lain (Gowin GW2AR-18, versi v4 sebelum penambahan proteksi fault): 15.881 unit logika LUT4. Konversi ke ALM Cyclone V (1,5–2,6 LUT4 per ALM) ditambah ≈ 1.900 LUT untuk sel PUF (di Cyclone V dibuat dari LUT) dan logika proteksi fault yang ditambahkan kemudian. Angka pasti diperoleh dari laporan fitter Quartus (`quartus_sh -t build.tcl se`).
2. **Flip-flop.** Jumlah terukur pada netlist sintesis RTL versi terkini (7.775 FF, 97 % di belakang clock gate; SkyWater 130 nm dengan RAM sebagai makro); jumlah di FPGA serupa.
3. **M10K.** Dihitung dari peta memori: RAM polinomial 2 × 1024 × 25 (6 blok), state Keccak 2 × 64 × 65 (4 blok), buffer I/O 2 × 512 × 32 (4 blok), ROM mikrokode 1024 × 96 (10 blok).
4. **DSP.** Pengali 12 × 12 dan pengali konstanta reduksi Barrett, pengali skala Compress dan pengali permutasi; pada Gowin terpakai 14,75 unit DSP.

**Perangkat Lunak & Tools Perancangan:**
- Intel Quartus Prime Lite, Platform Designer (Qsys), System Console, SignalTap: implementasi dan uji DE10-Nano.
- Verilator 5: simulasi RTL dan gate-level.
- Yosys (OSS CAD Suite): sintesis, clock gating otomatis.
- OpenSTA dengan pustaka sel SkyWater 130 nm (sky130_fd_sc_hd): analisis timing dan daya ASIC.
- Gowin EDA: validasi silang di Tang Nano 20K.
- Python 3: model aritmetika gadget, pemeriksa *robust probing*, TVLA, laporan kampanye fault, verifikasi KMAC independen, statistik PUF/TRNG.

## 3.2 Rencana Pengujian

**[Simulasi RTL]** (sudah dijalankan, semua lulus):
- **Testbench otomatis (`make sim-se`):**
  - vektor uji resmi NIST ACVP untuk KeyGen dan Encaps, serta Decaps termasking (ciphertext valid dan implicit rejection);
  - semua perintah, aturan lifecycle, persistensi status setelah power cycle, PUF (enroll, wrap/unwrap, drift 9,4 %, PUF sangat bising), pesan aman (panjang, replay, pesan dipantulkan, pesan dimodifikasi), SPI;
  - **17 uji injeksi fault dan tamper terarah** (pc, state sequencer, counter Keccak, RAM, register paritas, PRNG, watchdog, lifecycle, uji konsistensi, komputasi ganda, input tamper), masing-masing harus berakhir dengan status FAULT/KILLED yang benar.
- **Pemeriksaan probing (`make se-probe`):** pemeriksaan exhaustif keamanan orde-1 tiap gadget termasking dalam model *robust probing* (glitch + transisi), dengan kontrol negatif yang harus bocor.
- **TVLA:** uji t Welch *fixed-vs-random* pada Decaps termasking, dua run independen: tidak ada kebocoran terkonfirmasi. Kontrol positif dengan masking dimatikan harus bocor.
- **Kampanye fault (`make sim-se-fault`):** 200 bit-flip acak per perintah pada 38 target, setiap run dari chip "dingin":
  - Decaps: 111 tidak berpengaruh, 74 terdeteksi, 15 implicit rejection, **0 lolos**, 0 hang;
  - KeyGen: 127 tidak berpengaruh, 73 terdeteksi, **0 lolos**, 0 hang.
- **Timing/latensi dan daya (gate-level):** jumlah siklus per perintah dicatat otomatis. Analisis SkyWater 130 nm memberi slack setup 7,2 ns pada 20 ns dan energi KeyGen 73,5 µJ (turun dari 92,5 µJ setelah optimasi clock gating).

**[Uji Hardware Board FPGA DE10-Nano]:**
1. **Sintesis dan bitstream:** `quartus_sh -t build.tcl se` (top `de10_nano_pqse`); periksa laporan fitter (ALM, M10K, DSP) dan TimeQuest (slack setup positif pada 50 MHz).
2. **Uji fungsional on-board** dengan System Console (`pqse_test.tcl`): vektor NIST (KeyGen, Encaps, Decaps), lifecycle, ZEROIZE, SEAL/OPEN; tombol KEY1 sebagai tamper harus menghapus kunci dan memindah ke KILLED.
3. **SignalTap Logic Analyzer:** amati sinyal status/selesai, sinyal trigger dan siklus per perintah; bandingkan dengan simulasi.
4. **Karakterisasi PUF/TRNG:** dump mentah (PUFRAW, TRNGRAW) dari beberapa board, dianalisis dengan `pqse_puf_stats.py` (uniformity, bit-error rate, min-entropy).
5. **Uji side-channel nyata:** probe EM atau resistor shunt dan osiloskop dengan trigger di GPIO_0[0] (`pqse_tvla_capture.tcl`), lalu `pqse_tvla.py board` untuk TVLA pada trace nyata.
6. **(Opsional)** Integrasi HPS: komponen Platform Designer pada lightweight bridge dan program Linux di ARM.

**[Metrik Keberhasilan Target]:**

| Metrik | Target | Status saat ini |
|---|---|---|
| Akurasi fungsional | 100 % vektor uji NIST ACVP (KeyGen, Encaps, Decaps) | tercapai di simulasi |
| Latensi @ 50 MHz | KeyGen ≤ 11 ms, Encaps ≤ 6 ms, Decaps ≤ 7 ms | 10,9 / 5,4 / 6,1 ms (simulasi) |
| Timing closure FPGA | slack setup ≥ 0 pada 50 MHz | akan diukur dengan Quartus |
| Pemakaian resource | ≤ 30 % ALM, ≤ 10 % M10K, ≤ 15 % DSP | estimasi tabel 3.1 |
| Kebocoran side-channel | \|t\| < 4,5 (TVLA, dua run) | tercapai di simulasi; board: rencana |
| Ketahanan fault | 0 hasil salah tak terdeteksi, 0 hang | tercapai (400 run) |
| Energi (ASIC, SkyWater 130 nm) | ≤ 100 µJ per KeyGen, ≤ 1 mW @ 3,39 MHz | 73,5 µJ, 0,45 mW |

---

## 4. Referensi

1. NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, 2024.
2. NIST FIPS 202, *SHA-3 Standard*; NIST SP 800-185, *SHA-3 Derived Functions (cSHAKE, KMAC)*.
3. NIST SP 800-90B, *Recommendation for the Entropy Sources Used for Random Bit Generation*.
4. NIST FIPS 140-3 (ISO/IEC 19790): uji konsistensi pasangan kunci.
5. H. Groß, S. Mangard, T. Korak, *Domain-Oriented Masking: Compact Masked Hardware Implementations with Arbitrary Protection Order*, TIS 2016.
6. S. Faust, V. Grosso, S. Merino Del Pozo, C. Paglialonga, F.-X. Standaert, *Composable Masking Schemes in the Presence of Physical Defaults & the Robust Probing Model*, TCHES 2018.
7. G. Goodwill et al., *A Testing Methodology for Side-Channel Resistance Validation* (TVLA), NIST NIAT 2011.
8. R. Primas, P. Pessl, S. Mangard, *Single-Trace Side-Channel Attacks on Masked Lattice-Based Encryption*, CHES 2017.
9. P. Ravi et al., *Generic Side-channel Attacks on CCA-secure Lattice-based PKE and KEMs*, TCHES 2020.
10. R. Ueno et al., *Curse of Re-encryption: A Generic Power/EM Analysis on Post-Quantum KEMs*, TCHES 2022.
11. S. Mandal, D. Basu Roy, *A Lightweight Unified Keccak Module for Efficient Hashing in ML-KEM and ML-DSA*, QSec 2025 (pembanding modul Keccak tanpa proteksi).
12. S. S. Kumar et al., *The Butterfly PUF: Protecting IP on every FPGA*, HOST 2008.
13. C. De Cannière, B. Preneel, *Trivium*, eSTREAM, 2008.

---

## 5. Lampiran

- **Dokumentasi desain lengkap:**
  - `docs/PQSE_design.md`: bagian A untuk pembaca umum, bagian B untuk insinyur VLSI;
  - `hw/se/README.md`: peta register, daftar perintah, mikrokode, catatan bring-up.
- **Grafik hasil simulasi:** plot TVLA `build/tvla_m1_s1/tvla_t.png` (dan kontrol positif `build/tvla_m0_s1/tvla_t.png`); laporan kampanye fault `build/fault_*_s1/fault_report.txt`; laporan energi `build/sepower/gl/energy_*.txt`.
- **Cuplikan RTL penting:** gerbang AND termasking DOM pada χ Keccak (`hw/se/pqse_keccak.v`). Setiap produk silang antar-share diberi bit acak baru dan diregister sebelum dipakai, dan nilainya hanya hidup selama satu clock:

```verilog
// chi: Y operands and DOM products (two shares, fresh random rr per lane)
if (rst || dom_now || dom_q) begin
  d00 <= (!rst && dom_now) ? (X0r & Y0r)        : 64'd0;   // domain 0
  d01 <= (!rst && dom_now) ? ((X0r & Y1r) ^ rr) : 64'd0;   // cross term, refreshed
  d10 <= (!rst && dom_now) ? ((X1r & Y0r) ^ rr) : 64'd0;   // cross term, refreshed
  d11 <= (!rst && dom_now) ? (X1r & Y1r)        : 64'd0;   // domain 1
end
```

## Tim & Pembagian Peran

| Nama Anggota | Keahlian Utama | Tanggung Jawab & Peran |
|---|---|---|
| [Nama Ketua] | [isi] | arsitektur, RTL inti dan mikrokode, integrasi |
| [Nama Anggota 1] | [isi] | verifikasi: testbench, TVLA, kampanye fault, pemeriksaan probing |
| [Nama Anggota 2] | [isi] | implementasi FPGA DE10-Nano (Quartus, Platform Designer, SignalTap), pengukuran side-channel, analisis daya |

## Luaran & Demo (Opsional)

**Demo Live:** DE10-Nano menjalankan KeyGen → Encaps → Decaps dengan vektor NIST melalui System Console (kunci bersama cocok), lalu SEAL/OPEN pesan aman. Penekanan KEY1 (tamper) menghapus kunci dan mengunci chip (KILLED); perintah berikutnya ditolak.

**Video Demo:** 3–5 menit: arsitektur, simulasi (lulus semua uji), sintesis Quartus, demo on-board, plot TVLA dan hasil kampanye fault.

**Repository Source Code:** RTL Verilog (`hw/se`), testbench (`hw/sim`), skrip verifikasi dan analisis (`scripts`), flow Quartus (`quartus/jtag`), serta bitstream `.sof` hasil build.

**Laporan Teknis Singkat:** spesifikasi arsitektur, hasil sintesis (resource dan timing), kinerja (siklus dan latensi), analisis daya/energi, serta hasil uji keamanan (TVLA, probing, kampanye fault). Lihat `docs/PQSE_design.md`.

## Rencana Bootcamp (3 Hari) (Opsional)

| Hari | Fokus Kegiatan | Target Deliverables |
|---|---|---|
| Hari 1 | Sintesis Quartus dan timing closure 50 MHz; program board; uji fungsional dengan System Console (vektor NIST, lifecycle, tamper) | bitstream `.sof`, laporan fitter dan timing, log uji on-board lulus |
| Hari 2 | SignalTap (verifikasi sinyal dan siklus); dump PUF/TRNG dari board dan analisis statistik; pengambilan trace daya/EM dengan trigger GPIO dan TVLA pada trace nyata | tangkapan SignalTap, statistik PUF/TRNG, plot TVLA board |
| Hari 3 | Integrasi HPS (opsional) atau penyempurnaan demo; rekam video; susun laporan teknis dan presentasi | video demo 3–5 menit, laporan teknis, slide presentasi |
