# PROPOSAL PESERTA HACKATHON CHIP 2026

Kategori: IC Chip Design & FPGA Implementation

> Urutan bagian di bawah sama dengan template resmi, jadi tiap bagian bisa disalin langsung. Bagian bertanda **[isi]** dilengkapi tim. Semua angka hasil berasal dari simulasi dan analisis yang sudah dijalankan di repositori; angka yang masih estimasi diberi tanda dan dasar perhitungannya.

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
KTP elektronik, e-paspor, kartu pembayaran dan perangkat IoT mengamankan komunikasinya dengan RSA atau kriptografi kurva eliptik. Komputer kuantum berskala besar akan mampu memecahkan keduanya, dan data yang disadap hari ini bisa didekripsi nanti (*harvest now, decrypt later*). Tahun 2024 NIST menetapkan penggantinya, **ML-KEM (FIPS 203)**. Algoritma ini jauh lebih berat: kuncinya 1–2 KB dan perhitungannya ratusan ribu operasi aritmetika, sementara kartu nirkontak tanpa baterai hanya mendapat daya beberapa miliwatt dari medan pembaca. Perangkat seperti ini juga dipegang langsung oleh calon penyerang. Penyerang bisa mengukur konsumsi daya atau pancaran elektromagnetik chip untuk menebak kunci (**serangan side-channel**), atau mengganggu chip dengan glitch tegangan, glitch clock atau laser agar chip salah hitung dan membocorkan kunci (**serangan fault**). Implementasi perangkat lunak biasa tidak tahan terhadap kedua serangan ini.

**Solusi yang Ditawarkan:**
**PQSE** adalah *secure element* untuk ML-KEM-768, dalam bentuk IP core Verilog yang bisa dijalankan di FPGA dan difabrikasi sebagai chip. Secure element adalah chip kecil yang menyimpan kunci dan menjalankan kriptografi di dalamnya, seperti chip pada kartu bank atau SIM. Urutan prioritas desainnya:
1. **Area kecil.** Hanya satu engine aktif pada satu waktu di bawah kendali mikrokode, satu pengali modular, dan Keccak (fungsi hash di balik SHA-3) yang dihitung satu lane 64-bit per clock dengan state di RAM.
2. **Energi rendah.** Clock gating pada 97 % flip-flop dan operand isolation, sehingga blok yang menganggur tidak berpindah keadaan.
3. **Tahan serangan fisik.** *Masking* orde-1: setiap nilai rahasia dipecah menjadi dua bagian acak (share) yang diproses terpisah dan tidak pernah digabung, dan setiap rangkaian masking diperiksa dalam model *robust probing* yang memperhitungkan glitch dan transisi. *Hiding*: urutan operasi diacak dan siklus dummy acak disisipkan. Deteksi fault: komputasi ganda yang dibandingkan, register bayangan berisi nilai terbalik, paritas memori, watchdog, dan uji konsistensi pasangan kunci.

Chip ini juga menyimpan kunci tanpa memori non-volatil dengan bantuan **PUF** (*physically unclonable function*, "sidik jari" chip dari variasi proses fabrikasi), memakai kunci bersama hasil ML-KEM untuk **pesan aman** (KMAC256), dan punya *lifecycle* TEST → PERSO → USER → KILLED yang hanya bisa maju.

**Implementasi pada DE10-Nano:**
Inti PQSE dipetakan ke fabric FPGA Cyclone V (5CSEBA6U23I7) sebagai slave Avalon-MM. Semua RAM internal masuk ke blok M10K dan MLAB, pengali modular ke blok DSP, dan sel PUF ke sel logika. Desain mandiri (`quartus/jtag`, `build.tcl se`) dikendalikan dari PC lewat master JTAG-to-Avalon (System Console). KEY1 dipakai sebagai input tamper, GPIO_0[0] sebagai sinyal trigger untuk pengukuran side-channel dengan osiloskop, dan LED sebagai indikator. Komponen Platform Designer (`pqse_avalon_hw.tcl`) memungkinkan inti dihubungkan ke HPS (ARM Cortex-A9) lewat lightweight HPS-to-FPGA bridge, sehingga program Linux di ARM bisa memakai PQSE sebagai koprosesor kriptografi.

**Kebaruan & Keunggulan:**
- **Seluruh operasi terproteksi.** Akselerator ML-KEM di FPGA umumnya hanya mengejar kecepatan dan tidak terproteksi. PQSE melindungi KeyGen, Encaps dan Decaps dengan masking, hiding dan deteksi fault, dan setiap rangkaian masking diperiksa secara exhaustif terhadap semua kemungkinan probe orde-1.
- **Hasil keamanan terukur.** TVLA (uji kebocoran statistik pada jejak daya simulasi, dua run independen) tidak menemukan kebocoran orde-1 yang terkonfirmasi. Dalam 400 run injeksi fault acak, **tidak ada satu pun hasil salah yang lolos tanpa terdeteksi**, dan tidak ada yang macet.
- **Hemat energi untuk kartu nirkontak.** Sekitar **73,5 µJ per KeyGen**, rata-rata **0,45 mW** pada clock 3,39 MHz (analisis gate-level SkyWater 130 nm).
- **Kunci tidak pernah keluar dari chip.** Kunci bersama disimpan dalam bentuk termasking sebagai kunci sesi, dan kunci jangka panjang dibungkus dengan kunci turunan PUF.
- **Waktu eksekusi konstan.** Tidak ada percabangan atau alamat memori yang bergantung pada rahasia, sehingga serangan timing dan cache yang mengancam perangkat lunak di mikrokontroler tidak berlaku.

---

## 2. Latar Belakang & Rumusan Masalah (Problem Statement)

**Latar Belakang:**
Migrasi ke kriptografi pasca-kuantum sudah berjalan. FIPS 203 (ML-KEM) terbit tahun 2024, dan lembaga keamanan di banyak negara menargetkan migrasi sistem kritis dalam dekade ini. Perangkat identitas dan kepercayaan digital (KTP-el, e-paspor, kartu pembayaran, token tanda tangan digital, identitas perangkat IoT) bergantung pada secure element. Chip ini harus cukup kecil dan hemat daya untuk hidup dari medan RF pembaca yang hanya memberi beberapa miliwatt, dan harus tetap aman di tangan penyerang.

Literatur menunjukkan implementasi Kyber/ML-KEM tanpa proteksi bisa dipecahkan lewat analisis daya. Contohnya serangan single-trace pada NTT (transformasi yang dipakai ML-KEM untuk perkalian polinomial), serangan *plaintext-checking oracle* pada tahap dekripsi dan re-enkripsi, dan serangan fault yang melewati pemeriksaan re-enkripsi pada Decaps (transformasi Fujisaki–Okamoto, FO). Karena itu dibutuhkan IP core ML-KEM yang sejak awal dirancang sebagai secure element.

**Rumusan Masalah & Perancangan:**
1. **Area dan energi.** Bagaimana menjalankan ML-KEM-768 dengan area kecil dan energi per operasi rendah, dengan mengorbankan kecepatan sejauh masih bisa diterima pembaca nirkontak?
2. **Side-channel.** Bagaimana melindungi *setiap* nilai rahasia (seed, polinomial rahasia s, e, y, pesan hasil dekode m′, kunci bersama K, hasil pembandingan FO) dengan masking orde-1 yang tetap aman walaupun ada glitch dan transisi, dan bagaimana membuktikannya?
3. **Fault.** Bagaimana mendeteksi gangguan pada jalur kendali, memori, generator bilangan acak dan aritmetika, termasuk fault yang menghasilkan pasangan kunci yang tampak sah tetapi salah, lalu meresponsnya dengan aman (hapus kunci, hitung kejadian, matikan permanen setelah tiga kali)?
4. **Penyimpanan kunci tanpa NVM.** Bagaimana mengikat kunci ke satu chip tertentu (PUF dan *fuzzy extractor*, yaitu koreksi galat yang mengubah keluaran PUF yang sedikit berderau menjadi kunci yang stabil) dan menjaga status keamanan (lifecycle, penghitung fault) tetap tersimpan?
5. **Verifikasi.** Bagaimana memastikan kebenaran fungsional (vektor uji NIST), tidak adanya kebocoran (TVLA, pemeriksaan probing) dan ketahanan terhadap fault (kampanye injeksi fault) sebelum implementasi di FPGA atau silikon?

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

Sequencer menjalankan program mikrokode satu instruksi demi satu instruksi dan hanya mengaktifkan satu engine pada satu waktu. Karena itu port RAM cukup berupa multiplexer biasa, engine yang menganggur diam, dan jejak daya hanya memuat satu operasi pada satu saat. Dua share dari setiap rahasia selalu disimpan di RAM yang berbeda, sehingga tidak ada bus atau register baca yang memegang kedua share sekaligus.

**[Rincian Modul RTL]**

| Modul (hw/se) | Fungsi |
|---|---|
| `pqse_top.v` | top chip (SPI, IRQ, tamper, trigger), wrapper Avalon-MM untuk FPGA |
| `pqse_host.v` | register CSR, lifecycle TEST→PERSO→USER→KILLED dengan shadow terkomplemen, jendela akses buffer, kebijakan ekspor K, penghitung fault, watchdog perintah, penyimpanan persisten (`pqse_nvm`), penghapusan kunci saat power-on, fault dan tamper |
| `pqse_core.v` | sequencer mikrokode dengan deteksi fault (pc + shadow, paritas instruksi, cek engine berjalan), RAM berparitas per share, TRNG/PRNG, multiplexer port |
| `pqse_ucode.v` | program mikrokode: KeyGen (dengan komputasi ganda dan uji konsistensi pasangan kunci), Encaps, Decaps, Import, Enroll, Wrap/Unwrap, SEAL/OPEN, Zeroize |
| `pqse_keccak.v`, `pqse_sponge.v` | Keccak-f[1600] termasking, satu lane 64-bit per clock, state di RAM; sponge, padding, KMAC |
| `pqse_poly.v`, `pqse_arith.v` | NTT/INTT/PWM/ADD/SUB/MSPLIT/ZCHK dengan satu pengali Barrett dan satu butterfly, urutan kata acak per instruksi dan per lapis NTT |
| `pqse_perm.v` | permutasi acak Fisher–Yates (register file 128 × 7) |
| `pqse_masked.v`, `pqse_mcomp.v` | sampler CBD termasking, μ, Compress_d termasking, pembanding FO dengan dua akumulator "ok", seleksi termasking untuk implicit rejection |
| `pqse_io.v`, `pqse_sample.v` | encode/decode, operasi register seed (termasuk pembandingan SEQ), header dan jendela replay pesan; SampleNTT |
| `pqse_puf.v` | PUF 960 sel tipe SRAM, fuzzy extractor RM(1,5) dengan dekoding termasking, nilai cek dan pembacaan ulang mayoritas |
| `pqse_rng.v` | TRNG ring-oscillator dengan uji kesehatan, PRNG Trivium dengan cek kesegaran masker |
| `pqse_mem.v` | model RAM (M10K/MLAB di Cyclone V, makro SRAM di ASIC) |

Istilah pada tabel: *gadget* adalah rangkaian kecil yang menghitung langsung pada share; CBD adalah sampler distribusi binomial untuk polinomial rahasia; Compress_d membulatkan koefisien ke d bit; *implicit rejection* berarti ciphertext yang tidak sah menghasilkan kunci acak, bukan pesan galat.

Kinerja (simulasi Verilator, hiding aktif):

| Perintah | Siklus clock | @ 50 MHz (DE10-Nano) | @ 3,39 MHz (kartu nirkontak) |
|---|---|---|---|
| KeyGen (termasuk komputasi ganda dan uji konsistensi) | 545.344 | 10,9 ms | 161 ms |
| Encaps | 267.964 | 5,4 ms | 79 ms |
| Decaps | 298.465–304.526 | 6,0–6,1 ms | 88–90 ms |
| SEAL/OPEN 128 byte | 22.550 | 0,45 ms | 6,7 ms |

**[Estimasi Penggunaan Resource FPGA]**

| Komponen Resource | Estimasi Penggunaan | Kapasitas DE10-Nano |
|---|---|---|
| Logic Elements / LUT | ≈ 7.000–12.000 ALM (≈ 17–29 %)¹ | 110.000 LE / 41.910 ALM |
| Registers / Flip-Flops (FF) | ≈ 7.800² | 415.000 |
| Block RAM (M10K) | ≈ 24 blok, ≈ 186 Kbit (≈ 3,4 %)³ | 5.570 Kbit |
| DSP Blocks | ≈ 5–15⁴ | 112 DSP |
| MLAB (LUTRAM) | RAM seed 2 × 64 × 65 dan tabel permutasi 128 × 7 | - |
| Clock | target 50 MHz (clock board) | - |

Catatan estimasi:
1. **ALM.** Hasil *place & route* yang terukur ada pada FPGA lain, Gowin GW2AR-18, untuk versi v4 sebelum proteksi fault ditambahkan: 15.881 unit logika LUT4. Angka itu dikonversi ke ALM Cyclone V (1,5–2,6 LUT4 per ALM), lalu ditambah ≈ 1.900 LUT untuk sel PUF (di Cyclone V dibuat dari LUT) dan logika proteksi fault. Angka pasti diperoleh dari laporan fitter Quartus (`quartus_sh -t build.tcl se`).
2. **Flip-flop.** Terukur pada netlist sintesis versi terkini: 7.775 FF (SkyWater 130 nm, RAM sebagai makro). Jumlah di FPGA diperkirakan serupa.
3. **M10K.** Dihitung dari peta memori: RAM polinomial 2 × 1024 × 25 (6 blok), state Keccak 2 × 64 × 65 (4 blok), buffer I/O 2 × 512 × 32 (4 blok), ROM mikrokode 1024 × 96 (10 blok).
4. **DSP.** Pengali 12 × 12 dan pengali konstanta reduksi Barrett, pengali skala Compress dan pengali pada pengacak permutasi. Pada Gowin terpakai 14,75 unit DSP.

**Perangkat Lunak & Tools Perancangan:**
- Intel Quartus Prime Lite, Platform Designer (Qsys), System Console, SignalTap: implementasi dan uji di DE10-Nano.
- Verilator 5: simulasi RTL dan gate-level.
- Yosys (OSS CAD Suite): sintesis dan clock gating otomatis.
- OpenSTA dengan pustaka sel SkyWater 130 nm (sky130_fd_sc_hd): analisis timing dan daya ASIC.
- OpenRAM dan ngspice: karakterisasi energi SRAM.
- Gowin EDA: validasi silang di Tang Nano 20K.
- Python 3: model aritmetika gadget, pemeriksa robust probing, TVLA, laporan kampanye fault, verifikasi KMAC independen, statistik PUF/TRNG.

## 3.2 Rencana Pengujian

**[Simulasi RTL]** (sudah dijalankan, semua lulus):
- **Testbench otomatis (`make sim-se`).** Vektor uji resmi NIST ACVP untuk KeyGen dan Encaps, Decaps termasking (ciphertext sah dan implicit rejection), semua perintah, aturan lifecycle, persistensi status setelah power cycle, PUF (enroll, wrap/unwrap, drift 9,4 %, PUF sangat berderau), pesan aman (panjang pesan, replay, pesan dipantulkan, pesan diubah), dan SPI. Ditambah **17 uji injeksi fault dan tamper terarah** (pc, state sequencer, counter Keccak, RAM, register paritas, PRNG, watchdog, lifecycle, uji konsistensi, komputasi ganda, input tamper); setiap uji harus berakhir dengan status FAULT atau KILLED yang benar.
- **Pemeriksaan probing (`make se-probe`).** Setiap gadget disimulasikan per clock, dan untuk setiap kemungkinan probe orde-1 (termasuk glitch dan transisi) dihitung secara exhaustif apakah yang terlihat probe bergantung pada rahasia. Kontrol negatif, yaitu versi gadget yang diketahui bocor, harus terdeteksi bocor.
- **TVLA.** Uji t Welch antara jejak daya input tetap dan input acak pada Decaps termasking, dua run independen: tidak ada kebocoran terkonfirmasi. Kontrol positif dengan masking dimatikan harus bocor.
- **Kampanye fault (`make sim-se-fault`).** 200 bit-flip acak per perintah pada 38 target, setiap run dimulai dari chip yang baru dinyalakan. Decaps: 111 tidak berpengaruh, 74 terdeteksi, 15 implicit rejection, **0 lolos**, 0 macet. KeyGen: 127 tidak berpengaruh, 73 terdeteksi, **0 lolos**, 0 macet.
- **Timing, latensi dan daya (gate-level).** Jumlah siklus per perintah tercatat otomatis. Analisis SkyWater 130 nm memberi slack setup 7,2 ns pada periode 20 ns dan energi KeyGen 73,5 µJ, turun dari 92,5 µJ setelah optimasi clock gating.

**[Uji Hardware Board FPGA DE10-Nano]:**
1. **Sintesis dan bitstream.** `quartus_sh -t build.tcl se` (top `de10_nano_pqse`); periksa laporan fitter (ALM, M10K, DSP) dan TimeQuest (slack setup positif pada 50 MHz).
2. **Uji fungsional on-board** dengan System Console (`pqse_test.tcl`): vektor NIST (KeyGen, Encaps, Decaps), lifecycle, ZEROIZE, SEAL/OPEN. Penekanan KEY1 sebagai tamper harus menghapus kunci dan memindahkan chip ke KILLED.
3. **SignalTap Logic Analyzer.** Amati sinyal status dan selesai, sinyal trigger dan jumlah siklus per perintah, lalu bandingkan dengan simulasi.
4. **Karakterisasi PUF/TRNG.** Ambil dump mentah (PUFRAW, TRNGRAW) dari beberapa board dan analisis dengan `pqse_puf_stats.py` (keseragaman, bit-error rate, min-entropy).
5. **Uji side-channel nyata.** Probe EM atau resistor shunt dengan osiloskop yang dipicu dari GPIO_0[0] (`pqse_tvla_capture.tcl`), lalu `pqse_tvla.py board` untuk TVLA pada jejak nyata.
6. **(Opsional) Integrasi HPS.** Komponen Platform Designer pada lightweight bridge dan program Linux di ARM.

**[Metrik Keberhasilan Target]:**

| Metrik | Target | Status saat ini |
|---|---|---|
| Akurasi fungsional | 100 % vektor uji NIST ACVP (KeyGen, Encaps, Decaps) | tercapai di simulasi |
| Latensi @ 50 MHz | KeyGen ≤ 11 ms, Encaps ≤ 6 ms, Decaps ≤ 7 ms | 10,9 / 5,4 / 6,1 ms (simulasi) |
| Timing closure FPGA | slack setup ≥ 0 pada 50 MHz | akan diukur dengan Quartus |
| Pemakaian resource | ≤ 30 % ALM, ≤ 10 % M10K, ≤ 15 % DSP | estimasi pada tabel 3.1 |
| Kebocoran side-channel | \|t\| < 4,5 (TVLA, dua run) | tercapai di simulasi; board: rencana |
| Ketahanan fault | 0 hasil salah tak terdeteksi, 0 macet | tercapai (400 run) |
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

- **Dokumentasi desain lengkap:** `docs/PQSE_design.md` (bagian A untuk pembaca umum, bagian B untuk insinyur VLSI) dan `hw/se/README.md` (peta register, daftar perintah, peta mikrokode, catatan bring-up).
- **Grafik hasil simulasi:** plot TVLA `build/tvla_m1_s1/tvla_t.png` dan kontrol positifnya `build/tvla_m0_s1/tvla_t.png`; laporan kampanye fault `build/fault_*_s1/fault_report.txt`; laporan energi `build/sepower/gl/energy_*.txt`.
- **Cuplikan RTL penting:** gerbang AND termasking DOM (*domain-oriented masking*) pada langkah χ Keccak (`hw/se/pqse_keccak.v`). Kedua suku silang antar-share diberi bit acak baru dan diregister sebelum dipakai, dan nilainya hanya bertahan satu clock:

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

**Demo Live:** DE10-Nano menjalankan KeyGen, Encaps dan Decaps dengan vektor NIST lewat System Console (kunci bersama kedua sisi cocok), lalu SEAL/OPEN sebuah pesan. Penekanan KEY1 (tamper) menghapus kunci dan mengunci chip (KILLED), dan perintah berikutnya ditolak.

**Video Demo:** 3–5 menit berisi arsitektur, simulasi (semua uji lulus), sintesis Quartus, demo on-board, plot TVLA dan hasil kampanye fault.

**Repository Source Code:** RTL Verilog (`hw/se`), testbench (`hw/sim`), skrip verifikasi dan analisis (`scripts`), flow Quartus (`quartus/jtag`), serta bitstream `.sof` hasil build.

**Laporan Teknis Singkat:** spesifikasi arsitektur, hasil sintesis (resource dan timing), kinerja (siklus dan latensi), analisis daya dan energi, serta hasil uji keamanan (TVLA, probing, kampanye fault). Lihat `docs/PQSE_design.md`.

## Rencana Bootcamp (3 Hari) (Opsional)

| Hari | Fokus Kegiatan | Target Deliverables |
|---|---|---|
| Hari 1 | Sintesis Quartus dan timing closure 50 MHz; program board; uji fungsional dengan System Console (vektor NIST, lifecycle, tamper) | bitstream `.sof`, laporan fitter dan timing, log uji on-board lulus |
| Hari 2 | SignalTap (verifikasi sinyal dan siklus); dump PUF/TRNG dari board dan analisis statistik; pengambilan jejak daya/EM dengan trigger GPIO dan TVLA pada jejak nyata | tangkapan SignalTap, statistik PUF/TRNG, plot TVLA board |
| Hari 3 | Integrasi HPS (opsional) atau penyempurnaan demo; rekam video; susun laporan teknis dan presentasi | video demo 3–5 menit, laporan teknis, slide presentasi |
