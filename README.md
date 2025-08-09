<h1 align="center">SentrySol-Langchain</h1># SentrySol-Langchain

<!-- BADGES -->
<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white">
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi&logoColor=white">
  <img alt="LangChain" src="https://img.shields.io/badge/LangChain-Orchestration-1E88E5">
  <img alt="Mistral" src="https://img.shields.io/badge/LLM-Mistral%20Medium-FF6F00">
  <img alt="Solana" src="https://img.shields.io/badge/Solana-Supported-9945FF?logo=solana">
  <img alt="Agent Mode" src="https://img.shields.io/badge/Agent%20Mode-Direct%20/%20Reasoning-673AB7">
  <img alt="Security Scoring" src="https://img.shields.io/badge/Security%20Scoring-LLM%20Driven-4CAF50">
  <img alt="Status" src="https://img.shields.io/badge/Status-Active-success">
  <img alt="License" src="https://img.shields.io/badge/License-Private-red">
</p>

<p align="center">
  <b>Adaptive Web3 Security Intelligence Pipeline • Multi-Agent • LLM Scoring • Real-Time Wallet & Transaction Risk Profiling</b>
</p>

---

<p align="center">
  <a href="#1-ringkasan-fitur">Fitur</a> •
  <a href="#2-arsitektur-tingkat-tinggi">Arsitektur</a> •
  <a href="#8-endpoints">API</a> •
  <a href="#7-skor--risiko">Scoring</a> •
  <a href="#11-konfigurasi--variabel-lingkungan-disarankan">Konfigurasi</a> •
  <a href="#13-ekstensi--kustomisasi">Ekstensi</a> •
  <a href="#17-roadmap-saran">Roadmap</a>
</p>

---


Platform analisis keamanan Web3 (fokus Solana & multi-chain) yang memanfaatkan FastAPI + LangChain + multi-agent + LLM (Mistral) untuk:
- Screening wallet & token
- Tracing transaksi & histori
- Ekstraksi label / domain (Helius)
- Evaluasi risiko terstruktur + skor keamanan + rekomendasi eksekutif

## 1. Ringkasan Fitur
- Mode eksekusi ganda: Direct Tool Execution (deterministik) atau Agent-Based (reasoning).
- Multi-tool orchestrator (Supervisor) dengan scoring berbasis LLM.
- Dynamic "WHAT / WHO / HOW" summary.
- Security scores (overall + wallet + transaction + token + domain).
- Risk level mapping (VERY_LOW → CRITICAL).
- Pre-transaction screening & wallet-only API.
- Batch-ready (function `run_supervisor_batch`).

## 2. Arsitektur Tingkat Tinggi

```
┌──────────────────────────────────────────────────────────┐
│                        Client / UI                       │
└───────────────┬──────────────────────────────────────────┘
                │ HTTP (JSON)
        ┌───────▼────────┐
        │   FastAPI       │ main.py
        │  (Routing)      │
        └───┬─────────────┘
            │ panggil analyze()/tools
            ▼
   ┌──────────────────────────┐
   │ Supervisor Orchestrator  │ supervisor.py
   │ - Input detection         │
   │ - Mode switch             │
   │ - Tool calling / agent    │
   │ - Dynamic summary         │
   │ - LLM scoring / recs      │
   └──────────┬───────────────┘
              │
   ┌──────────▼───────────┐
   │   Agents / Tools      │ agents.py
   │  - Chainabuse (token) │
   │  - Metasleuth (wallet)│
   │  - Helius (tx, labels)│
   │  - Mistral FT (ML)    │
   └──────────┬───────────┘
              │ data mentah
              ▼
        ┌──────────────┐
        │  LLM (Mistral)│
        │  - Scoring    │
        │  - Summaries  │
        └───────────────┘
```

## 3. Komponen Utama
- main.py: Endpoint FastAPI (/analyze, /pre-transaction, /check-wallet, /transactions, /transfers, /domains, /labels).
- agents.py: Definisi tool wrapper API eksternal.
- supervisor.py: Orkestrasi pipeline end-to-end + scoring + fallback.
- README.md: Dokumentasi.
- (Log) app.log, supervisor.log, agents.log.

## 4. Mode Eksekusi
1. direct_tool_execution = true  
   - Memanggil tool secara langsung (urutan deterministik).
   - Cepat, stabil, output konsisten.

2. direct_tool_execution = false  
   - Menggunakan LangChain agent (zero-shot-react-description).
   - Reasoning fleksibel, bisa variasi output.
   - Lebih rentan error parsing → fallback disiapkan.

## 5. Alur Eksekusi (Direct)
```
Request JSON
  ↓
Validasi + detect input_type (wallet / token / tx)
  ↓
Tool Invocation (wallet → labels → tx → transfers → ML)
  ↓
LLM Summary (WHAT/WHO/HOW)
  ↓
LLM Security Scoring (JSON parsed)
  ↓
Generate Recommendations + Executive Summary
  ↓
Response final (analysis + meta)
```

## 6. Input Detection
Heuristik:
- token_address → token_analysis
- wallet_address → wallet_analysis
- transaction_hash / transaction_details → transaction_analysis
- lainnya → general_analysis

## 7. Skor & Risiko
Field:
- overall_security_score
- wallet_security_score
- transaction_security_score
- token_security_score
- domain_security_score
- confidence_level
- risk_level (VERY_LOW, LOW, MODERATE, HIGH, CRITICAL)
- positive_indicators / threat_indicators
- compliance_score / reputation_score

Interpretasi singkat:
- 90–100 = Sangat aman (VERY_LOW)
- 75–89 = Aman (LOW)
- 60–74 = Waspada (MODERATE)
- 40–59 = Risiko tinggi (HIGH)
- 0–39  = Sangat berbahaya (CRITICAL)

## 8. Endpoints

| Endpoint | Method | Deskripsi |
|----------|--------|-----------|
| /analyze | POST | Analisis umum (wallet/tx/token kombinasi) |
| /pre-transaction | POST | Screening sebelum eksekusi transaksi |
| /check-wallet | GET | Fokus analisa wallet saja |
| /transactions | GET | Raw histori transaksi (Helius) |
| /transfers | GET | Token transfers (spam / scam indicator) |
| /domains | GET | Domain / SNS |
| /labels | GET | Label reputasi (Helius) |

Query param penting:
- direct_tool_execution=true/false

## 9. Endpoint /analyze
Request:
```json
{
  "data": {
    "wallet_address": "DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas",
    "transaction_hash": "ExampleTxHashOrSignatureHere",
    "transaction_details": "From: ...\nTo: ...\nValue: 0.01 SOL",
    "chain": "solana",
    "direct_tool_execution": true
  }
}
```

Respons (dipersingkat):
```json
{
  "status": "success",
  "analysis": {
    "wallet_screening": "...",
    "transaction_details": "...",
    "labels_and_domains": "...",
    "token_transfers": "...",
    "security_scores": {
      "overall_security_score": 82,
      "risk_level": "LOW",
      "confidence_level": 78
    },
    "professional_summary": {
      "executive_summary": "...",
      "key_metrics": { "security_grade": "B+", "threat_level": "LOW" }
    },
    "what": "...",
    "who": "...",
    "how": "...",
    "recommendations": ["...", "..."]
  },
  "meta": {
    "analysis_type": "wallet_analysis",
    "direct_tool_execution": true
  }
}
```

### 9.1 Endpoint Lain

#### a. /pre-transaction (POST)
Digunakan sebelum mengeksekusi transaksi on-chain (screening preventif).
Request:
Request:
```json
{
  "data": {
    "wallet_address": "BQjmJq8EVptiTn5XbWHDA6FyeXC6qkijAjN6UojED1Mf",
    "chain": "solana",
    "analysis_type": "pre_transaction",
    "check_type": "destination_wallet"
  }
}
```
Query opsional: ?direct_tool_execution=false  

#### b. /check-wallet (GET)
Analisa fokus wallet saja.
```bash
curl "http://localhost:8000/check-wallet?wallet_address=DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas&chain=solana&direct_tool_execution=true"
```

#### c. /transactions (GET)
Histori transaksi (raw) via Helius.
```bash
curl "http://localhost:8000/transactions?wallet_address=DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas"
```

#### d. /transfers (GET)
Token transfer (indikasi spam / airdrop berisiko).
```bash
curl "http://localhost:8000/transfers?wallet_address=DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas"
```

#### e. /domains (GET)
SNS / domain mapping.
```bash
curl "http://localhost:8000/domains?wallet_address=DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas"
```

#### f. /labels (GET)
Label reputasi (scam / phishing / exchange).
```bash
curl "http://localhost:8000/labels?wallet_address=DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas"
```

#### g. Ringkasan Cepat Perbedaan
| Endpoint | Fokus | Output Inti |
|----------|-------|-------------|
| /analyze | Gabungan multi-aspek | Full security_scores + summaries |
| /pre-transaction | Gate sebelum eksekusi | Tambahan pre_transaction_recommendations |
| /check-wallet | Hanya wallet | wallet_analysis + wallet_summary |
| /transactions | Raw histori | Array transaksi mentah |
| /transfers | Token movement | Deteksi spam / pattern token |
| /domains | Domain wallet | daftar domain SNS |
| /labels | Label reputasi | Kategori / tag wallet |

> Catatan: Endpoint raw (transactions/transfers/domains/labels) tidak selalu memiliki field scoring; scoring penuh hanya pada /analyze & /pre-transaction (serta derivasi /check-wallet).

## 10. Pre-Transaction Flow
- Tambahan field pre_transaction_recommendations
- Jika risk HIGH/CRITICAL → blokir / manual review
- Jika LOW/VERY_LOW → APPROVED

## 11. Konfigurasi & Variabel Lingkungan (Disarankan)
Ganti hard-coded API key di kode agar aman:
```
export CHAINABUSE_API_KEY=...
export BLOCKSEC_API_KEY=...
export HELIUS_API_KEY=...
export MISTRAL_API_KEY=...
```
Lalu modifikasi agents.py & supervisor.py untuk membaca via os.getenv.

## 12. Instalasi
```
python -m venv .venv
source .venv/Scripts/activate (Windows: .venv\Scripts\activate)
pip install -r requirements.txt   # (buat file kalau belum)
uvicorn main:app --reload
```

## 13. Ekstensi / Kustomisasi
Tambahkan tool baru:
1. Definisikan fungsi di agents.py
2. Bungkus dengan Tool(name=..., func=..., description=...)
3. Tambahkan ke list tools di supervisor.py
4. Perbarui prompt template bila perlu

## 14. Error Handling & Fallback
- Agent-based gagal → create_fallback_analysis
- LLM scoring gagal → fallback skor default (moderate risk neutral)
- Dynamic summary gagal → fallback statis

## 15. Logging
- app.log (API level)
- supervisor.log (pipeline & scoring)
- agents.log (pemanggilan tool)

## 16. Keamanan & Pertimbangan
- Jangan commit API key.
- Rate limit eksternal (Helius, Metasleuth, Chainabuse).
- Sanitasi input (panjang address, format).
- Tambah auth (API key header) sebelum produksi.
- Tambahkan cache (misal Redis) untuk mengurangi panggilan identik.

## 17. Roadmap (Saran)
- Integrasi on-chain anomaly model khusus.
- Penambahan reputasi kontrak & dex interaction heuristics.
- Integrasi SIEM / webhook alert.
- Batch large-scale risk scoring + streaming.
- OpenMetrics exporter (Prometheus).

## 18. FAQ Singkat
Q: Kenapa skor bisa berbeda antara mode agent & direct?  
A: Agent mode menambah reasoning chain, bisa memicu variasi ringkasan sehingga mempengaruhi interpretasi LLM scoring.

Q: Bisa multi-chain?  
A: Saat ini deteksi Ethereum (0x...) & Solana (Base58). Dapat diperluas.

Q: Apakah hasil selalu deterministik?  
A: Tidak, bagian summary & scoring berbasis LLM (stochastic).

## 19. Struktur Folder (Ringkas)
```
SentrySol-Langchain/
 ├─ main.py               (FastAPI endpoints)
 ├─ agents.py             (Tool definitions)
 ├─ supervisor.py         (Pipeline & orchestration)
 ├─ README.md             (Dokumentasi)
 ├─ *.log                 (Log runtime)
```

## 20. Interpretasi Cepat Hasil
- overall_security_score < 60 → Perlu investigasi lanjut.
- risk_level HIGH/CRITICAL → Stop otomatis (policy saran).
- confidence_level < 50 → Minta re-run / manual review.
- Banyak threat_indicators → Flag incident.

--- 
Jika memerlukan versi English atau penambahan diagram sequence detail, dapat ditambahkan kemudian.
