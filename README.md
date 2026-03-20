# 🛡️ PhishTriage — Automated Phishing Email Analysis Platform

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=flat&logo=flask&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API-394EFF?style=flat&logo=virustotal&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-E82B2B?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Status](https://img.shields.io/badge/Status-Active-00ff88?style=flat)

**A production-grade SOC tool that automates phishing email triage — from raw `.eml` ingestion to enriched, MITRE-mapped incident reports — in under 60 seconds.**

[Features](#-features) · [Architecture](#-architecture) · [Setup](#-setup) · [Usage](#-usage) · [Reports](#-sample-reports) · [API Coverage](#-threat-intel-apis)

---

> *"In a real SOC, a Tier-1 analyst handles 50–200 alerts per shift. Manual phishing triage takes 15–30 minutes per email.*
> *This tool brings that down to under 60 seconds — with better consistency and zero analyst fatigue."*

</div>

---

## 🎯 The Problem This Solves

Phishing emails are the **#1 initial access vector** in over 90% of breaches. In a SOC environment, a Tier-1 analyst receives dozens of user-reported suspicious emails per shift. The manual process looks like this:

```
📧 Receive email → Open headers → Extract URLs manually → Check VirusTotal
→ Check AbuseIPDB → Check SPF/DKIM/DMARC → Write ticket → Escalate or close
```

This takes **15–30 minutes per email** and is error-prone under fatigue.

**PhishTriage automates the entire pipeline:**

```
📧 Upload .eml → Automatic IOC extraction → Real-time threat intel enrichment
→ MITRE ATT&CK mapping → Threat score → Downloadable incident report
```

**Time to triage: < 60 seconds.**

---

## ✨ Features

### 🔍 Email Parsing & Header Analysis
- Full RFC-compliant `.eml` parsing
- SPF / DKIM / DMARC authentication result extraction
- Received-header chain analysis for originating IP
- Reply-To vs From mismatch detection
- Display name spoofing detection

### 🎯 IOC Extraction
- URLs (including obfuscated and shortened)
- Public IP addresses (private ranges filtered automatically)
- Domains extracted from all URLs
- Email addresses from headers and body
- Attachment filenames, MD5 and SHA256 hashes

### 🌐 Threat Intelligence Enrichment (Real APIs)
| API | What It Checks | Free Tier |
|-----|---------------|-----------|
| **VirusTotal** | URL & file hash reputation — 70+ AV engine consensus | ✅ 4 req/min |
| **AbuseIPDB** | IP abuse score, total reports, country, ISP | ✅ 1000 req/day |
| **URLScan.io** | Full URL scan with screenshot and DOM analysis | ✅ 100 req/hr |

### 📊 Threat Scoring Engine
- Weighted scoring algorithm (0–100) based on:
  - Malicious/suspicious verdicts from enrichment APIs
  - Spoofing indicator count
  - Authentication failure flags (SPF fail, missing DKIM)
  - Attachment presence with malicious hash matches
- Severity classification: 🟢 LOW / 🟡 MEDIUM / 🔴 HIGH

### 🗺️ MITRE ATT&CK Mapping
Every analysis is automatically mapped to relevant adversary techniques:

| Technique ID | Name | Tactic |
|---|---|---|
| T1566 | Phishing | Initial Access |
| T1598 | Phishing for Information | Reconnaissance |
| T1204 | User Execution | Execution |

### 📋 Report Export
- **HTML** — Full dark-themed report for digital sharing
- **PDF** — Print-ready via browser print dialog
- **CSV** — Structured, section-labelled export for SIEM ingestion or ticket attachment

### 🖥️ SOC-Grade Dashboard
- Live IST clock
- Drag-and-drop `.eml` upload
- Animated terminal loading sequence
- Animated threat score meter
- Color-coded verdict pills (MALICIOUS / SUSPICIOUS / CLEAN)
- One-click IOC copy buttons
- AJAX-based — zero page redirects, results render in place

---

## 🏗️ Architecture

```
phishing-triage-tool/
│
├── analyzer/
│   ├── email_parser.py       # RFC email parsing, header extraction, spoofing detection
│   ├── ioc_extractor.py      # Regex-based IOC extraction (URLs, IPs, domains, hashes)
│   └── enrichment.py         # VirusTotal, AbuseIPDB, URLScan.io API integrations
│
├── reports/
│   ├── report_generator.py   # Jinja2 HTML report builder
│   └── samples/              # Generated reports stored here
│
├── templates/
│   └── report_template.html  # Dark SOC-themed report template
│
├── phishing_samples/         # Test .eml files
├── uploads/                  # Runtime upload directory (auto-created)
├── app.py                    # Flask app — dashboard UI + REST endpoints
├── config.py                 # Environment variable loader
├── .env                      # API keys (never committed)
├── .env.example              # Safe reference for setup
└── requirements.txt
```

### Data Flow

```
[ .eml Upload ]
      │
      ▼
[ email_parser.py ]──────────────────────────────┐
  • Parse headers (From, Reply-To, SPF, DKIM)     │
  • Extract body (plain + HTML)                   │
  • Detect spoofing flags                         │
  • Extract attachments                           │
      │                                           │
      ▼                                           │
[ ioc_extractor.py ]                              │
  • Regex: URLs, IPs, domains, emails             │
  • Hash: MD5 + SHA256 of attachments             │
      │                                           │
      ▼                                           │
[ enrichment.py ]                                 │
  • VirusTotal → URL + hash reputation            │
  • AbuseIPDB  → IP abuse confidence score        │
  • URLScan.io → Full URL behavioral scan         │
      │                                           │
      ▼                                           │
[ Threat Scoring Engine ]◄───────────────────────┘
  • Weighted score (0–100)
  • Severity: LOW / MEDIUM / HIGH
  • Analyst recommendation
      │
      ▼
[ Report Generator ]
  • HTML / PDF / CSV export
  • MITRE ATT&CK mapping
  • Dashboard render via AJAX (no redirects)
```

---

## 🚀 Setup

### Prerequisites
- Python 3.10+
- Ubuntu 20.04+ / Kali Linux / macOS
- Free API keys (links below)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/vatsalsapovadiya/phishing-triage-tool
cd phishing-triage-tool

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys
cp .env.example .env
nano .env
```

### API Keys (All Free)

| Service | Signup | What You Need |
|---------|--------|---------------|
| VirusTotal | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) | API Key |
| AbuseIPDB | [abuseipdb.com/register](https://www.abuseipdb.com/register) | API Key |
| URLScan.io | [urlscan.io/user/signup](https://urlscan.io/user/signup) | API Key |

### `.env` format
```env
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
```

### Run
```bash
python3 app.py
# Open: http://localhost:5000
```

---

## 📖 Usage

### Web Dashboard

1. Navigate to `http://localhost:5000`
2. Drag and drop a `.eml` file onto the upload zone
3. Click **▶ INITIATE ANALYSIS**
4. Watch the SOC terminal animation as the pipeline runs
5. Review threat assessment, IOCs, enrichment results, and MITRE mapping
6. Export your report as **HTML**, **PDF**, or **CSV**

### Command Line

```bash
# Analyze a single email via curl
curl -X POST http://localhost:5000/analyze \
  -F "email_file=@phishing_samples/sample.eml" | python3 -m json.tool
```

### Getting Test Samples

```bash
# Real phishing .eml samples (safe, archived)
git clone https://github.com/rf-peixoto/phishing_pot
cp phishing_pot/*.eml phishing_samples/
```

---

## 📄 Sample Reports

> Real analysis output from a test phishing email. Full reports in `/reports/samples/`.

```
┌─────────────────────────────────────────────────────┐
│  THREAT SCORE: 85/100          SEVERITY: 🔴 HIGH    │
├─────────────────────────────────────────────────────┤
│  INDICATORS DETECTED                                │
│  ⚠ Malicious URL: http://paypa1-secure-login.xyz   │
│  ⚠ Reply-To differs from From (attacker redirect)  │
│  ⚠ SPF check FAILED                                │
│  ⚠ DKIM signature missing                          │
│  ⚠ IP 185.220.101.45 — AbuseIPDB score: 97/100     │
├─────────────────────────────────────────────────────┤
│  EXTRACTED IOCs                                     │
│  URL     → http://paypa1-secure-login.xyz/verify   │
│  IP      → 185.220.101.45                          │
│  Domain  → paypa1-secure-login.xyz                 │
│  Email   → security@paypa1-alert.com               │
├─────────────────────────────────────────────────────┤
│  RECOMMENDATION                                     │
│  BLOCK & ESCALATE — Quarantine email, block sender │
│  domain, escalate to Tier-2, document all IOCs.    │
└─────────────────────────────────────────────────────┘
```

---

## 🔐 Threat Intel APIs

### VirusTotal
- Checks URLs against 70+ antivirus and URL scanner engines
- Checks file hashes against known malware signatures
- Returns: malicious count, suspicious count, harmless count, community verdict

### AbuseIPDB
- Returns abuse confidence score (0–100) for any public IP
- Total number of abuse reports in last 90 days
- Country of origin and ISP identification
- Score >50 → MALICIOUS · >10 → SUSPICIOUS · ≤10 → CLEAN

### URLScan.io
- Full behavioral URL scan with screenshot capture
- Returns DOM analysis and final redirect destination
- Useful for detecting cloaked or multi-hop phishing pages

---

## 🛡️ Spoofing Detection Logic

```python
# 1. Reply-To ≠ From  (most common phishing tactic)
if reply_addr != from_addr:
    flag("[!] Reply-To differs from From — attacker redirecting replies")

# 2. Display name contains an email address (impersonation)
if "@" in from_display_name:
    flag("[!] Display name contains email — potential impersonation")

# 3. SPF failure
if "fail" in spf_result.lower():
    flag("[!] SPF check failed — sender not authorized for this domain")

# 4. Missing DKIM
if not dkim_header:
    flag("[!] No DKIM signature — email authenticity unverifiable")
```

---

## 📦 Dependencies

```
flask>=2.3.0          # Web framework
python-dotenv>=1.0.0  # Environment variable management
requests>=2.31.0      # API calls (VirusTotal, AbuseIPDB, URLScan)
jinja2>=3.1.0         # HTML report templating
```

---

## 🗺️ Roadmap

- [ ] Batch `.eml` analysis — multiple files in one session
- [ ] STIX 2.1 export for threat intel platform sharing
- [ ] Slack / Teams webhook for HIGH severity alerts
- [ ] Historical analysis log with search and filter
- [ ] Wazuh SIEM integration — push IOCs as custom alerts
- [ ] URL detonation via Any.run / Joe Sandbox API

---

## 🔒 Security & Responsible Use

- API keys loaded from `.env` — never hardcoded or committed
- `.env` listed in `.gitignore` by default
- Uploaded files processed locally — no email content stored permanently
- Designed exclusively for **defensive security and SOC operations**
- Do not use to analyze emails you are not authorized to inspect

---

## 👤 Author

**Vatsal Sapovadiya**
Cybersecurity Student · Aspiring SOC Analyst · Defensive Security

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/vatsalsapovadiya/)
[![Portfolio](https://img.shields.io/badge/Portfolio-000000?style=flat&logo=vercel&logoColor=white)](https://vatsalsapovadiya.vercel.app)
[![Email](https://img.shields.io/badge/Email-D14836?style=flat&logo=gmail&logoColor=white)](mailto:vatsalsapovadiya22@gmail.com)
[![Medium](https://img.shields.io/badge/Medium-12100E?style=flat&logo=medium&logoColor=white)](https://medium.com/@vatsalsapovadiya22)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built to solve a real SOC problem. Not a tutorial clone. Not a CRUD app.**

*If this tool would save time in your SOC, feel free to fork, extend, and contribute.*

⭐ **Star this repo if you found it useful**

</div>
