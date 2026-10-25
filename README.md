<div align="center">

# 🛡️ AI-Assisted Cybersecurity Threat Modeling Tool

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=22&pause=1000&color=00FF41&center=true&vCenter=true&width=700&lines=AI-Powered+Threat+Modeling+Dashboard;STRIDE+%7C+MITRE+ATT%26CK+%7C+NIST+%7C+CVE+%7C+CERT-In;Built+with+Python+%26+Streamlit;100%25+Local+%7C+Zero+Telemetry+%7C+Privacy+First" alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30%2B-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io/)
[![STRIDE](https://img.shields.io/badge/Framework-STRIDE-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
[![MITRE](https://img.shields.io/badge/Intel-MITRE%20ATT%26CK%C2%AE-CC0000?style=for-the-badge)](https://attack.mitre.org/)
[![NIST](https://img.shields.io/badge/Controls-NIST%20CSF-003087?style=for-the-badge)](https://www.nist.gov/cyberframework)
[![Tests](https://img.shields.io/badge/Tests-28%20Passing-00C851?style=for-the-badge&logo=pytest&logoColor=white)](tests/)
[![License](https://img.shields.io/badge/License-MIT-F4D03F?style=for-the-badge)](LICENSE)
[![Made with Love](https://img.shields.io/badge/Made%20with-%E2%9D%A4%EF%B8%8F-red?style=for-the-badge)](https://github.com/Sukhmnpreetkaur)

<br/>

> **An AI-powered, interactive cybersecurity threat modeling dashboard** that analyzes your system architecture and identifies real-world security threats using Microsoft's STRIDE framework, cross-referenced with live intelligence from MITRE ATT&CK®, CVE, CVSS, NIST CSF, and CERT-In — all running **100% locally** on your machine.

<br/>

[🚀 Quick Start](#-quick-start) &nbsp;•&nbsp;
[✨ Features](#-features) &nbsp;•&nbsp;
[🧠 How It Works](#-how-it-works) &nbsp;•&nbsp;
[📸 Screenshots](#-screenshots) &nbsp;•&nbsp;
[🌐 Threat Intel](#-threat-intelligence-coverage) &nbsp;•&nbsp;
[🧪 Tests](#-automated-tests) &nbsp;•&nbsp;
[👩‍💻 Author](#-author)

</div>

---

## 💡 What Is This?

Traditional threat modeling is manual, time-consuming, and requires deep security expertise. This tool **automates** the process.

You describe your system — what services you use, what components you have, what your architecture looks like — and the AI engine:

1. 🔍 **Identifies threats** across all 6 STRIDE categories
2. 📊 **Scores each threat** using a 5×5 Risk Matrix (Likelihood × Impact)
3. 🌐 **Maps threats to real CVEs**, MITRE ATT&CK tactics, NIST controls, and CERT-In advisories
4. 🛠️ **Recommends mitigations** with specific, actionable steps
5. 📥 **Exports reports** as CSV datasets or Markdown assessment documents

> 🔒 **Privacy First:** Runs 100% locally. No internet connection needed. No data leaves your machine. No paid APIs required.

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🧠 Intelligence Engine
- **STRIDE Heuristic Engine** — Detects all 6 threat categories automatically
- **Keyword Context Scan** — Identifies risk amplifiers like `ssn`, `payment`, `upload`, `admin`, `unencrypted`
- **5×5 Risk Matrix** — Scores threats from 1–25 with qualitative tiers
- **Real-World CVE Mapping** — Links threats to actual vulnerability records

</td>
<td width="50%">

### 🖥️ Dashboard & UX
- **Dark Cybersecurity Theme** — Console-inspired UI with neon severity accents
- **Live Metric Counters** — Real-time Critical / High / Medium / Low counts
- **Interactive Filters** — Filter by STRIDE category, risk level, or keyword
- **Expandable Mitigation Cards** — Detailed fix recommendations per threat
- **STRIDE Analytics Charts** — Visual distribution of threat categories

</td>
</tr>
<tr>
<td width="50%">

### 🌐 Threat Intelligence
- **MITRE ATT&CK®** — Tactic IDs (T1190, T1611, T1059…)
- **CWE** — Weakness IDs (CWE-89, CWE-22, CWE-287…)
- **CVSS Scores** — Maximum historical severity per technology
- **CERT-In / CISA** — Real advisory bulletin references
- **NIST CSF & SP 800-53** — Prescriptive security controls

</td>
<td width="50%">

### 📤 Export & Reporting
- **CSV Export** — Structured threat dataset for spreadsheets or SIEM
- **Markdown Report** — Executive assessment report with disclaimer
- **Sample Scenario** — Pre-loaded university portal demo
- **28 Unit Tests** — Full pytest suite, all passing ✅

</td>
</tr>
</table>

---

## 🧠 How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                        YOU (the user)                               │
│  Enter: System Name · Description · Components · Tech Stack         │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │      app.py          │
                    │  (Streamlit UI)      │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  threat_engine.py    │  ◄── Applies STRIDE rules
                    │  (Core AI Engine)    │  ◄── Runs keyword heuristics
                    └──────────┬──────────┘
                               │
         ┌─────────────────────┼──────────────────────┐
         │                     │                      │
┌────────▼────────┐  ┌─────────▼────────┐  ┌─────────▼──────────────┐
│  risk_scoring   │  │ report_generator │  │ real_world_threat_intel │
│                 │  │                  │  │                         │
│ Likelihood ×    │  │ CSV + Markdown   │  │ CVE · MITRE ATT&CK      │
│ Impact Matrix   │  │ report export    │  │ NIST · CVSS · CERT-In   │
└─────────────────┘  └──────────────────┘  └─────────────────────────┘
         │                     │                      │
         └─────────────────────▼──────────────────────┘
                               │
              ┌────────────────▼───────────────────┐
              │         Results Dashboard           │
              │  Threat Register · Risk Cards       │
              │  Analytics Charts · Export Center   │
              └────────────────────────────────────┘
```

---

## 📂 Project Structure

```
ai-cybersecurity-threat-modeling-tool/
│
├── 📄 app.py                       ← Streamlit dashboard (UI, layout, tabs, export)
├── 🧠 threat_engine.py             ← STRIDE rules, heuristic scanner, component catalogue
├── 🌐 real_world_threat_intel.py   ← CVE / CVSS / MITRE ATT&CK / NIST / CERT-In data
├── 📊 risk_scoring.py              ← 5×5 Likelihood × Impact matrix & tier calculator
├── 📝 report_generator.py          ← CSV dataset & Markdown report formatter
├── 📦 requirements.txt             ← Python dependencies
├── 📖 README.md                    ← You are here
│
└── 🧪 tests/
    └── test_threat_engine.py       ← 28 automated pytest unit & integration tests
```

---

## 🎯 The STRIDE Framework

STRIDE is Microsoft's industry-standard threat modeling methodology. Each letter represents a category of security threat:

| | Category | Property Violated | What It Means | Key Defenses |
|:---:|:---|:---:|:---|:---|
| **S** | **S**poofing | Authenticity | Attacker impersonates a legitimate user or service | MFA, signed JWTs, secure session cookies |
| **T** | **T**ampering | Integrity | Unauthorized modification of data or code in transit/at rest | Parameterized queries, HMAC, input validation |
| **R** | **R**epudiation | Non-repudiability | User denies performing an action due to missing audit logs | Immutable audit trails, centralized SIEM logging |
| **I** | **I**nformation Disclosure | Confidentiality | Sensitive data exposed to unauthorized parties | TLS 1.3, AES-256 at rest, CORS, PII masking |
| **D** | **D**enial of Service | Availability | Resources exhausted to cause service downtime | Rate limiting, WAF, CDN, connection pool quotas |
| **E** | **E**levation of Privilege | Authorization | Attacker gains admin/root access they shouldn't have | RBAC/ABAC, IDOR checks, least-privilege principle |

---

## 📊 Risk Scoring — 5×5 Matrix

```
Risk Score  =  Likelihood (1–5)  ×  Impact (1–5)      Range: 1–25
```

| Score | Level | Indicator | Action |
|:---:|:---:|:---:|:---|
| 1–4 | Low | 🟢 | Acceptable — apply standard security hygiene |
| 5–9 | Medium | 🟡 | Schedule remediation in next sprint |
| 10–16 | High | 🟠 | Fix before production release |
| 17–25 | Critical | 🔴 | **Immediate action required — deployment blocker** |

---

## 🌐 Threat Intelligence Coverage

This tool cross-references your tech stack against curated intelligence from 6 major security frameworks:

| Framework | What You Get |
|:---|:---|
| 🔴 **MITRE ATT&CK®** | Active attack tactic & technique IDs (e.g. T1190 Exploit Public-Facing App) |
| 🟠 **CWE (MITRE)** | Common Weakness Enumeration IDs (e.g. CWE-89 SQL Injection) |
| 🟡 **CVSS v3** | Maximum historical severity score per technology (0.0–10.0) |
| 🔵 **NIST CSF & SP 800-53** | Identify / Protect / Detect controls mapped per component |
| 🟣 **CERT-In / CISA** | Real Indian and US government advisory bulletin references |
| ⚪ **CVE Database** | Historical vulnerability count and highest-severity CVE per service |

**Technologies with full intel profiles:**
`PostgreSQL` · `MySQL` · `Docker` · `Kubernetes` · `Redis` · `Nginx` · `Apache` · `AWS S3` · `JWT` · `OpenSSL` · `Stripe`

---

## 📸 Screenshots

> Run the app with `streamlit run app.py` and open `http://localhost:8501`

<br/>

**🖥️ 1 — Main Dashboard**
> Dark-themed cybersecurity UI with live Critical / High / Medium / Low metric counters and sidebar architecture input panel

---

**📋 2 — Threat Register**
> Sortable and filterable data table showing every identified threat with STRIDE category, risk score (1–25), affected component, and mitigation summary

---

**🔍 3 — Mitigation Detail Cards**
> Expandable accordion cards with full threat scenarios, MITRE ATT&CK tactic IDs, CVSS severity scores, CWE weakness references, and step-by-step remediation guidance

---

**📊 4 — STRIDE Analytics**
> Bar charts visualising threat distribution across all 6 STRIDE categories and 4 risk severity tiers

---

**🌐 5 — Real-World Threat Intel Lookup**
> Type any technology name (PostgreSQL, Docker, JWT, Nginx…) and instantly see its complete CVE history, CVSS score, MITRE tactics, NIST controls, and CERT-In advisories

---

**📥 6 — Export Centre**
> One-click download for a structured `.csv` threat dataset and an executive `.md` security assessment report

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.9+** (3.10 or 3.11 recommended)
- `pip` package manager
- Works on **Windows**, **macOS**, and **Linux**

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Sukhmnpreetkaur/ai-cybersecurity-threat-modeling-tool.git
cd ai-cybersecurity-threat-modeling-tool

# 2. Create a virtual environment
python -m venv venv

# Activate — Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# Activate — macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch the app 🚀
streamlit run app.py
```

The app opens automatically at **[http://localhost:8501](http://localhost:8501)**

### Windows — Execution Policy Fix
If PowerShell blocks the venv activation script:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 🎓 Try the Demo — College Portal Scenario

The tool ships with a built-in university portal scenario so you can explore immediately without typing anything:

```
1. Click  ➡  "🎓 Load College Sample"  in the sidebar
2. Click  ➡  "🚀 Analyze Threats"
3. Explore the results!
```

| Tab | What You'll See |
|:---|:---|
| **Threat Register** | SQL Injection, PII Exposure, Session Fixation, Malicious PDF Uploads |
| **Mitigation Cards** | MITRE T1190, CWE-89, CVSS 9.8, step-by-step fixes |
| **Analytics** | STRIDE category distribution charts |
| **Export Centre** | Download CSV + Markdown report |

---

## 🧪 Automated Tests

**28 unit and integration tests** covering all core modules — all passing ✅

```bash
pytest -v
```

```
tests/test_threat_engine.py::TestRiskScoring::test_score_multiplication        PASSED
tests/test_threat_engine.py::TestRiskScoring::test_low_tier_classification     PASSED
tests/test_threat_engine.py::TestRiskScoring::test_medium_tier_classification  PASSED
tests/test_threat_engine.py::TestRiskScoring::test_high_tier_classification    PASSED
tests/test_threat_engine.py::TestRiskScoring::test_critical_tier_classification PASSED
tests/test_threat_engine.py::TestThreatEngine::test_full_stride_coverage       PASSED
tests/test_threat_engine.py::TestThreatEngine::test_heuristic_keyword_upload   PASSED
tests/test_threat_engine.py::TestThreatEngine::test_heuristic_keyword_payment  PASSED
tests/test_threat_engine.py::TestThreatEngine::test_input_validation_errors    PASSED
tests/test_threat_engine.py::TestReportGenerator::test_csv_generation          PASSED
tests/test_threat_engine.py::TestReportGenerator::test_markdown_disclaimer     PASSED
...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
28 passed in 0.42s ✅
```

| Test Class | Module | Covers |
|:---|:---|:---|
| `TestRiskScoring` | `risk_scoring.py` | Score multiplication, bounds (1–25), all 4 tier classifications |
| `TestThreatEngine` | `threat_engine.py` | STRIDE coverage, component rules, keyword heuristics, input validation |
| `TestReportGenerator` | `report_generator.py` | CSV syntax, Markdown structure, human review disclaimer |

---

## 🛠️ Troubleshooting

| Error | Fix |
|:---|:---|
| `Scripts cannot be loaded` | `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| `'streamlit' is not recognized` | `python -m streamlit run app.py` |
| `Port 8501 already in use` | `streamlit run app.py --server.port 8502` |
| `ModuleNotFoundError` | Activate venv → `pip install -r requirements.txt` |
| Any import error | Make sure all 5 `.py` files are in the same directory |

---

## ⚠️ Disclaimer

> **Educational & Defensive Use Only**
>
> - This tool uses a deterministic heuristic rule engine. It does **not** guarantee detection of all threats, zero-days, or complex business logic flaws.
> - All findings must be reviewed and validated by qualified security professionals before being acted upon.
> - The tool performs **no network scanning, no intrusive probing, and no offensive operations** of any kind.
> - CVE IDs, CVSS scores, and MITRE tactic IDs are curated for educational demonstration. Always verify against live sources:
>   - [nvd.nist.gov](https://nvd.nist.gov) — CVE / CVSS
>   - [attack.mitre.org](https://attack.mitre.org) — MITRE ATT&CK
>   - [cert-in.org.in](https://www.cert-in.org.in) — CERT-In advisories

---

## 👩‍💻 Author

<div align="center">

**Sukhmanpreet Kaur**

*Cybersecurity Enthusiast | Python Developer | Sure Trust Training Program*

[![GitHub](https://img.shields.io/badge/GitHub-Sukhmnpreetkaur-181717?style=for-the-badge&logo=github)](https://github.com/Sukhmnpreetkaur)

</div>

---

## 📄 License

This project is licensed under the **MIT License** — free to use, modify, and distribute for educational and non-commercial purposes.

---

<div align="center">

**If this project helped you, please consider giving it a ⭐ star on GitHub!**

*Built with ❤️ to make cybersecurity accessible, educational, and open source.*

</div>
