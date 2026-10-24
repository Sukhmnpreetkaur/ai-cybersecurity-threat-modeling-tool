# 🛡️ AI-Assisted Cybersecurity Threat Modeling Tool

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.30%2B-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![STRIDE](https://img.shields.io/badge/Framework-STRIDE-0078D4?style=for-the-badge)
![MITRE](https://img.shields.io/badge/Intel-MITRE%20ATT%26CK-red?style=for-the-badge)
![Tests](https://img.shields.io/badge/Tests-28%20Passing-brightgreen?style=for-the-badge&logo=pytest)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**An AI-powered, interactive cybersecurity threat modeling dashboard built with Python & Streamlit.**  
Implements Microsoft's STRIDE framework with real-world threat intelligence from MITRE ATT&CK, NIST, CVE, and CERT-In.

[Features](#-key-features) • [Architecture](#-project-architecture) • [Quick Start](#-quick-start) • [Screenshots](#-screenshots) • [Tests](#-automated-tests) • [Disclaimer](#-disclaimer)

</div>

---

## 📌 About the Project

This tool was developed as part of the **Sure Trust Cybersecurity Training Program** to demonstrate applied threat modeling techniques using industry-standard security frameworks.

It enables developers, architects, and security students to:
- **Input** a real system's architecture, tech stack, and components
- **Analyze** threats automatically using the STRIDE heuristic engine
- **Cross-reference** findings with live CVE records, MITRE ATT&CK tactics, NIST CSF controls, and CERT-In advisories
- **Export** structured CSV datasets and Markdown security assessment reports

> **🔒 Privacy Guarantee:** This application runs **100% locally** on your machine. It requires no paid APIs, transmits zero telemetry, and performs no offensive attacks or network scanning of any kind.

---

## 🚀 Key Features

### 🧠 Core Intelligence
| Feature | Description |
| :--- | :--- |
| **STRIDE Engine** | Heuristic detection across all 6 STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege) |
| **Real-World Threat Intel** | Cross-references 11+ technology stacks with live CVE history, CVSS severity scores, MITRE ATT&CK tactics, and CERT-In bulletins |
| **5×5 Risk Matrix** | Calculates `Likelihood (1–5) × Impact (1–5)` and classifies findings as Low / Medium / High / Critical |
| **Heuristic Context Scan** | Detects risk-amplifying keywords in system descriptions (`upload`, `ssn`, `payment`, `admin`, `unencrypted`) and dynamically adjusts threat severity |

### 🖥️ Dashboard & UX
| Feature | Description |
| :--- | :--- |
| **Dark Theme UI** | Cybersecurity console-inspired interface with neon severity accents and real-time metric counters |
| **Component Analysis** | Evaluates Web App, Database, API, Authentication, File Storage, and Network components |
| **Interactive Filters** | Instantly filter the threat register by STRIDE category, risk level, or keyword search |
| **Mitigation Cards** | Expandable detail cards with MITRE tactic IDs, CVSS scores, CWE references, and actionable fix recommendations |
| **STRIDE Analytics** | Visual bar charts showing threat distribution across categories and severity tiers |
| **Export Centre** | One-click download of structured CSV datasets and executive Markdown reports |
| **Sample Scenario** | Pre-loaded university portal demo for instant exploration |

### 🌐 Threat Intelligence Coverage
| Source | Data Provided |
| :--- | :--- |
| **MITRE ATT&CK®** | Active attack tactic IDs (e.g. T1190, T1611) mapped per technology |
| **CWE (MITRE)** | Weakness IDs (e.g. CWE-89 SQL Injection, CWE-22 Path Traversal) |
| **CVSS** | Maximum historical severity score and vulnerability profile per service |
| **NIST CSF & SP 800-53** | Identify, Protect, and Detect controls prescribed per component |
| **CERT-In / CISA** | Real advisory bulletin references (CIVN/CIAD) and ransomware targeting history |
| **CVE Database** | Historical vulnerability counts and exploit severity for PostgreSQL, Docker, Redis, Nginx, Apache, AWS S3, Stripe, Kubernetes, JWT, OpenSSL, MySQL |

---

## 📂 Project Architecture

```
AI-Threat-Modeling-Tool/
│
├── app.py                       # Streamlit dashboard — UI, layout, sidebar, tabs, export
├── threat_engine.py             # STRIDE heuristic rule engine & component catalogue
├── real_world_threat_intel.py   # CVE / CVSS / MITRE ATT&CK / NIST CSF / CERT-In data
├── risk_scoring.py              # 5×5 Likelihood × Impact matrix & risk tier calculator
├── report_generator.py          # CSV dataset & Markdown report formatter
├── requirements.txt             # Python dependencies
├── README.md                    # Project documentation
│
└── tests/
    └── test_threat_engine.py    # 28 automated pytest unit & integration tests
```

### Module Responsibilities

```
┌─────────────────────────────────────────────────────────────────┐
│                          app.py (UI Layer)                       │
│          Sidebar Input → Analyze Button → Results Display        │
└─────────────────────┬───────────────────────────────────────────┘
                      │
          ┌───────────▼───────────┐
          │    threat_engine.py   │  ← Applies STRIDE rules per component
          │  (Core STRIDE Engine) │  ← Runs heuristic keyword scan
          └───────────┬───────────┘
                      │
     ┌────────────────┼─────────────────┐
     │                │                 │
┌────▼─────┐  ┌───────▼────────┐  ┌────▼──────────────────┐
│risk_     │  │report_         │  │real_world_threat_      │
│scoring.py│  │generator.py    │  │intel.py                │
│          │  │                │  │                        │
│Likelihood│  │CSV + Markdown  │  │CVE · MITRE · NIST      │
│× Impact  │  │report export   │  │CVSS · CERT-In · CISA   │
└──────────┘  └────────────────┘  └────────────────────────┘
```

---

## 🎯 The STRIDE Framework

| Letter | Category | Security Property | Description | Key Mitigations |
| :---: | :--- | :--- | :--- | :--- |
| **S** | Spoofing | Authenticity | Impersonating a legitimate user or service | MFA, signed JWTs (RS256), secure session cookies |
| **T** | Tampering | Integrity | Unauthorized modification of data or code | Parameterized queries, input validation, HMAC |
| **R** | Repudiation | Non-repudiability | Denying performed actions due to missing logs | Immutable audit trails, SIEM logging |
| **I** | Information Disclosure | Confidentiality | Exposing sensitive data to unauthorized parties | TLS 1.3, AES-256 at rest, strict CORS, PII masking |
| **D** | Denial of Service | Availability | Exhausting resources to cause downtime | Rate limiting, WAF, CDN, connection quotas |
| **E** | Elevation of Privilege | Authorization | Gaining unauthorized admin / root permissions | RBAC/ABAC, IDOR checks, least-privilege principle |

---

## 📊 Risk Scoring — 5×5 Matrix

**Formula:** `Risk Score = Likelihood (1–5) × Impact (1–5)`

| Score Range | Risk Level | Colour | Action Required |
| :---: | :---: | :---: | :--- |
| 1 – 4 | Low | 🟢 | Acceptable risk — apply standard security hygiene |
| 5 – 9 | Medium | 🟡 | Schedule remediation in next development sprint |
| 10 – 16 | High | 🟠 | Remediate before production release |
| 17 – 25 | Critical | 🔴 | Immediate fix required — deployment blocker |

---

## ⚡ Quick Start

### Prerequisites
- Python **3.9** or higher
- `pip` package manager
- Windows / macOS / Linux

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/sure-trust/cyber-security-stu-96bb0b.git
cd cyber-security-stu-96bb0b/Assignments/AI-Threat-Modeling-Tool

# 2. Create a virtual environment
python -m venv venv

# Activate — Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# Activate — macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch the app
streamlit run app.py
```

The app will open automatically at **http://localhost:8501**

### PowerShell Execution Policy (Windows only)
If you see `cannot be loaded because running scripts is disabled`:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 🎓 Sample Walkthrough — College Portal Demo

The tool ships with a pre-loaded university portal scenario. Try it in 3 steps:

1. Click **"🎓 Load College Sample"** in the sidebar
2. Click **"🚀 Analyze Threats"**
3. Explore the results:

| What to Explore | Where to Find It |
| :--- | :--- |
| Critical & High threat counts | Top metric cards |
| SQL Injection, PII Exposure, Session Fixation | Threat Register tab |
| MITRE ATT&CK tactic IDs + CVSS scores | Mitigation Detail Cards |
| STRIDE category distribution chart | Analytics tab |
| Download CSV / Markdown report | Export Centre tab |

---

## 📸 Screenshots

> **To run the app:** `streamlit run app.py` → opens at `http://localhost:8501`

### 1. Dashboard Overview
The main dashboard showing the dark-themed cybersecurity UI with live metric counters for Critical, High, Medium, and Low threats, and the sidebar configuration panel.

### 2. Threat Register
A sortable and filterable data table displaying every identified threat with its STRIDE category, risk score (1–25), affected component, and recommended mitigation.

### 3. Mitigation Detail Cards
Expandable accordion cards showing the full threat scenario, MITRE ATT&CK tactic IDs, CVSS severity scores, CWE weakness references, and step-by-step fix recommendations.

### 4. STRIDE Analytics
Bar charts visualising the distribution of threats across all 6 STRIDE categories and 4 risk severity tiers.

### 5. Real-World Threat Intel Tab
The technology lookup panel — type any service name (e.g. PostgreSQL, Docker, Nginx, JWT) and instantly see its CVE history, maximum CVSS score, MITRE ATT&CK tactics, NIST controls, and CERT-In advisories.

### 6. Export Centre
One-click buttons to download a structured `.csv` threat dataset and an executive `.md` security assessment report with human review disclaimer.

---

## 🧪 Automated Tests

The project includes **28 automated unit and integration tests** covering all core modules.

```bash
# Run all tests with verbose output
pytest -v
```

```
tests/test_threat_engine.py::TestRiskScoring::test_score_calculation          PASSED
tests/test_threat_engine.py::TestRiskScoring::test_low_classification          PASSED
tests/test_threat_engine.py::TestRiskScoring::test_medium_classification       PASSED
tests/test_threat_engine.py::TestRiskScoring::test_high_classification         PASSED
tests/test_threat_engine.py::TestRiskScoring::test_critical_classification     PASSED
tests/test_threat_engine.py::TestThreatEngine::test_stride_coverage            PASSED
tests/test_threat_engine.py::TestThreatEngine::test_heuristic_keywords         PASSED
tests/test_threat_engine.py::TestReportGenerator::test_csv_generation          PASSED
tests/test_threat_engine.py::TestReportGenerator::test_markdown_disclaimer     PASSED
...
28 passed in 0.42s ✅
```

### Test Coverage by Module

| Test Class | Module Tested | What Is Verified |
| :--- | :--- | :--- |
| `TestRiskScoring` | `risk_scoring.py` | Score multiplication, bounds (1–25), all 4 tier classifications |
| `TestThreatEngine` | `threat_engine.py` | Input validation, component rules, full STRIDE coverage, keyword heuristics |
| `TestReportGenerator` | `report_generator.py` | CSV syntax validity, Markdown structure, human review disclaimer presence |

---

## 🛠️ Troubleshooting

| Error | Fix |
| :--- | :--- |
| `Scripts cannot be loaded` (PowerShell) | `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| `'streamlit' is not recognized` | `python -m streamlit run app.py` |
| `Port 8501 is already in use` | `streamlit run app.py --server.port 8502` |
| `ModuleNotFoundError` | Ensure venv is active, then `pip install -r requirements.txt` |
| `NameError: name 're' is not defined` | Ensure you're running the latest version of `app.py` from this repository |

---

## ⚠️ Disclaimer

> **This tool is for educational and defensive security engineering purposes only.**
>
> - Results are generated by a deterministic heuristic rule engine. They do **not** guarantee 100% threat coverage and may not capture zero-day exploits or complex business logic vulnerabilities.
> - All findings must be validated by qualified security professionals before being acted upon.
> - This tool performs **no network scanning**, **no intrusive probing**, and **no offensive operations** of any kind.
> - Real-world threat intelligence (CVE IDs, CVSS scores, MITRE tactic IDs) is curated for educational demonstration. Always verify against live databases at [nvd.nist.gov](https://nvd.nist.gov) and [attack.mitre.org](https://attack.mitre.org).

---

## 👩‍💻 Author

**Sukhmanpreet Kaur**  
Cybersecurity Student — Sure Trust Training Program  
GitHub: [@Sukhmnpreetkaur](https://github.com/Sukhmnpreetkaur)

---

## 📄 License

This project is licensed under the **MIT License** — free to use, modify, and distribute for educational purposes.

---

<div align="center">
Built with ❤️ for learning cybersecurity the right way — defensively, ethically, and thoroughly.
</div>
