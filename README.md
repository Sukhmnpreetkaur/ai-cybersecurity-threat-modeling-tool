# 🛡️ AI-Assisted Cybersecurity Threat Modeling Tool

An interactive, beginner-friendly, and privacy-preserving cybersecurity threat modeling dashboard built with **Python** and **Streamlit**. 

This tool implements Microsoft's **STRIDE** framework and a **5×5 Risk Scoring Matrix** to automate architectural threat discovery, evaluate risk severity, and provide actionable security mitigations.

> **Privacy & Ethics Assurance:** This application runs **100% locally**. It requires **no paid external AI APIs**, transmits **zero telemetry**, and performs **no offensive attacks or external network scanning**.

---

## 📋 Table of Contents
- [Key Features](#-key-features)
- [Project Architecture & File Structure](#-project-architecture--file-structure)
- [The STRIDE Framework](#-the-stride-framework)
- [Risk Scoring Methodology (5×5 Matrix)](#-risk-scoring-methodology-55-matrix)
- [Quick Start Guide](#-quick-start-guide)
  - [Prerequisites](#prerequisites)
  - [Installation Steps](#installation-steps)
  - [Running the Application](#running-the-application)
- [Sample Walkthrough: College Portal](#-sample-walkthrough-college-portal)
- [Running Automated Tests](#-running-automated-tests)
- [Troubleshooting & Common Fixes](#-troubleshooting--common-fixes)
- [Screenshots](#-screenshots)
- [Limitations & Human Review Disclaimer](#-limitations--human-review-disclaimer)
- [Defensive Use & Ethical Guidelines](#-defensive-use--ethical-guidelines)

---

## 🚀 Key Features

- **Cybersecurity Dark Theme Dashboard:** Modern, console-inspired interface with responsive metric counters and neon severity accents.
- **STRIDE Threat Modeling Engine:** Comprehensive heuristic detection across all 6 STRIDE categories:
  - **S**poofing
  - **T**ampering
  - **R**epudiation
  - **I**nformation Disclosure
  - **D**enial of Service
  - **E**levation of Privilege
- **Component-Driven Analysis:** Evaluates key architectural building blocks:
  - *Web application*, *Database*, *API*, *Authentication system*, *File storage*, and *Network*.
- **Heuristic Context Detection:** Scans architectural descriptions for keywords (`upload`, `ssn`, `cookies`, `payment`, `admin`, `unencrypted`) and dynamically adjusts likelihood, impact, and mitigations.
- **5×5 Risk Scoring Matrix:** Calculates `Likelihood (1–5) × Impact (1–5)` and assigns qualitative tiers (*Low*, *Medium*, *High*, *Critical*).
- **Interactive Filtering & Search:** Filter findings instantly by STRIDE category, risk level, or text query.
- **Export Center:** Download structured **CSV datasets** and executive **Markdown assessment reports**.
- **Sample Scenario Included:** One-click loader for a fictional university student and faculty portal scenario.
- **Input Validation & Error Handling:** Graceful validation warnings for missing inputs or invalid component selections.
- **Real-World Threat Intelligence & Framework Mapping:**
  - **MITRE ATT&CK® & CWE:** Cross-references technologies with active attack tactics (T1190, T1611, etc.) and weakness IDs (CWE-89, CWE-22, etc.).
  - **CVSS Historical Ratings:** Displays maximum historical CVSS severity (e.g., 9.8 / 10.0) and vulnerability profiles.
  - **NIST CSF & SP 800-53:** Prescribes specific Identify, Protect, and Detect controls for each service.
  - **CERT-In & CISA Bulletins:** Informs about real-world exploit advisories (CIVN/CIAD) and ransomware targets.
  - **Interactive Technology Lookup:** Search and inspect threat histories for *PostgreSQL, Docker, Redis, Nginx, Apache, AWS S3, Stripe, Kubernetes, JWT, OpenSSL, and MySQL*.

---

## 📂 Project Architecture & File Structure

```text
AI-Threat-Modeling-Tool/
│
├── app.py                      # Main Streamlit dashboard UI and layout
├── threat_engine.py            # STRIDE rules, component catalogue & heuristic scanner
├── real_world_threat_intel.py  # CVE, CVSS, MITRE ATT&CK, NIST CSF & CERT-In intelligence
├── risk_scoring.py             # 5x5 Likelihood x Impact matrix & risk level calculator
├── report_generator.py         # Formats downloadable CSV datasets and Markdown reports
├── requirements.txt            # Python dependencies (Streamlit, Pandas, Pytest)
├── README.md                   # Complete documentation and setup manual
│
└── tests/
    └── test_threat_engine.py   # Automated pytest unit and integration test suite
```

### Module Roles
- **`real_world_threat_intel.py`**: Curated intelligence correlating specific technology stacks with MITRE ATT&CK tactics, NIST controls, CERT-In alerts, and historical CVE/CVSS vectors.
- **`risk_scoring.py`**: Pure calculation functions for multiplying likelihood and impact, validating integer bounds (1–5), and mapping results into risk tiers (Low, Medium, High, Critical).
- **`threat_engine.py`**: Core heuristic rule engine storing baseline threats for each component and detecting risk patterns in user-submitted system descriptions.
- **`report_generator.py`**: Exports structured reports with an executive summary, threat register, mitigations, and disclaimers.
- **`app.py`**: The Streamlit user interface featuring sidebar configuration, metric cards, data tables, visual analytics, and export buttons.

---

## 🎯 The STRIDE Framework

| Category | Security Property Violated | Threat Description | Common Remediation |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Authenticity | Impersonating an authorized user or service | MFA, signed JWTs (RS256), secure cookies |
| **Tampering** | Integrity | Unauthorized modification of data or code | Parameterized queries, input validation, HMAC checks |
| **Repudiation** | Non-repudiability | Denying performed actions due to lack of proof | Immutable audit trails, centralized SIEM logging |
| **Information Disclosure** | Confidentiality | Unauthorized exposure of sensitive data | TLS 1.3, AES-256 at rest, strict CORS, PII masking |
| **Denial of Service** | Availability | Exhausting resources to cause service downtime | Rate limiting, connection pool quotas, WAF, CDN |
| **Elevation of Privilege** | Authorization | Gaining unauthorized admin/root permissions | Strict RBAC/ABAC, IDOR verification, least privilege |

---

## 📊 Risk Scoring Methodology (5×5 Matrix)

$$\text{Risk Score} = \text{Likelihood } (1\dots5) \times \text{Impact } (1\dots5)$$

| Likelihood (1–5) | Impact (1–5) | Score (1–25) | Qualitative Risk Level | Action Standard |
| :---: | :---: | :---: | :---: | :--- |
| 1 – 2 | 1 – 2 | **1 – 4** | 🟢 **Low** | Acceptable risk; apply standard hygiene. |
| 2 – 3 | 2 – 3 | **5 – 9** | 🟡 **Medium** | Schedule into regular development sprint. |
| 3 – 4 | 3 – 4 | **10 – 16** | 🟠 **High** | Remediate prior to production release. |
| 4 – 5 | 4 – 5 | **17 – 25** | 🔴 **Critical** | Immediate mitigation; blocker for deployment. |

---

## ⚡ Quick Start Guide

### Prerequisites
- **Python 3.9+** (Python 3.10, 3.11, or 3.12 recommended)
- **pip** package installer

### Installation Steps

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/YOUR_USERNAME/ai-cybersecurity-threat-modeling-tool.git
   cd ai-cybersecurity-threat-modeling-tool
   ```

2. **Create and activate a Python virtual environment (recommended):**
   ```powershell
   # Create virtual environment
   python -m venv venv

   # Activate on Windows (PowerShell)
   .\venv\Scripts\Activate.ps1

   # Or on macOS/Linux (Bash)
   # source venv/bin/activate
   ```

3. **Install the dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

### Running the Application

Launch the Streamlit web dashboard:
```powershell
streamlit run app.py
```
After running, Streamlit will automatically open your default web browser to:
```text
http://localhost:8501
```

---

## 🎓 Sample Walkthrough: College Portal

To explore the tool quickly, use the pre-packaged sample dataset:

1. Click the **"🎓 Load College Sample"** button in the sidebar.
2. The sidebar fields will automatically populate with:
   - **System Name:** `Oakwood State University - Student & Faculty Portal`
   - **Description:** A public portal with student transcripts, assignment PDF uploads, payment gateways, legacy session cookies, and database with SSNs.
   - **Components:** Web application, Database, API, Authentication system, File storage, Network.
3. Click **"🚀 Analyze Threats"**.
4. Explore:
   - **Metric Cards:** Review counts of Critical, High, Medium, and Low risks.
   - **Threat Register:** Inspect identified threats such as *Malicious PDF Uploads*, *PII Exposure*, and *Session Fixation*.
   - **Filters:** Filter by `Critical` or search for `upload`.
   - **Analytics Tab:** Visualize STRIDE category distributions.
   - **Export Center:** Download your `.csv` dataset or `.md` report.

---

## 🧪 Running Automated Tests

Run the test suite using `pytest`:

```powershell
pytest -v
```

### What the test suite covers:
- **`TestRiskScoring`**: Validates multiplication logic, integer type checks, bounds checks, and classifications across all score brackets (1–25).
- **`TestThreatEngine`**: Validates input validation error handling, component rule generation, complete STRIDE coverage, and heuristic keyword triggers.
- **`TestReportGenerator`**: Validates CSV syntax and Markdown report generation with human review disclaimer guarantees.

---

## 🛠️ Troubleshooting & Common Fixes

### 1. PowerShell Script Execution Policy Error
**Error:** `.\venv\Scripts\Activate.ps1 cannot be loaded because running scripts is disabled on this system.`  
**Fix:** Run PowerShell with an adjusted execution policy for your user session:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 2. Streamlit Command Not Found
**Error:** `'streamlit' is not recognized as an internal or external command.`  
**Fix:** Ensure your virtual environment is active, or invoke Streamlit through Python:
```powershell
python -m streamlit run app.py
```

### 3. Port 8501 Already in Use
**Error:** `Port 8501 is already in use.`  
**Fix:** Specify an alternate port:
```powershell
streamlit run app.py --server.port 8502
```

---

## 📸 Screenshots

> **For reviewers:** Run `streamlit run app.py`, take screenshots of each view below, save them in a `screenshots/` folder, and replace the image paths.

| View | Description |
| :--- | :--- |
| **1 — Dashboard Overview** | Cyber-themed header, live metric counters (Critical / High / Medium / Low), and sidebar configuration panel |
| **2 — Threat Register** | Sortable & filterable data table with STRIDE category, risk score (1–25), component, and mitigation columns |
| **3 — Mitigation Detail Cards** | Expandable accordion cards with full threat scenarios, MITRE ATT&CK IDs, CVSS scores, and fix recommendations |
| **4 — STRIDE Analytics** | Bar charts visualising threat distribution across all 6 STRIDE categories and 4 risk tiers |
| **5 — Real-World Intel Tab** | Technology lookup panel cross-referencing CVE history, CERT-In advisories, NIST CSF controls, and MITRE tactics |
| **6 — Export Centre** | One-click CSV dataset and Markdown report download buttons |

<!-- 
  ─── HOW TO ADD REAL SCREENSHOTS ────────────────────────────────────────────
  1. Create a folder called `screenshots/` in the project root.
  2. Run the app: `streamlit run app.py`
  3. Take a screenshot of each view and save with these exact names:
       screenshots/01_dashboard_overview.png
       screenshots/02_threat_register.png
       screenshots/03_mitigation_cards.png
       screenshots/04_stride_analytics.png
       screenshots/05_realworld_intel.png
       screenshots/06_export_centre.png
  4. Uncomment the lines below (remove the HTML comment tags).
-->

<!--
![Dashboard Overview](screenshots/01_dashboard_overview.png)
*Figure 1 — Main dashboard with live threat metric counters*

![Threat Register](screenshots/02_threat_register.png)
*Figure 2 — Filterable threat register with STRIDE categories and risk scores*

![STRIDE Analytics](screenshots/04_stride_analytics.png)
*Figure 4 — Visual analytics tab showing threat distribution charts*
-->

---

## ⚠️ Limitations & Human Review Disclaimer

> [!IMPORTANT]
> **Human Review Required:**
> 1. **No Guarantee of 100% Coverage:** This application uses a transparent, deterministic rule-based heuristic engine designed for preliminary architectural modeling and security training. It **does not guarantee detection of all potential threats**, zero-day exploits, or complex business logic flaws.
> 2. **Context Matters:** Real-world security depends heavily on specific implementation details, library versions, configurations, and network environments that cannot be fully captured in high-level descriptions.
> 3. **Mandatory Human Validation:** Findings generated by this tool must always be validated and prioritized by qualified security professionals, system architects, and penetration testing specialists.

---

## 🛡️ Defensive Use & Ethical Guidelines

This tool is strictly designed for **defensive security engineering**, **educational threat modeling**, and **architectural risk assessment**. 
- It does **not** include exploit payloads or offensive scanning modules.
- It does **not** perform intrusive probing or scan external systems.
- It helps developers build secure software by design before writing code.
