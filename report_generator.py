"""
Report Generator for AI-Assisted Threat Modeling Tool.
Generates structured, downloadable CSV datasets and comprehensive Markdown
security assessment reports with human review disclaimers.
"""

import csv
import io
from datetime import datetime
from typing import List, Dict, Any, Optional



def generate_csv_report(threats: List[Dict[str, Any]]) -> str:
    """
    Serializes a list of threat findings into a standard RFC 4180 CSV string.

    Args:
        threats: List of enriched threat dictionaries.

    Returns:
        CSV string suitable for download.
    """
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    headers = [
        "Threat ID",
        "STRIDE Category",
        "Target Component",
        "Threat Title",
        "Description",
        "Likelihood (1-5)",
        "Impact (1-5)",
        "Risk Score (1-25)",
        "Risk Level",
        "Recommended Mitigation",
        "Detection Source",
    ]
    writer.writerow(headers)

    for t in threats:
        writer.writerow([
            t.get("id", ""),
            t.get("category", ""),
            t.get("component", ""),
            t.get("title", ""),
            t.get("description", ""),
            t.get("likelihood", ""),
            t.get("impact", ""),
            t.get("risk_score", ""),
            t.get("risk_level", ""),
            t.get("mitigation", ""),
            t.get("source", ""),
        ])

    return output.getvalue()


def generate_markdown_report(
    system_name: str,
    system_description: str,
    selected_components: List[str],
    threats: List[Dict[str, Any]],
    stats: Dict[str, Any],
    detected_services: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    Builds a professional, comprehensive Markdown security assessment report.

    Args:
        system_name: System name analyzed.
        system_description: User-provided architecture overview.
        selected_components: Architectural components assessed.
        threats: List of identified threat findings.
        stats: Aggregated threat metrics.

    Returns:
        Formatted markdown report string.
    """
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    components_str = ", ".join(selected_components)
    category_counts = stats.get("category_counts", {})

    lines = [
        f"# Threat Modeling Security Assessment Report",
        f"**Target System:** {system_name}  ",
        f"**Assessment Date:** {generated_at}  ",
        f"**Framework:** Microsoft STRIDE (Rule-Based Heuristic Engine)  ",
        f"**Components in Scope:** {components_str}  ",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        "This security assessment summarizes the potential threats identified for the specified architecture. "
        "Threats were classified according to the STRIDE methodology and prioritized using a standard 5x5 Likelihood-Impact risk matrix.",
        "",
        "| Risk Level | Finding Count | Score Range | Immediate Action Required |",
        "| :--- | :--- | :--- | :--- |",
        f"| **Critical** | {stats.get('critical', 0)} | 17 – 25 | Immediate remediation required prior to production deployment. |",
        f"| **High** | {stats.get('high', 0)} | 10 – 16 | Remediate in the next development cycle; implement compensating controls. |",
        f"| **Medium** | {stats.get('medium', 0)} | 5 – 9 | Address as part of regular security backlog and technical debt. |",
        f"| **Low** | {stats.get('low', 0)} | 1 – 4 | Acceptable risk or low-effort defensive hardening. |",
        f"| **Total Identified** | **{stats.get('total', 0)}** | 1 – 25 | Comprehensive STRIDE threat landscape. |",
        "",
        "---",
        "",
        "## 2. System Architecture & Context",
        "",
        f"**Description Provided:**",
        f"> {system_description}",
        "",
        "### Evaluated Architectural Components",
        "".join([f"- **{c}**\n" for c in selected_components]),
        "---",
        "",
        "## 3. STRIDE Threat Distribution",
        "",
        "| STRIDE Category | Threat Focus | Identified Findings |",
        "| :--- | :--- | :--- |",
        f"| **Spoofing** | Identity impersonation & credential theft | {category_counts.get('Spoofing', 0)} |",
        f"| **Tampering** | Data or code modification in transit or at rest | {category_counts.get('Tampering', 0)} |",
        f"| **Repudiation** | Denying performed actions due to lack of audit trail | {category_counts.get('Repudiation', 0)} |",
        f"| **Information Disclosure** | Data breaches, credential leaks, and eavesdropping | {category_counts.get('Information Disclosure', 0)} |",
        f"| **Denial of Service** | Resource exhaustion, crash loops, and outages | {category_counts.get('Denial of Service', 0)} |",
        f"| **Elevation of Privilege** | Bypassing authorization and unauthorized root/admin access | {category_counts.get('Elevation of Privilege', 0)} |",
        "",
        "---",
        "",
        "## 4. Detailed Threat Register & Actionable Mitigations",
        "",
    ]

    for idx, t in enumerate(threats, 1):
        lines.extend([
            f"### {idx}. [{t['id']}] {t['title']}",
            f"- **STRIDE Category:** `{t['category']}`",
            f"- **Target Component:** `{t['component']}`",
            f"- **Risk Rating:** **{t['risk_level'].upper()}** (Score: {t['risk_score']} | Likelihood: {t['likelihood']}/5 | Impact: {t['impact']}/5)",
            f"- **Detection Source:** *{t['source']}*",
            "",
            f"**Threat Scenario:**",
            f"{t['description']}",
            "",
            f"**Recommended Mitigation:**",
            f"> {t['mitigation']}",
            "",
            "---",
        ])

    if detected_services:
        lines.extend([
            "",
            "## 5. Real-World Framework Mapping (MITRE ATT&CK, NIST CSF & CERT-In)",
            "",
            "The following production technologies detected in your architecture were correlated with active CVEs, MITRE tactics, and security advisories:",
            "",
        ])
        for s in detected_services:
            lines.extend([
                f"### Service: {s['service_name']} ({s['category']})",
                f"- **Historical Max CVSS Severity:** `{s['cvss_threat_level']}`",
                f"- **MITRE ATT&CK Tactics:** {', '.join(s['mitre_tactics'])}",
                f"- **Common Weaknesses (CWE):** {', '.join(s['cwe_weaknesses'])}",
                f"- **NIST CSF Controls:** {', '.join(s['nist_csf_controls'])}",
                f"- **CERT-In / CISA Advisories:** {', '.join(s['cert_in_cisa_alerts'])}",
                "",
                "**Hardening Actions:**",
            ])
            for h in s["hardening_checklist"]:
                lines.append(f"- [ ] {h}")
            lines.append("")

    disclaimer_num = 6 if detected_services else 5
    lines.extend([
        "",
        f"## {disclaimer_num}. Limitations & Human Review Disclaimer",
        "",
        "> [!IMPORTANT]",
        "> **Human Review Required:** This report was produced using a deterministic, rule-based heuristic threat detection engine intended for educational and preliminary architectural threat modeling. **This tool does not and cannot guarantee detection of all security vulnerabilities, zero-days, or business logic flaws.**",
        ">",
        "> Automated and rule-based findings represent potential architectural risk patterns and must always be reviewed, verified, and contextualized by qualified cybersecurity professionals, software architects, and penetration testers before making production deployment decisions.",
        "",
        "---",
        "*Report generated by AI-Assisted Cybersecurity Threat Modeling Tool.*",
    ])

    return "\n".join(lines)
