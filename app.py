"""
AI-Assisted Cybersecurity Threat Modeling Tool
Interactive Streamlit Application implementing Microsoft STRIDE framework,
5x5 Risk Scoring, and Heuristic Threat Detection.
Runs completely offline with zero external API calls or data leakage.
"""

import re
import streamlit as st
import pandas as pd
from typing import List, Dict, Any

from risk_scoring import (
    calculate_risk_score,
    get_risk_level,
    RISK_LEVEL_COLORS,
    RISK_LEVEL_BADGES,
)
from threat_engine import (
    analyze_threats,
    compute_threat_metrics,
    STRIDE_CATEGORIES,
    SUPPORTED_COMPONENTS,
    SAMPLE_COLLEGE_PORTAL,
)
from report_generator import (
    generate_csv_report,
    generate_markdown_report,
)
from real_world_threat_intel import (
    lookup_service_intel,
    extract_services_from_text,
    TECHNOLOGY_INTEL_CATALOG,
)



# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="CyberThreat AI | Threat Modeling Tool",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- CYBERSECURITY DARK THEME CSS ---
CYBER_CSS = """
<style>
    /* Dark Cybersecurity Palette */
    :root {
        --cyber-bg: #0b1120;
        --cyber-card: #131d33;
        --cyber-border: #1e293b;
        --cyber-cyan: #00d2ff;
        --cyber-neon: #00e676;
        --cyber-orange: #ff9100;
        --cyber-red: #ff3366;
    }
    
    /* Top Header Bar */
    .cyber-header {
        background: linear-gradient(135deg, #0d1b2a 0%, #1b263b 50%, #0d1b2a 100%);
        border: 1px solid #1e3a5f;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 24px;
        box-shadow: 0 4px 20px rgba(0, 210, 255, 0.1);
    }
    .cyber-title {
        color: #00d2ff;
        font-size: 2.2rem;
        font-weight: 800;
        letter-spacing: -0.5px;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .cyber-subtitle {
        color: #94a3b8;
        font-size: 1rem;
        margin-top: 8px;
        margin-bottom: 0;
    }
    .cyber-pill {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .pill-local {
        background-color: rgba(0, 230, 118, 0.15);
        color: #00e676;
        border: 1px solid #00e676;
    }
    .pill-stride {
        background-color: rgba(0, 210, 255, 0.15);
        color: #00d2ff;
        border: 1px solid #00d2ff;
    }

    /* Metric Cards */
    .metric-card {
        background: #111a2e;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 18px 20px;
        text-align: center;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        border-color: #00d2ff;
    }
    .metric-val {
        font-size: 2.2rem;
        font-weight: 800;
        margin: 4px 0;
    }
    .metric-lbl {
        color: #94a3b8;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        font-weight: 600;
    }

    /* Badges */
    .badge-critical {
        background: rgba(255, 51, 102, 0.2);
        color: #ff3366;
        border: 1px solid #ff3366;
        padding: 3px 8px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.8rem;
    }
    .badge-high {
        background: rgba(255, 145, 0, 0.2);
        color: #ff9100;
        border: 1px solid #ff9100;
        padding: 3px 8px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.8rem;
    }
    .badge-medium {
        background: rgba(255, 214, 0, 0.2);
        color: #ffd600;
        border: 1px solid #ffd600;
        padding: 3px 8px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.8rem;
    }
    .badge-low {
        background: rgba(0, 230, 118, 0.2);
        color: #00e676;
        border: 1px solid #00e676;
        padding: 3px 8px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.8rem;
    }

    /* Threat Card Container */
    .threat-card {
        background-color: #111a2e;
        border: 1px solid #1e293b;
        border-left: 5px solid #00d2ff;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 14px;
    }
    .threat-card-critical { border-left-color: #ff3366; }
    .threat-card-high { border-left-color: #ff9100; }
    .threat-card-medium { border-left-color: #ffd600; }
    .threat-card-low { border-left-color: #00e676; }

    /* Footer Banner */
    .disclaimer-box {
        background-color: rgba(255, 145, 0, 0.08);
        border: 1px solid rgba(255, 145, 0, 0.3);
        border-radius: 8px;
        padding: 14px 18px;
        margin-top: 30px;
        color: #e2e8f0;
        font-size: 0.88rem;
    }
</style>
"""
st.markdown(CYBER_CSS, unsafe_allow_html=True)


# --- INITIALIZE SESSION STATE ---
if "system_name" not in st.session_state:
    st.session_state["system_name"] = ""
if "tech_stack" not in st.session_state:
    st.session_state["tech_stack"] = ""
if "system_description" not in st.session_state:
    st.session_state["system_description"] = ""
if "selected_components" not in st.session_state:
    st.session_state["selected_components"] = ["Web application", "Database", "Authentication system"]
if "analysis_results" not in st.session_state:
    st.session_state["analysis_results"] = None


# --- HELPER ACTIONS ---
def load_sample_college_data():
    """Populates input fields with sample college portal data."""
    st.session_state["system_name"] = SAMPLE_COLLEGE_PORTAL["system_name"]
    st.session_state["tech_stack"] = "PostgreSQL, Apache HTTP Server, OpenSSL, Legacy Cookies"
    st.session_state["system_description"] = SAMPLE_COLLEGE_PORTAL["system_description"]
    st.session_state["selected_components"] = SAMPLE_COLLEGE_PORTAL["selected_components"]
    st.session_state["analysis_results"] = None
    st.rerun()


def clear_all_inputs():
    """Resets all fields and clears analysis state."""
    st.session_state["system_name"] = ""
    st.session_state["tech_stack"] = ""
    st.session_state["system_description"] = ""
    st.session_state["selected_components"] = []
    st.session_state["analysis_results"] = None
    st.rerun()


# --- HEADER SECTION ---
st.markdown(
    """
    <div class="cyber-header">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div>
                <h1 class="cyber-title">🛡️ AI-Assisted Cybersecurity Threat Modeling Tool</h1>
                <p class="cyber-subtitle">Automated STRIDE threat discovery, 5×5 risk scoring matrix, and actionable security controls</p>
            </div>
            <div style="display: flex; gap: 8px;">
                <span class="cyber-pill pill-stride">STRIDE Framework</span>
                <span class="cyber-pill pill-local">🔒 100% Local / Zero Data Leakage</span>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# --- SIDEBAR: SYSTEM INPUT & COMPONENT SELECTOR ---
with st.sidebar:
    st.subheader("⚙️ System Architecture Input")
    st.caption("Provide architecture details to run heuristic threat modeling.")

    # Action buttons for demo / reset
    col_sb1, col_sb2 = st.columns(2)
    with col_sb1:
        if st.button("🎓 Load College Sample", help="Populate with fictional college portal scenario", use_container_width=True):
            load_sample_college_data()
    with col_sb2:
        if st.button("🔄 Clear All", help="Reset all fields", use_container_width=True):
            clear_all_inputs()

    st.divider()

    # System Name
    system_name_input = st.text_input(
        "System / Project Name *",
        value=st.session_state["system_name"],
        placeholder="e.g. My Secure App / CarePulse Telehealth",
        help="Identify the target software system or boundary under evaluation.",
    )
    st.session_state["system_name"] = system_name_input

    # Real-World Tech Stack & Services
    tech_stack_input = st.text_input(
        "Technologies, OS, VPNs & APIs in Scope",
        value=st.session_state.get("tech_stack", ""),
        placeholder="e.g. Windows, Android, proton.com, PostgreSQL, Twilio, Docker",
        help="Specify any operating systems (Windows, iOS, Android), VPNs (proton.com), databases, or APIs.",
    )
    st.session_state["tech_stack"] = tech_stack_input

    # System Description
    system_description_input = st.text_area(
        "System Architecture Description *",
        value=st.session_state["system_description"],
        placeholder="Describe technologies, data flow, sensitive assets (SSN, credit cards), user roles, uploads, or APIs...",
        height=170,
        help="Include data sensitivity, authentication mechanisms, third-party integrations, and deployment environments.",
    )
    st.session_state["system_description"] = system_description_input

    # Component Multiselect
    selected_components_input = st.multiselect(
        "Architectural Components in Scope *",
        options=SUPPORTED_COMPONENTS,
        default=st.session_state["selected_components"],
        help="Select all structural elements comprising this system.",
    )
    st.session_state["selected_components"] = selected_components_input

    st.divider()

    # Analyze Button
    analyze_clicked = st.button("🚀 Analyze Threats", type="primary", use_container_width=True)

    st.markdown(
        """
        <div style="margin-top: 20px; font-size: 0.78rem; color: #64748b; line-height: 1.4;">
            <strong>Privacy Note:</strong> All analysis runs completely inside your local Python runtime. 
            No prompts or architectural details are transmitted to third-party AI APIs.
        </div>
        """,
        unsafe_allow_html=True,
    )


# --- RUN THREAT ANALYSIS ON CLICK ---
if analyze_clicked:
    # Form validation
    if not system_name_input.strip():
        st.error("⚠️ Validation Error: Please provide a System / Project Name in the sidebar.")
    elif not system_description_input.strip():
        st.error("⚠️ Validation Error: Please provide a System Architecture Description in the sidebar.")
    elif len(selected_components_input) == 0:
        st.error("⚠️ Validation Error: Please select at least one Architectural Component.")
    else:
        with st.spinner("Analyzing architecture against STRIDE rules & heuristic triggers..."):
            try:
                # Merge tech stack into description for complete contextual inspection
                combined_desc = system_description_input
                if tech_stack_input.strip():
                    combined_desc = f"{system_description_input}\nTechnologies and services in use: {tech_stack_input}"

                results = analyze_threats(
                    system_name=system_name_input,
                    system_description=combined_desc,
                    selected_components=selected_components_input,
                )
                st.session_state["analysis_results"] = results
                st.session_state["combined_description"] = combined_desc
                st.toast("Threat modeling completed successfully!", icon="✅")
            except Exception as e:
                st.error(f"Analysis failed: {str(e)}")


# --- MAIN CONTENT AREA ---
threats: List[Dict[str, Any]] = st.session_state.get("analysis_results")

if not threats:
    # Welcoming Hero State when no analysis has been run yet
    st.info("👈 **Get Started:** Enter your system details in the sidebar and click **'Analyze Threats'**, or click **'Load College Sample'** for an instant preconfigured walkthrough.")

    with st.expander("ℹ️ How the STRIDE Threat Modeling Engine Works", expanded=True):
        st.markdown(
            """
            This tool implements Microsoft's industry-standard **STRIDE** security methodology combined with a **5×5 Likelihood & Impact Risk Scoring Matrix**:
            
            | Category | Definition | Real-world Scenario |
            | :--- | :--- | :--- |
            | **S - Spoofing** | Illegitimate identity impersonation | Stolen session cookies, forged JWTs, or credential brute-forcing |
            | **T - Tampering** | Unauthorized data or code modification | SQL injection, parameter manipulation, or malicious file uploads |
            | **R - Repudiation** | Plausible deniability due to lack of audit trail | Absence of database query logs or unmonitored grade changes |
            | **I - Information Disclosure** | Exposure of confidential data to unauthorized parties | Leaked student SSNs, unencrypted DB backups, or cleartext HTTP |
            | **D - Denial of Service** | Depriving authorized users of access to services | Application worker exhaustion, unthrottled API flooding, or DDoS |
            | **E - Elevation of Privilege** | Gaining unauthorized admin/root privileges | Insecure Direct Object References (IDOR) or role claim tampering |
            
            ### Risk Matrix Formula
            $$\\text{Risk Score} = \\text{Likelihood } (1\\dots5) \\times \\text{Impact } (1\\dots5)$$
            
            - 🟢 **Low (1–4):** Minimal operational impact; minor hardening recommended.
            - 🟡 **Medium (5–9):** Noticeable vulnerability; address in regular sprint backlog.
            - 🟠 **High (10–16):** Severe architectural flaw; remediation required prior to release.
            - 🔴 **Critical (17–25):** Immediate danger of catastrophic exploit or data loss; hotfix priority.
            """
        )
else:
    # --- METRIC CARDS ROW ---
    metrics = compute_threat_metrics(threats)

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-lbl">Total Threats</div>
                <div class="metric-val" style="color: #00d2ff;">{metrics['total']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-lbl">Critical Risk</div>
                <div class="metric-val" style="color: #ff3366;">{metrics['critical']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-lbl">High Risk</div>
                <div class="metric-val" style="color: #ff9100;">{metrics['high']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-lbl">Medium Risk</div>
                <div class="metric-val" style="color: #ffd600;">{metrics['medium']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c5:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-lbl">Low Risk</div>
                <div class="metric-val" style="color: #00e676;">{metrics['low']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.write("")

    # --- FILTER BAR ---
    st.subheader("🔍 Threat Register & Filters")

    fcol1, fcol2, fcol3 = st.columns([2, 2, 3])
    with fcol1:
        risk_filter = st.multiselect(
            "Filter by Risk Level",
            options=["Critical", "High", "Medium", "Low"],
            default=["Critical", "High", "Medium", "Low"],
        )
    with fcol2:
        category_filter = st.multiselect(
            "Filter by STRIDE Category",
            options=STRIDE_CATEGORIES,
            default=STRIDE_CATEGORIES,
        )
    with fcol3:
        search_query = st.text_input(
            "Keyword Search",
            placeholder="Search titles, descriptions, components, or mitigations...",
        )

    # Apply filters
    filtered_threats = []
    for t in threats:
        # Risk level match
        if risk_filter and t["risk_level"] not in risk_filter:
            continue
        # Category match
        if category_filter and t["category"] not in category_filter:
            continue
        # Search query match
        if search_query:
            query = search_query.lower()
            corpus = f"{t['title']} {t['description']} {t['component']} {t['mitigation']} {t['id']}".lower()
            if query not in corpus:
                continue
        filtered_threats.append(t)

    st.caption(f"Showing **{len(filtered_threats)}** of **{len(threats)}** total identified threats.")

    # --- TAB NAVIGATION ---
    tab_table, tab_cards, tab_viz, tab_intel, tab_export = st.tabs([
        "📋 Threat Table",
        "🗂️ Detailed Mitigation Cards",
        "📊 STRIDE Analytics & Matrix",
        "🌐 Real-World Intel (CVE / MITRE / CERT-In)",
        "📥 Export Reports",
    ])

    # 1. TAB: THREAT TABLE
    with tab_table:
        if not filtered_threats:
            st.warning("No threats match the current filter criteria. Try broadening your filter selections.")
        else:
            table_data = []
            for t in filtered_threats:
                table_data.append({
                    "ID": t["id"],
                    "STRIDE Category": t["category"],
                    "Component": t["component"],
                    "Threat Title": t["title"],
                    "Likelihood": f"{t['likelihood']}/5",
                    "Impact": f"{t['impact']}/5",
                    "Score": t["risk_score"],
                    "Risk Level": t["risk_level"],
                    "Recommended Mitigation": t["mitigation"],
                })

            df = pd.DataFrame(table_data)

            # Highlight risk levels
            def highlight_risk(val):
                color = RISK_LEVEL_COLORS.get(val, "#ffffff")
                return f"color: {color}; font-weight: bold;"

            styled_df = df.style.map(highlight_risk, subset=["Risk Level"])
            st.dataframe(styled_df, use_container_width=True, height=450)

    # 2. TAB: DETAILED MITIGATION CARDS
    with tab_cards:
        if not filtered_threats:
            st.warning("No threats match the current filter criteria.")
        else:
            for t in filtered_threats:
                level_class = f"threat-card-{t['risk_level'].lower()}"
                badge_class = f"badge-{t['risk_level'].lower()}"

                with st.expander(f"[{t['id']}] {t['title']} — {t['category']} ({t['risk_level'].upper()})", expanded=(t['risk_level'] == 'Critical')):
                    st.markdown(
                        f"""
                        <div class="threat-card {level_class}">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                <div>
                                    <strong style="color: #00d2ff; font-size: 1.05rem;">{t['title']}</strong>
                                    <span style="color: #94a3b8; font-size: 0.85rem; margin-left: 8px;">• Component: <code>{t['component']}</code></span>
                                </div>
                                <div>
                                    <span class="{badge_class}">{t['risk_level'].upper()} (Score: {t['risk_score']})</span>
                                </div>
                            </div>
                            <p style="color: #cbd5e1; margin-bottom: 12px; line-height: 1.5;">{t['description']}</p>
                            <div style="display: flex; gap: 20px; font-size: 0.85rem; color: #94a3b8; margin-bottom: 12px;">
                                <span>Likelihood: <strong style="color: #f1f5f9;">{t['likelihood']}/5</strong></span>
                                <span>Impact: <strong style="color: #f1f5f9;">{t['impact']}/5</strong></span>
                                <span>Source: <em>{t['source']}</em></span>
                            </div>
                            <div style="background: rgba(0, 210, 255, 0.05); border: 1px solid rgba(0, 210, 255, 0.2); border-radius: 6px; padding: 10px 12px;">
                                <strong style="color: #00d2ff; font-size: 0.85rem;">🛡️ Actionable Mitigation:</strong>
                                <div style="color: #e2e8f0; font-size: 0.88rem; margin-top: 4px;">{t['mitigation']}</div>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

    # 3. TAB: STRIDE ANALYTICS
    with tab_viz:
        st.subheader("📊 Architectural Risk Analytics")

        vcol1, vcol2 = st.columns(2)
        with vcol1:
            st.markdown("#### Findings by STRIDE Category")
            cat_df = pd.DataFrame(
                list(metrics["category_counts"].items()),
                columns=["STRIDE Category", "Count"]
            ).set_index("STRIDE Category")
            st.bar_chart(cat_df, color="#00d2ff", use_container_width=True)

        with vcol2:
            st.markdown("#### Findings by Risk Severity")
            risk_counts = {
                "Critical (17-25)": metrics["critical"],
                "High (10-16)": metrics["high"],
                "Medium (5-9)": metrics["medium"],
                "Low (1-4)": metrics["low"],
            }
            risk_df = pd.DataFrame(
                list(risk_counts.items()),
                columns=["Risk Severity", "Count"]
            ).set_index("Risk Severity")
            st.bar_chart(risk_df, color="#ff9100", use_container_width=True)

        st.divider()
        st.markdown("#### 5×5 Likelihood vs Impact Matrix Breakdown")
        matrix_data = []
        for t in threats:
            matrix_data.append({
                "Threat": t["title"],
                "Likelihood (1-5)": t["likelihood"],
                "Impact (1-5)": t["impact"],
                "Risk Score": t["risk_score"],
                "Risk Level": t["risk_level"],
                "Category": t["category"],
            })
        st.dataframe(pd.DataFrame(matrix_data), use_container_width=True, height=250)

    # 4. TAB: REAL-WORLD THREAT INTELLIGENCE (CVE, MITRE, NIST, CERT-In)
    with tab_intel:
        st.subheader("🌐 Real-World Threat Intelligence & Framework Mapping")
        st.caption(
            "Cross-references your technology stack with **MITRE ATT&CK®**, **NIST Cybersecurity Framework (CSF)**, "
            "**Common Vulnerabilities and Exposures (CVE/CVSS)**, and official **CERT-In / CISA** advisories."
        )

        # 1. Auto-detected technologies from user description & tech stack input
        search_corpus = st.session_state.get("combined_description", st.session_state.get("system_description", ""))
        detected_services = extract_services_from_text(search_corpus)

        # Also inspect comma/space-separated items in the tech stack field
        if st.session_state.get("tech_stack"):
            raw_items = re.split(r"[,;]+", st.session_state["tech_stack"])
            for raw_item in raw_items:
                clean_item = raw_item.strip()
                if clean_item and len(clean_item) > 1:
                    matched = lookup_service_intel(clean_item)
                    if matched and not any(d["service_name"] == matched["service_name"] for d in detected_services):
                        detected_services.append(matched)

        if detected_services:
            st.success(f"🔍 **Auto-Detected {len(detected_services)} Production System(s) & Service(s):** " +
                       ", ".join(f"**{s['service_name']}**" for s in detected_services))

            # Display each auto-detected technology in an interactive card
            for s in detected_services:
                with st.expander(f"📌 {s['service_name']} — {s['cvss_threat_level']}", expanded=True):
                    scol1, scol2 = st.columns(2)
                    with scol1:
                        st.markdown(f"**Category:** `{s['category']}`")
                        st.markdown(f"*{s['description']}*")
                        st.markdown("##### ⚔️ MITRE ATT&CK & CWE")
                        for m in s["mitre_tactics"]:
                            st.markdown(f"- `{m}`")
                        for w in s["cwe_weaknesses"]:
                            st.markdown(f"- `{w}`")
                    with scol2:
                        st.markdown("##### 🏛️ NIST CSF Controls")
                        for n in s["nist_csf_controls"]:
                            st.markdown(f"- 🛡️ {n}")
                        st.markdown("##### 🚨 CERT-In & CISA Alerts")
                        for a in s["cert_in_cisa_alerts"]:
                            st.markdown(f"""
                            <div style="background: rgba(255, 51, 102, 0.08); border-left: 3px solid #ff3366; padding: 6px 10px; border-radius: 4px; margin-bottom: 6px; font-size: 0.83rem;">
                                ⚠️ {a}
                            </div>
                            """, unsafe_allow_html=True)
                    
                    st.markdown("##### 📜 Historical CVE Record & Vulnerability Vectors")
                    cve_rows = []
                    for c in s["historical_cves"]:
                        cve_rows.append({
                            "CVE Identifier": c["cve_id"],
                            "CVSS Score": f"🔴 {c['cvss']}/10.0" if c['cvss'] >= 9.0 else f"🟠 {c['cvss']}/10.0",
                            "Summary": c["summary"],
                        })
                    st.table(pd.DataFrame(cve_rows))

                    st.markdown("##### ✅ Hardening & Mitigation Checklist")
                    for h in s["hardening_checklist"]:
                        st.markdown(f"- [ ] {h}")
        else:
            st.info("💡 You can mention specific technologies (e.g. *Windows, iOS, Android, proton.com, PostgreSQL, Twilio, Docker*) in your description or Tech Stack field to auto-correlate real-world CVEs and MITRE tactics.")

        st.divider()

        # 2. Interactive Custom Service / Domain Lookup
        st.markdown("#### 🔎 Interactive Technology & Service Lookup")
        st.caption("Type ANY service, OS, cloud provider, or VPN (e.g. `proton.com`, `iOS`, `Windows`, `PostgreSQL`, `Twilio`, `Render`) to see its complete threat profile.")

        search_query_custom = st.text_input(
            "Enter Service Name or Domain",
            placeholder="e.g. proton.com, Windows 11, iOS, Twilio, Docker, MySQL...",
            key="custom_service_search_box",
        )

        target_lookup = search_query_custom.strip() if search_query_custom.strip() else "Windows"
        intel = lookup_service_intel(target_lookup)

        if intel:
            # Service Card Header
            st.markdown(
                f"""
                <div style="background: #111a2e; border: 1px solid #1e3a5f; border-left: 6px solid #00d2ff; border-radius: 8px; padding: 18px; margin-bottom: 20px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                        <div>
                            <h3 style="color: #00d2ff; margin: 0; font-size: 1.4rem;">{intel['service_name']}</h3>
                            <span style="color: #94a3b8; font-size: 0.9rem;">Category: <code>{intel['category']}</code></span>
                        </div>
                        <div>
                            <span class="badge-critical" style="font-size: 0.85rem; padding: 6px 12px;">{intel['cvss_threat_level']}</span>
                        </div>
                    </div>
                    <p style="color: #cbd5e1; margin-top: 10px; margin-bottom: 0;">{intel['description']}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            icol1, icol2 = st.columns(2)

            with icol1:
                # MITRE ATT&CK & CWE
                st.markdown("#### ⚔️ MITRE ATT&CK® Tactics & Techniques")
                for tactic in intel["mitre_tactics"]:
                    st.markdown(f"- **`{tactic.split(' - ')[0]}`** — {tactic.split(' - ')[1]}")

                st.markdown("#### 🧩 Common Weakness Enumeration (CWE)")
                for cwe in intel["cwe_weaknesses"]:
                    st.markdown(f"- `{cwe}`")

            with icol2:
                # NIST CSF & CERT-In / CISA
                st.markdown("#### 🏛️ NIST Cybersecurity Framework (CSF)")
                for nist in intel["nist_csf_controls"]:
                    st.markdown(f"- 🛡️ **`{nist.split(': ')[0]}`**: {nist.split(': ')[1]}")

                st.markdown("#### 🚨 CERT-In & CISA Real-World Bulletins")
                for alert in intel["cert_in_cisa_alerts"]:
                    st.markdown(f"""
                    <div style="background: rgba(255, 51, 102, 0.08); border-left: 3px solid #ff3366; padding: 8px 12px; border-radius: 4px; margin-bottom: 8px; font-size: 0.85rem; color: #e2e8f0;">
                        ⚠️ {alert}
                    </div>
                    """, unsafe_allow_html=True)

            st.write("")
            st.markdown("#### 📜 Historical High-Impact CVEs & Vulnerability History")
            cve_table = []
            for c in intel["historical_cves"]:
                cve_table.append({
                    "CVE Identifier": c["cve_id"],
                    "CVSS Score": f"🔴 {c['cvss']}/10.0" if c['cvss'] >= 9.0 else f"🟠 {c['cvss']}/10.0",
                    "Exploit Summary / Attack Vector": c["summary"],
                })
            st.table(pd.DataFrame(cve_table))

            st.markdown("#### ✅ NIST-Aligned Hardening & Mitigation Checklist")
            for h in intel["hardening_checklist"]:
                st.markdown(f"- [ ] **Defensive Control:** {h}")

    # 5. TAB: EXPORT REPORTS
    with tab_export:
        st.subheader("📥 Export Security Assessment Reports")
        st.write("Download formatted artifacts for stakeholder reviews, compliance audits, or issue trackers.")

        # Generate CSV & Markdown strings
        report_corpus = st.session_state.get("combined_description", st.session_state.get("system_description", ""))
        detected_services_for_report = extract_services_from_text(report_corpus)
        if st.session_state.get("tech_stack"):
            for raw_item in re.split(r"[,;]+", st.session_state.get("tech_stack", "")):
                ci = raw_item.strip()
                if ci and len(ci) > 1:
                    m = lookup_service_intel(ci)
                    if m and not any(d["service_name"] == m["service_name"] for d in detected_services_for_report):
                        detected_services_for_report.append(m)
        csv_data = generate_csv_report(threats)
        md_data = generate_markdown_report(
            system_name=st.session_state["system_name"],
            system_description=st.session_state["system_description"],
            selected_components=st.session_state["selected_components"],
            threats=threats,
            stats=metrics,
            detected_services=detected_services_for_report,
        )

        safe_filename = st.session_state["system_name"].lower().replace(" ", "_").replace("-", "_")[:30]
        if not safe_filename:
            safe_filename = "threat_model_report"

        ecol1, ecol2 = st.columns(2)
        with ecol1:
            st.download_button(
                label="📄 Download CSV Dataset (.csv)",
                data=csv_data,
                file_name=f"{safe_filename}_threats.csv",
                mime="text/csv",
                use_container_width=True,
                help="Download structured CSV dataset for Excel or ticketing import",
            )
        with ecol2:
            st.download_button(
                label="📝 Download Markdown Report (.md)",
                data=md_data,
                file_name=f"{safe_filename}_threat_report.md",
                mime="text/markdown",
                use_container_width=True,
                help="Download complete Markdown assessment report with mitigations and disclaimer",
            )

        with st.expander("👁️ Preview Markdown Report"):
            st.markdown(md_data)

    # --- DISCLAIMER / ETHICS FOOTER ---
    st.markdown(
        """
        <div class="disclaimer-box">
            <strong>⚠️ Limitations & Human Review Disclaimer:</strong><br>
            This threat modeling tool utilizes deterministic heuristic rules and Microsoft's STRIDE framework to identify common architectural security risks. 
            <strong>It does not guarantee detection of all security vulnerabilities, zero-day flaws, or organization-specific business logic errors.</strong> 
            All automated findings must be reviewed, validated, and tested by qualified human security professionals before deploying systems to production.
        </div>
        """,
        unsafe_allow_html=True,
    )
