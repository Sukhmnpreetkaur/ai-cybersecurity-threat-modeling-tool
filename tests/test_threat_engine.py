"""
Automated Unit and Integration Tests for AI-Assisted Threat Modeling Tool.
Validates risk scoring matrices, STRIDE threat detection heuristics,
input validation, report generation, and human review disclaimers.

Compatible with both `pytest` and Python's standard `unittest` test runners.
"""

import sys
import os
import unittest

# Ensure project root is in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from risk_scoring import (
    calculate_risk_score,
    get_risk_level,
    get_risk_metadata,
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



# ==========================================
# 1. RISK SCORING ENGINE TESTS
# ==========================================

class TestRiskScoring(unittest.TestCase):
    def test_calculate_risk_score_valid_bounds(self):
        """Tests that 1x1 through 5x5 calculate correctly."""
        self.assertEqual(calculate_risk_score(1, 1), 1)
        self.assertEqual(calculate_risk_score(3, 3), 9)
        self.assertEqual(calculate_risk_score(4, 4), 16)
        self.assertEqual(calculate_risk_score(5, 5), 25)
        self.assertEqual(calculate_risk_score(2, 5), 10)

    def test_calculate_risk_score_invalid_ranges(self):
        """Tests that out-of-range inputs raise ValueError."""
        with self.assertRaises(ValueError):
            calculate_risk_score(0, 3)
        with self.assertRaises(ValueError):
            calculate_risk_score(6, 3)
        with self.assertRaises(ValueError):
            calculate_risk_score(3, 0)
        with self.assertRaises(ValueError):
            calculate_risk_score(3, 6)

    def test_calculate_risk_score_invalid_types(self):
        """Tests that non-integer inputs raise TypeError."""
        with self.assertRaises(TypeError):
            calculate_risk_score("3", 4)  # type: ignore
        with self.assertRaises(TypeError):
            calculate_risk_score(3, 4.5)  # type: ignore

    def test_risk_level_classification_low(self):
        """Scores 1-4 must classify as Low."""
        for score in [1, 2, 3, 4]:
            self.assertEqual(get_risk_level(score), "Low")

    def test_risk_level_classification_medium(self):
        """Scores 5-9 must classify as Medium."""
        for score in [5, 6, 7, 8, 9]:
            self.assertEqual(get_risk_level(score), "Medium")

    def test_risk_level_classification_high(self):
        """Scores 10-16 must classify as High."""
        for score in [10, 12, 15, 16]:
            self.assertEqual(get_risk_level(score), "High")

    def test_risk_level_classification_critical(self):
        """Scores 17-25 must classify as Critical."""
        for score in [17, 20, 24, 25]:
            self.assertEqual(get_risk_level(score), "Critical")

    def test_risk_level_out_of_bounds(self):
        """Scores outside 1-25 must raise ValueError."""
        with self.assertRaises(ValueError):
            get_risk_level(0)
        with self.assertRaises(ValueError):
            get_risk_level(26)

    def test_risk_metadata_payload(self):
        """Verifies full metadata dictionary generation."""
        meta = get_risk_metadata(4, 5)
        self.assertEqual(meta["risk_score"], 20)
        self.assertEqual(meta["risk_level"], "Critical")
        self.assertEqual(meta["color"], "#FF3366")
        self.assertEqual(meta["badge"], "CRITICAL")


# ==========================================
# 2. THREAT DETECTION ENGINE TESTS
# ==========================================

class TestThreatEngine(unittest.TestCase):
    def test_empty_system_name_raises(self):
        with self.assertRaises(ValueError) as ctx:
            analyze_threats("", "A sample description.", ["Web application"])
        self.assertIn("System name cannot be empty", str(ctx.exception))

    def test_empty_description_raises(self):
        with self.assertRaises(ValueError) as ctx:
            analyze_threats("Portal", "   ", ["Web application"])
        self.assertIn("System description cannot be empty", str(ctx.exception))

    def test_empty_components_raises(self):
        with self.assertRaises(ValueError) as ctx:
            analyze_threats("Portal", "Valid description.", [])
        self.assertIn("At least one system component", str(ctx.exception))

    def test_unsupported_component_raises(self):
        with self.assertRaises(ValueError) as ctx:
            analyze_threats("Portal", "Valid description.", ["Quantum Computer"])
        self.assertIn("Unsupported component", str(ctx.exception))

    def test_individual_components_generate_threats(self):
        """Every individual component must generate valid STRIDE findings."""
        for comp in SUPPORTED_COMPONENTS:
            threats = analyze_threats(
                system_name="Test Component System",
                system_description="Basic standard architecture setup.",
                selected_components=[comp],
            )
            self.assertGreater(len(threats), 0, f"Component {comp} produced no threats.")
            for t in threats:
                self.assertIn(t["category"], STRIDE_CATEGORIES)
                self.assertTrue(1 <= t["likelihood"] <= 5)
                self.assertTrue(1 <= t["impact"] <= 5)
                self.assertTrue(1 <= t["risk_score"] <= 25)
                self.assertIn(t["risk_level"], ["Low", "Medium", "High", "Critical"])
                self.assertGreater(len(t["mitigation"]), 10)

    def test_stride_category_completeness_all_components(self):
        """Selecting all components must produce threats across all 6 STRIDE categories."""
        threats = analyze_threats(
            system_name="Full Architecture",
            system_description="Production system with web, api, db, auth, storage, and networking.",
            selected_components=SUPPORTED_COMPONENTS,
        )
        found_categories = {t["category"] for t in threats}
        for expected_cat in STRIDE_CATEGORIES:
            self.assertIn(expected_cat, found_categories, f"STRIDE category '{expected_cat}' was missing.")

    def test_heuristic_triggers_file_upload(self):
        """Description with 'upload' should trigger malicious file execution threat."""
        threats = analyze_threats(
            system_name="Assignment Submitter",
            system_description="Students can upload coursework in PDF format to professors.",
            selected_components=["File storage"],
        )
        threat_ids = [t["id"] for t in threats]
        has_upload = "CTX-T-UPLOAD" in threat_ids or any("upload" in t["title"].lower() for t in threats)
        self.assertTrue(has_upload)

    def test_heuristic_triggers_ssn_pii(self):
        """Description with 'ssn' should elevate risk and add high-impact PII finding."""
        threats = analyze_threats(
            system_name="Registrar DB",
            system_description="Stores student personal records and SSN numbers.",
            selected_components=["Database"],
        )
        threat_ids = [t["id"] for t in threats]
        self.assertIn("CTX-I-PII", threat_ids)

    def test_sample_college_portal_analysis(self):
        """Validates execution on the provided fictional college portal sample scenario."""
        threats = analyze_threats(
            system_name=SAMPLE_COLLEGE_PORTAL["system_name"],
            system_description=SAMPLE_COLLEGE_PORTAL["system_description"],
            selected_components=SAMPLE_COLLEGE_PORTAL["selected_components"],
        )
        self.assertGreaterEqual(len(threats), 20)
        metrics = compute_threat_metrics(threats)
        self.assertEqual(metrics["total"], len(threats))
        self.assertGreater(metrics["critical"], 0)
        self.assertGreater(metrics["high"], 0)
        # Check all STRIDE categories exist in metrics
        for cat in STRIDE_CATEGORIES:
            self.assertGreater(metrics["category_counts"][cat], 0)


# ==========================================
# 3. REPORT GENERATION TESTS
# ==========================================

class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.sample_findings = analyze_threats(
            system_name="Test College System",
            system_description="A web portal with database and file uploads for student transcripts.",
            selected_components=["Web application", "Database", "File storage"],
        )

    def test_csv_report_generation(self):
        csv_text = generate_csv_report(self.sample_findings)
        self.assertIn("Threat ID,STRIDE Category,Target Component", csv_text)
        self.assertIn("Web application", csv_text)
        self.assertGreater(len(csv_text.splitlines()), 5)

    def test_markdown_report_generation(self):
        metrics = compute_threat_metrics(self.sample_findings)
        md_text = generate_markdown_report(
            system_name="Test College System",
            system_description="A web portal with database and file uploads for student transcripts.",
            selected_components=["Web application", "Database", "File storage"],
            threats=self.sample_findings,
            stats=metrics,
        )
        self.assertIn("# Threat Modeling Security Assessment Report", md_text)
        self.assertIn("Test College System", md_text)
        self.assertIn("## 1. Executive Summary", md_text)
        self.assertIn("## 3. STRIDE Threat Distribution", md_text)
        self.assertIn("## 5. Limitations & Human Review Disclaimer", md_text)
        # Must emphasize human review and not guarantee 100% detection
        self.assertIn("Human Review Required", md_text)
        self.assertIn("does not and cannot guarantee detection of all security vulnerabilities", md_text)


# ==========================================
# 4. REAL-WORLD THREAT INTEL TESTS (CVE/MITRE/NIST/CERT-In)
# ==========================================

class TestThreatIntel(unittest.TestCase):
    def test_lookup_known_service_postgresql(self):
        intel = lookup_service_intel("PostgreSQL")
        self.assertIsNotNone(intel)
        self.assertEqual(intel["category"], "Database")
        self.assertTrue(len(intel["historical_cves"]) > 0)
        self.assertTrue(any("CWE-89" in c for c in intel["cwe_weaknesses"]))
        self.assertTrue(any("CIVN" in a for a in intel["cert_in_cisa_alerts"]))

    def test_lookup_service_aliases(self):
        self.assertEqual(lookup_service_intel("postgres")["service_name"], "PostgreSQL Database Server")
        self.assertEqual(lookup_service_intel("k8s")["service_name"], "Kubernetes (K8s) Orchestration Platform")
        self.assertEqual(lookup_service_intel("s3")["service_name"], "AWS S3 / Cloud Object Storage")

    def test_lookup_empty_query_returns_none(self):
        self.assertIsNone(lookup_service_intel(""))
        self.assertIsNone(lookup_service_intel("   "))

    def test_lookup_custom_service_synthesizes_profile(self):
        custom = lookup_service_intel("my-custom-service.internal")
        self.assertIsNotNone(custom)
        self.assertIn("my-custom-service.internal", custom["service_name"])
        self.assertTrue(len(custom["mitre_tactics"]) > 0)
        self.assertTrue(len(custom["nist_csf_controls"]) > 0)

    def test_lookup_proton_vpn(self):
        proton = lookup_service_intel("proton.com")
        self.assertIsNotNone(proton)
        self.assertIn("Proton", proton["service_name"])
        self.assertTrue(any("Kill Switch" in h for h in proton["hardening_checklist"]))

    def test_lookup_os_windows_and_ios(self):
        win = lookup_service_intel("Windows")
        self.assertIsNotNone(win)
        self.assertTrue(any("PrintNightmare" in str(c) for c in win["historical_cves"]))

        ios = lookup_service_intel("iOS")
        self.assertIsNotNone(ios)
        self.assertTrue(any("BLASTPASS" in str(a) for a in ios["cert_in_cisa_alerts"]))


    def test_extract_services_from_text(self):
        desc = "A web platform running on Docker containers connected to a PostgreSQL database and AWS S3 storage."
        extracted = extract_services_from_text(desc)
        service_names = [s["service_name"] for s in extracted]
        self.assertTrue(any("PostgreSQL" in s for s in service_names))
        self.assertTrue(any("Docker" in s for s in service_names))
        self.assertTrue(any("AWS S3" in s for s in service_names))

    def test_lookup_twilio_and_render(self):
        twilio_intel = lookup_service_intel("Twilio")
        self.assertIsNotNone(twilio_intel)
        self.assertIn("SMS/2FA", twilio_intel["service_name"])
        self.assertTrue(any("Toll Fraud" in t for t in twilio_intel["mitre_tactics"]))

        render_intel = lookup_service_intel("Render")
        self.assertIsNotNone(render_intel)
        self.assertIn("Render Cloud", render_intel["service_name"])
        self.assertTrue(any("sslmode=require" in h for h in render_intel["hardening_checklist"]))



if __name__ == "__main__":
    unittest.main()
