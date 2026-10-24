"""
Threat Detection Engine for AI-Assisted Threat Modeling Tool.
Implements the Microsoft STRIDE framework using transparent, deterministic,
rule-based heuristics without requiring paid external AI APIs.
"""

import re
from typing import List, Dict, Any, Tuple
from risk_scoring import calculate_risk_score, get_risk_level


def is_keyword_present_and_not_negated(kw: str, text: str) -> bool:
    """
    Checks if a keyword exists in text as a whole word or common plural,
    ensuring it is not preceded by negation terms (e.g., 'no', 'zero', 'without').
    """
    pattern = rf"\b{re.escape(kw)}s?\b"
    negations = {
        "no",
        "zero",
        "without",
        "not",
        "never",
        "none",
        "neither",
        "disallow",
        "disallows",
        "lacks",
        "exclude",
        "excludes",
    }
    for match in re.finditer(pattern, text):
        start = match.start()
        preceding = text[max(0, start - 35) : start].strip()
        words = [w.strip(".,;:()\"'") for w in preceding.split()]
        if any(w.lower() in negations for w in words[-3:]):
            continue  # Negated in context (e.g., 'zero internet', 'no public')
        return True
    return False



# STRIDE Framework Categories
STRIDE_CATEGORIES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
]

# Supported system components
SUPPORTED_COMPONENTS = [
    "Web application",
    "Database",
    "API",
    "Authentication system",
    "File storage",
    "Network",
]

# Baseline Component Threat Knowledge Base (Rules)
COMPONENT_RULES: Dict[str, List[Dict[str, Any]]] = {
    "Web application": [
        {
            "id": "WEB-S-01",
            "title": "Session Hijacking & Cookie Theft",
            "category": "Spoofing",
            "component": "Web application",
            "description": "Attackers can intercept or steal session tokens via cross-site scripting (XSS) or unencrypted communication, allowing them to impersonate legitimate users.",
            "base_likelihood": 3,
            "base_impact": 4,
            "mitigation": "Set Secure, HttpOnly, and SameSite=Strict/Lax flags on session cookies. Implement strict Content Security Policy (CSP) and rotate session IDs upon authentication.",
        },
        {
            "id": "WEB-T-01",
            "title": "Cross-Site Scripting (XSS) & Data Tampering",
            "category": "Tampering",
            "component": "Web application",
            "description": "Unsanitized user inputs rendered into web pages allow malicious script execution in victim browsers, leading to DOM manipulation, keystroke logging, or content alteration.",
            "base_likelihood": 4,
            "base_impact": 3,
            "mitigation": "Apply context-aware output encoding (HTML, JavaScript, CSS contexts) and enforce input validation using a strict whitelist. Use modern frontend frameworks that automatically escape output.",
        },
        {
            "id": "WEB-R-01",
            "title": "Insufficient User Action Logging",
            "category": "Repudiation",
            "component": "Web application",
            "description": "Lack of immutable audit logs for critical application operations (e.g., records changes, profile updates) allows users to deny performing actions.",
            "base_likelihood": 3,
            "base_impact": 2,
            "mitigation": "Maintain centralized, append-only application logs capturing timestamp, user ID, IP address, and operation details with cryptographic hash chaining or remote log shipping.",
        },
        {
            "id": "WEB-I-01",
            "title": "Verbose Error Messages & Information Leakage",
            "category": "Information Disclosure",
            "component": "Web application",
            "description": "Stack traces, server banners, and database diagnostic messages displayed in browser responses reveal underlying architecture, software versions, and internal paths.",
            "base_likelihood": 4,
            "base_impact": 2,
            "mitigation": "Implement global custom error handling that returns generic messages to clients while logging detailed diagnostics only to secure internal logging sinks.",
        },
        {
            "id": "WEB-D-01",
            "title": "Application-Layer Resource Exhaustion",
            "category": "Denial of Service",
            "component": "Web application",
            "description": "Heavy compute operations (e.g., uncontrolled file compression, regex evaluation, or large report exports) can be triggered repeatedly to tie up worker processes.",
            "base_likelihood": 3,
            "base_impact": 3,
            "mitigation": "Offload long-running tasks to asynchronous background job queues (e.g., Celery/Redis). Enforce request timeouts, pagination, and concurrency limits per user/IP.",
        },
        {
            "id": "WEB-E-01",
            "title": "Insecure Direct Object Reference (IDOR)",
            "category": "Elevation of Privilege",
            "component": "Web application",
            "description": "Flawed access control where URLs or parameters expose database primary keys or filenames without verifying whether the requesting user is authorized.",
            "base_likelihood": 4,
            "base_impact": 4,
            "mitigation": "Validate authorization checks on the server-side for every single request using role-based or attribute-based access controls (RBAC/ABAC). Use indirect references (UUIDs).",
        },
    ],
    "Database": [
        {
            "id": "DB-T-01",
            "title": "SQL / Query Injection",
            "category": "Tampering",
            "component": "Database",
            "description": "Unsanitized user data concatenated into database queries allows attackers to execute arbitrary SQL commands, altering or wiping critical tables.",
            "base_likelihood": 4,
            "base_impact": 5,
            "mitigation": "Use parameterized queries (prepared statements) or Object-Relational Mappers (ORM) exclusively. Never concatenate dynamic raw strings into database queries.",
        },
        {
            "id": "DB-I-01",
            "title": "Unencrypted Data-at-Rest Exposure",
            "category": "Information Disclosure",
            "component": "Database",
            "description": "Sensitive records, passwords, or PII stored unencrypted on disk can be exposed if physical media, backup snapshots, or raw database files are leaked.",
            "base_likelihood": 2,
            "base_impact": 5,
            "mitigation": "Enable Transparent Data Encryption (TDE) or volume-level encryption (e.g., AES-256). Apply application-level field encryption for highly sensitive attributes (SSNs, secrets).",
        },
        {
            "id": "DB-E-01",
            "title": "Excessive Database User Privileges",
            "category": "Elevation of Privilege",
            "component": "Database",
            "description": "Application database accounts running with DBA, SUPERUSER, or DROP permissions allow compromised application threads to gain full database control.",
            "base_likelihood": 3,
            "base_impact": 4,
            "mitigation": "Adhere strictly to the Principle of Least Privilege: grant only SELECT, INSERT, UPDATE, DELETE permissions on specific tables needed by the application service account.",
        },
        {
            "id": "DB-D-01",
            "title": "Connection Pool Exhaustion & Query Starvation",
            "category": "Denial of Service",
            "component": "Database",
            "description": "Unindexed slow queries or unbounded query concurrency exhaust available database connection pools, causing total service outages for all incoming users.",
            "base_likelihood": 3,
            "base_impact": 4,
            "mitigation": "Configure strict database connection pool limits, query statement timeouts, database read replicas, and comprehensive query profiling on foreign keys and search columns.",
        },
        {
            "id": "DB-S-01",
            "title": "Database Credential Forgery & Weak Authentication",
            "category": "Spoofing",
            "component": "Database",
            "description": "Hardcoded or default database passwords allow rogue internal hosts to impersonate legitimate backend services and directly query data stores.",
            "base_likelihood": 2,
            "base_impact": 5,
            "mitigation": "Employ dedicated Secrets Managers (e.g., HashiCorp Vault, AWS Secrets Manager) with automated credential rotation and mutual TLS (mTLS) for database client authentication.",
        },
        {
            "id": "DB-R-01",
            "title": "Lack of Data Modification Auditing",
            "category": "Repudiation",
            "component": "Database",
            "description": "Without database change-data-capture or audit tables, administrators or compromised accounts can alter sensitive rows without leaving evidence.",
            "base_likelihood": 3,
            "base_impact": 3,
            "mitigation": "Enable database audit extensions (e.g., pgAudit or SQL Server Audit) and forward transaction logs to an immutable write-once read-many (WORM) storage archive.",
        },
    ],
    "API": [
        {
            "id": "API-S-01",
            "title": "API Token Forgery / Broken Object Level Auth",
            "category": "Spoofing",
            "component": "API",
            "description": "Improperly validated JWT tokens, weak signing algorithms ('none' alg), or shared API keys permit attackers to forge credentials and impersonate clients.",
            "base_likelihood": 3,
            "base_impact": 4,
            "mitigation": "Validate JWT signatures using robust asymmetric keys (RS256/ES256), enforce token expiration times, and implement strict client token binding.",
        },
        {
            "id": "API-D-01",
            "title": "API Rate Limit Bypass & Endpoint Flooding",
            "category": "Denial of Service",
            "component": "API",
            "description": "Endpoints lacking throttling allow automated scripts to trigger expensive computational workflows, causing server latency or downtime.",
            "base_likelihood": 4,
            "base_impact": 3,
            "mitigation": "Deploy an API Gateway with Token Bucket or Leaky Bucket rate limiting per IP, API key, and authenticated user ID. Add Cloudflare/WAF DDoS protection.",
        },
        {
            "id": "API-T-01",
            "title": "Mass Assignment / Parameter Tampering",
            "category": "Tampering",
            "component": "API",
            "description": "API endpoints blindly mapping incoming JSON payloads to backend object models allow attackers to overwrite protected fields (e.g., 'is_admin': true).",
            "base_likelihood": 3,
            "base_impact": 4,
            "mitigation": "Define explicit Data Transfer Objects (DTOs) with strict input whitelisting. Never bind client payloads directly to database entity models.",
        },
        {
            "id": "API-I-01",
            "title": "Excessive Data Exposure in API Payloads",
            "category": "Information Disclosure",
            "component": "API",
            "description": "APIs returning full internal objects and relying on client-side frontend code to filter sensitive fields expose confidential metadata to network inspectors.",
            "base_likelihood": 4,
            "base_impact": 3,
            "mitigation": "Implement strict response serialization schemas that only serialize the exact fields required by the user's role and view.",
        },
        {
            "id": "API-E-01",
            "title": "Broken Function Level Authorization (BFLA)",
            "category": "Elevation of Privilege",
            "component": "API",
            "description": "Administrative API endpoints (e.g., /api/admin/users) accessible by changing HTTP verbs or request paths without server-side permission checks.",
            "base_likelihood": 3,
            "base_impact": 5,
            "mitigation": "Enforce explicit endpoint route middleware verifying user roles and granular permissions prior to controller execution.",
        },
        {
            "id": "API-R-01",
            "title": "Unlogged API Calls & Traceability Gaps",
            "category": "Repudiation",
            "component": "API",
            "description": "State-altering REST or GraphQL mutations execute without persistent request correlation IDs, preventing traceability of malicious transactions.",
            "base_likelihood": 2,
            "base_impact": 3,
            "mitigation": "Assign unique X-Request-ID headers across all API gateways and services, logging every mutating HTTP request with authenticated client context.",
        },
    ],
    "Authentication system": [
        {
            "id": "AUTH-S-01",
            "title": "Credential Stuffing & Brute Force Attacks",
            "category": "Spoofing",
            "component": "Authentication system",
            "description": "Automated tools attempt lists of leaked credentials against login endpoints, leading to account takeovers if no throttling or lockout exists.",
            "base_likelihood": 4,
            "base_impact": 4,
            "mitigation": "Enforce Multi-Factor Authentication (MFA/TOTP/FIDO2). Implement progressive account lockouts, CAPTCHAs, and risk-based adaptive authentication.",
        },
        {
            "id": "AUTH-I-01",
            "title": "Weak Password Hashing & Salt Omission",
            "category": "Information Disclosure",
            "component": "Authentication system",
            "description": "Using outdated hash functions (MD5, SHA-1, plain SHA-256) enables rapid offline password cracking via rainbow tables if hashes are dumped.",
            "base_likelihood": 2,
            "base_impact": 5,
            "mitigation": "Use memory-hard adaptive hashing algorithms such as Argon2id or bcrypt with high work factors and unique cryptographic salts per password.",
        },
        {
            "id": "AUTH-E-01",
            "title": "Privilege Escalation via Role Parameter Manipulation",
            "category": "Elevation of Privilege",
            "component": "Authentication system",
            "description": "Improperly verified user role tokens or cookie session parameters allow normal users to inject administrative privileges into their active session.",
            "base_likelihood": 3,
            "base_impact": 5,
            "mitigation": "Store and verify role memberships strictly in server-side session stores or cryptographically signed and encrypted claims (HMAC-SHA256 / RSA).",
        },
        {
            "id": "AUTH-D-01",
            "title": "Account Lockout Denial of Service Abuse",
            "category": "Denial of Service",
            "component": "Authentication system",
            "description": "Attackers deliberately send multiple incorrect passwords for known executive or staff usernames, locking legitimate users out of the system.",
            "base_likelihood": 3,
            "base_impact": 3,
            "mitigation": "Use IP-based rate limiting instead of permanent account lockouts. Provide self-service secure unlocking via verified email/SMS magic links.",
        },
        {
            "id": "AUTH-T-01",
            "title": "Password Reset Token Tampering",
            "category": "Tampering",
            "component": "Authentication system",
            "description": "Predictable, persistent, or unencrypted password reset tokens can be intercepted or guessed to hijack user passwords without authorization.",
            "base_likelihood": 2,
            "base_impact": 5,
            "mitigation": "Generate cryptographically secure random reset tokens (e.g., secrets.token_urlsafe). Enforce strict 15-minute expirations and one-time use invalidation.",
        },
        {
            "id": "AUTH-R-01",
            "title": "Unrecorded Authentication Failures & Security Events",
            "category": "Repudiation",
            "component": "Authentication system",
            "description": "Failed login attempts, password changes, and MFA resets are not logged, leaving security teams blind to active attacks and unable to trace compromised accounts.",
            "base_likelihood": 3,
            "base_impact": 3,
            "mitigation": "Log all authentication lifecycle events (success, failure, password reset, MFA challenge) to a SIEM with client IP, user agent, and timestamp.",
        },
    ],
    "File storage": [
        {
            "id": "FILE-T-01",
            "title": "Unrestricted Malicious File Upload (Web Shells / Malware)",
            "category": "Tampering",
            "component": "File storage",
            "description": "Allowing arbitrary files without MIME-type and extension validation allows attackers to upload executable scripts (.php, .jsp, .exe, HTML with embedded JavaScript).",
            "base_likelihood": 4,
            "base_impact": 5,
            "mitigation": "Enforce strict extension and magic-number byte inspection. Store uploaded files in an isolated object storage bucket outside the webroot without execute permissions.",
        },
        {
            "id": "FILE-I-01",
            "title": "Publicly Accessible Storage Buckets / Insecure Direct Access",
            "category": "Information Disclosure",
            "component": "File storage",
            "description": "Misconfigured storage permissions allow unauthenticated internet users to browse or download stored student documents, submissions, or private data.",
            "base_likelihood": 3,
            "base_impact": 4,
            "mitigation": "Disable public read access on storage directories/buckets. Serve files strictly through time-limited signed URLs or backend authentication proxies.",
        },
        {
            "id": "FILE-D-01",
            "title": "Storage Exhaustion & Disk Flood",
            "category": "Denial of Service",
            "component": "File storage",
            "description": "Lack of file size quotas or rate limits on upload endpoints allows bad actors to upload gigabytes of junk files, filling server disks and causing crashes.",
            "base_likelihood": 3,
            "base_impact": 3,
            "mitigation": "Enforce maximum file upload size limits (e.g., 10MB per file) and per-user storage quotas at the web server and application layers.",
        },
        {
            "id": "FILE-E-01",
            "title": "Directory Traversal via File Paths (Zip Slip / Path Traversal)",
            "category": "Elevation of Privilege",
            "component": "File storage",
            "description": "Using client-supplied filenames containing path traversal sequences ('../' or absolute paths) allows writing or reading files outside the designated upload directory.",
            "base_likelihood": 3,
            "base_impact": 4,
            "mitigation": "Sanitize filenames using secure filename utilities. Generate random UUIDs for stored filenames on disk and keep user-facing names only as database metadata.",
        },
        {
            "id": "FILE-S-01",
            "title": "File Author & Origin Spoofing",
            "category": "Spoofing",
            "component": "File storage",
            "description": "Absence of cryptographic checksums or digital signatures allows an attacker to replace submitted coursework or documents with falsified content.",
            "base_likelihood": 2,
            "base_impact": 3,
            "mitigation": "Compute and store SHA-256 hashes upon file receipt. Bind the hash and uploader identity immutably in the database record.",
        },
        {
            "id": "FILE-R-01",
            "title": "Unlogged Document Access & Deletion",
            "category": "Repudiation",
            "component": "File storage",
            "description": "Users can download, overwrite, or delete sensitive academic files and later deny doing so because file access logs are omitted.",
            "base_likelihood": 3,
            "base_impact": 2,
            "mitigation": "Implement cloud storage access logging (e.g., S3 server access logs) tracking download, overwrite, and delete operations.",
        },
    ],
    "Network": [
        {
            "id": "NET-I-01",
            "title": "Man-in-the-Middle (MitM) & Cleartext Interception",
            "category": "Information Disclosure",
            "component": "Network",
            "description": "Transmitting network traffic over unencrypted channels (HTTP, plain FTP, Telnet) permits eavesdropping on passwords, transcripts, and session tokens.",
            "base_likelihood": 4,
            "base_impact": 4,
            "mitigation": "Enforce TLS 1.3 across all endpoints. Implement HTTP Strict Transport Security (HSTS) with long max-age and includeSubDomains directives.",
        },
        {
            "id": "NET-D-01",
            "title": "Network Perimeter Denial of Service (SYN / UDP Flood)",
            "category": "Denial of Service",
            "component": "Network",
            "description": "Volumetric network attacks saturate campus bandwidth or firewall state tables, cutting off legitimate access to all hosted services.",
            "base_likelihood": 3,
            "base_impact": 4,
            "mitigation": "Use managed DDoS mitigation services (e.g., Cloudflare, AWS Shield) and upstream ISP scrubbing centers. Configure stateful firewall rate-limiting.",
        },
        {
            "id": "NET-S-01",
            "title": "DNS & ARP Spoofing on Shared Campus Network",
            "category": "Spoofing",
            "component": "Network",
            "description": "Adversaries on the same local subnet can broadcast fraudulent ARP replies or spoof internal DNS queries to reroute traffic to attacker-controlled proxies.",
            "base_likelihood": 3,
            "base_impact": 4,
            "mitigation": "Deploy Dynamic ARP Inspection (DAI), DHCP Snooping, and DNSSEC on network switches. Isolate student and administrative traffic into separated VLANs.",
        },
        {
            "id": "NET-E-01",
            "title": "Lateral Movement via Flat Network Architecture",
            "category": "Elevation of Privilege",
            "component": "Network",
            "description": "Lack of network segmentation between public student Wi-Fi and core administrative servers enables compromised endpoints to pivot into restricted networks.",
            "base_likelihood": 3,
            "base_impact": 5,
            "mitigation": "Segment networks into strict security zones using firewalls and Zero-Trust Network Access (ZTNA). Disallow direct routing between student Wi-Fi and server VLANs.",
        },
        {
            "id": "NET-T-01",
            "title": "Packet Injection & Route Hijacking",
            "category": "Tampering",
            "component": "Network",
            "description": "Unauthenticated network routing protocols or lack of packet integrity verification allows malicious nodes to inject rogue route advertisements.",
            "base_likelihood": 2,
            "base_impact": 4,
            "mitigation": "Enable BGP route filtering with RPKI, OSPF authentication, and MACsec where physical transmission lines traverse untrusted premises.",
        },
        {
            "id": "NET-R-01",
            "title": "Incomplete Network Flow (NetFlow/IPFIX) Retention",
            "category": "Repudiation",
            "component": "Network",
            "description": "Inability to correlate IP traffic during post-incident investigations due to short retention windows or disabled firewall session logging.",
            "base_likelihood": 3,
            "base_impact": 2,
            "mitigation": "Retain firewall connection logs and NetFlow data in an encrypted centralized SIEM repository for at least 90 to 180 days.",
        },
    ],
}

# Heuristic Keyword Trigger Catalog for System Descriptions
KEYWORD_HEURISTICS: List[Dict[str, Any]] = [
    {
        "keywords": ["cookie", "cookies", "legacy session", "session cookie"],
        "trigger_threat_id": "CTX-S-COOKIE",
        "title": "Session Fixation & Insecure Cookie Handling",
        "category": "Spoofing",
        "component": "Authentication system",
        "likelihood_delta": 1,
        "impact_delta": 0,
        "description": "The system mentions legacy session cookies. Legacy cookie implementations often lack modern HttpOnly, Secure, and SameSite flags, making sessions vulnerable to cookie tossing and client-side extraction.",
        "mitigation": "Migrate from legacy cookies to modern cryptographically signed, short-lived session identifiers with Secure, HttpOnly, and SameSite=Strict attributes.",
    },
    {
        "keywords": ["ssn", "social security", "transcript", "student record", "gradebook", "grades", "pii"],
        "trigger_threat_id": "CTX-I-PII",
        "title": "High-Impact Sensitive Academic & PII Data Exposure",
        "category": "Information Disclosure",
        "component": "Database",
        "likelihood_delta": 1,
        "impact_delta": 2,
        "description": "The system handles highly sensitive data (SSNs, academic transcripts, student gradebooks). A data disclosure here constitutes a severe regulatory violation (e.g., FERPA, GDPR) with catastrophic reputational consequences.",
        "mitigation": "Apply end-to-end field encryption for SSNs and grades. Mask data in non-production environments and implement rigorous database access monitoring.",
    },
    {
        "keywords": ["upload", "uploads", "pdf", "file upload", "coursework", "assignment"],
        "trigger_threat_id": "CTX-T-UPLOAD",
        "title": "Malicious PDF / Document Payload Execution",
        "category": "Tampering",
        "component": "File storage",
        "likelihood_delta": 1,
        "impact_delta": 1,
        "description": "The description indicates coursework or PDF uploads. Attackers frequently embed malicious JavaScript, PDF exploit payloads, or polyglot files into document submissions.",
        "mitigation": "Pass all uploaded documents through an automated antivirus/sandboxed malware scanner (e.g., ClamAV). Re-encode or sanitize PDFs to strip active JavaScript payloads before storage.",
    },
    {
        "keywords": ["payment", "gateway", "credit card", "tuition", "fee"],
        "trigger_threat_id": "CTX-T-PAYMENT",
        "title": "Third-Party Payment Callback Manipulation & Webhook Forgery",
        "category": "Tampering",
        "component": "API",
        "likelihood_delta": 1,
        "impact_delta": 2,
        "description": "Integration with external payment systems opens risks of spoofed payment confirmation webhooks or manipulated transaction parameters (e.g., changing fee amounts).",
        "mitigation": "Verify cryptographic HMAC signatures on all payment gateway webhooks. Always confirm payment status by initiating an outbound server-to-server inquiry to the processor before updating student accounts.",
    },
    {
        "keywords": ["public", "public-facing", "portal", "internet"],
        "trigger_threat_id": "CTX-D-PUBLIC",
        "title": "Internet-Facing Automated Brute Force & DoS Exposure",
        "category": "Denial of Service",
        "component": "Web application",
        "likelihood_delta": 1,
        "impact_delta": 0,
        "description": "Because the system is publicly exposed to the internet, it is subject to continuous reconnaissance, automated vulnerability scanning, and botnet-driven denial-of-service attempts.",
        "mitigation": "Implement edge Web Application Firewall (WAF) filtering, bot management, and geo-blocking/rate-limiting to deflect unauthenticated scrapers.",
    },
    {
        "keywords": ["admin", "gradebook", "administrative", "staff"],
        "trigger_threat_id": "CTX-E-ADMIN",
        "title": "Administrative Gradebook Privilege Tampering",
        "category": "Elevation of Privilege",
        "component": "Web application",
        "likelihood_delta": 1,
        "impact_delta": 1,
        "description": "The presence of administrative gradebook features creates a high-value target for students or malicious insiders seeking unauthorized grade alterations.",
        "mitigation": "Enforce mandatory Multi-Factor Authentication (MFA) for administrative roles, dual-authorization (four-eyes principle) for grade changes, and real-time alerts on anomalous grade updates.",
    },
    {
        "keywords": ["unencrypted", "plaintext", "http:", "cleartext"],
        "trigger_threat_id": "CTX-I-CLEARTEXT",
        "title": "Cleartext Communication Channel Eavesdropping",
        "category": "Information Disclosure",
        "component": "Network",
        "likelihood_delta": 2,
        "impact_delta": 2,
        "description": "Cleartext or unencrypted protocols detected in the system description expose all transmitted passwords, session tokens, and data to any network observer.",
        "mitigation": "Eliminate all unencrypted HTTP/FTP connections immediately. Upgrade all listeners to enforce TLS 1.3 encryption with strict cipher suites.",
    },
]

# Sample College Portal Demonstration Data
SAMPLE_COLLEGE_PORTAL = {
    "system_name": "Oakwood State University - Student & Faculty Portal",
    "system_description": (
        "A public-facing university web portal allowing 25,000 students and staff to view academic transcripts, "
        "submit coursework assignments via PDF file uploads, pay tuition fees through an external payment gateway, "
        "and access administrative gradebooks using legacy session cookies. "
        "The backend database stores student personal records, SSNs, and faculty credentials, "
        "connected over a campus intranet."
    ),
    "selected_components": [
        "Web application",
        "Database",
        "API",
        "Authentication system",
        "File storage",
        "Network",
    ],
}


def analyze_threats(
    system_name: str,
    system_description: str,
    selected_components: List[str],
) -> List[Dict[str, Any]]:
    """
    Analyzes a system description and selected architectural components to generate
    a comprehensive STRIDE threat register using deterministic rule-based heuristics.

    Args:
        system_name: Name of the system/project under review.
        system_description: Architectural and functional description text.
        selected_components: List of system component strings.

    Returns:
        List of enriched threat dictionaries with calculated risk scores and mitigations.

    Raises:
        ValueError: If system_name is empty, description is empty, or components list is empty.
    """
    # Input validation
    if not system_name or not system_name.strip():
        raise ValueError("System name cannot be empty.")

    if not system_description or not system_description.strip():
        raise ValueError("System description cannot be empty. Please provide architectural details.")

    if not selected_components or len(selected_components) == 0:
        raise ValueError("At least one system component must be selected for threat analysis.")

    # Validate component names
    for comp in selected_components:
        if comp not in SUPPORTED_COMPONENTS:
            raise ValueError(f"Unsupported component '{comp}'. Supported: {SUPPORTED_COMPONENTS}")

    desc_lower = system_description.lower()
    threats: List[Dict[str, Any]] = []
    seen_threat_ids = set()

    # Step 1: Evaluate baseline rules for all selected components
    for comp in selected_components:
        rules = COMPONENT_RULES.get(comp, [])
        for rule in rules:
            rule_id = rule["id"]
            if rule_id in seen_threat_ids:
                continue

            likelihood = rule["base_likelihood"]
            impact = rule["base_impact"]

            # Dynamic contextual elevation: check if description mentions high-risk words
            # that exacerbate this specific component rule (and are not negated)
            if comp == "Database" and any(is_keyword_present_and_not_negated(k, desc_lower) for k in ["ssn", "records", "credentials", "database"]):
                impact = min(5, impact + 1)

            if comp == "Web application" and is_keyword_present_and_not_negated("public", desc_lower) and rule["category"] == "Denial of Service":
                likelihood = min(5, likelihood + 1)

            if comp == "Authentication system" and is_keyword_present_and_not_negated("cookie", desc_lower) and rule["category"] == "Spoofing":
                likelihood = min(5, likelihood + 1)

            risk_score = calculate_risk_score(likelihood, impact)
            risk_level = get_risk_level(risk_score)

            threats.append({
                "id": rule_id,
                "title": rule["title"],
                "category": rule["category"],
                "component": comp,
                "description": rule["description"],
                "likelihood": likelihood,
                "impact": impact,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "mitigation": rule["mitigation"],
                "source": "Component Baseline Rule",
            })
            seen_threat_ids.add(rule_id)

    # Step 2: Evaluate Contextual Heuristics from system description text
    for heuristic in KEYWORD_HEURISTICS:
        # Match only keywords that are not negated by words like 'no', 'zero', 'without'
        matched_keywords = [
            kw for kw in heuristic["keywords"]
            if is_keyword_present_and_not_negated(kw, desc_lower)
        ]
        if matched_keywords:
            heuristic_id = heuristic["trigger_threat_id"]
            if heuristic_id in seen_threat_ids:
                continue

            # Only trigger heuristic if the associated component is in scope
            comp = heuristic["component"]
            if comp not in selected_components:
                continue

            base_l = 3 + heuristic["likelihood_delta"]
            base_i = 3 + heuristic["impact_delta"]
            likelihood = max(1, min(5, base_l))
            impact = max(1, min(5, base_i))

            risk_score = calculate_risk_score(likelihood, impact)
            risk_level = get_risk_level(risk_score)

            matched_str = ", ".join(f"'{k}'" for k in matched_keywords)
            enhanced_desc = f"{heuristic['description']} (Triggered by contextual keywords: {matched_str})"

            threats.append({
                "id": heuristic_id,
                "title": heuristic["title"],
                "category": heuristic["category"],
                "component": comp,
                "description": enhanced_desc,
                "likelihood": likelihood,
                "impact": impact,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "mitigation": heuristic["mitigation"],
                "source": "Contextual Description Heuristic",
            })
            seen_threat_ids.add(heuristic_id)

    # Sort threats descending by risk score (most dangerous first)
    threats.sort(key=lambda t: t["risk_score"], reverse=True)
    return threats


def compute_threat_metrics(threats: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes summary metrics for threat dashboard display.
    """
    total = len(threats)
    critical = sum(1 for t in threats if t["risk_level"] == "Critical")
    high = sum(1 for t in threats if t["risk_level"] == "High")
    medium = sum(1 for t in threats if t["risk_level"] == "Medium")
    low = sum(1 for t in threats if t["risk_level"] == "Low")

    # Category breakdown
    category_counts = {cat: 0 for cat in STRIDE_CATEGORIES}
    for t in threats:
        cat = t.get("category", "")
        if cat in category_counts:
            category_counts[cat] += 1

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "category_counts": category_counts,
    }
