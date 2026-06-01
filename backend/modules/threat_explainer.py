"""
Explainable AI (XAI) Threat Explainer
========================================
Provides human-readable, structured explanations for every detected threat type.
Outputs threat_name, severity, reason, impact, and recommendation for analysts.

This module enables non-technical users to understand what a threat means
and what action to take — core to InteliSecure's educational usability.

Author: InteliSecure Team
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── XAI Knowledge Base ────────────────────────────────────────────────────────
# Maps each threat_type string to a structured explanation template.
# Templates support optional field substitution via .format(**context).

XAI_KNOWLEDGE_BASE: dict[str, dict] = {

    "Brute Force Attack": {
        "threat_name":      "Brute Force Attack",
        "category":         "Credential Attack",
        "severity_default": "Critical",
        "simple_summary":   "Someone repeatedly tried wrong passwords to break into an account.",
        "technical_reason": (
            "Multiple consecutive failed authentication attempts were detected from the same "
            "source IP address within a short time window, indicating an automated password "
            "guessing or credential stuffing attack."
        ),
        "impact": (
            "If successful, the attacker gains unauthorized access to user accounts, potentially "
            "leading to data theft, privilege escalation, lateral movement, or complete system compromise."
        ),
        "recommendation": [
            "Immediately block the offending IP address in your firewall.",
            "Enable Multi-Factor Authentication (MFA) on all critical accounts.",
            "Implement an account lockout policy (e.g., lock after 5 failed attempts).",
            "Review logs for any successful logins from the flagged IP.",
            "Notify the affected user(s) to change their passwords immediately.",
            "Consider deploying a CAPTCHA on login forms."
        ],
        "mitre_technique": "T1110 — Brute Force"
    },

    "Port Scan": {
        "threat_name":      "Port Scan Detected",
        "category":         "Reconnaissance",
        "severity_default": "High",
        "simple_summary":   "An attacker is mapping your network to find open doors.",
        "technical_reason": (
            "A single source IP address sent connection requests to an unusually high number of "
            "distinct ports in a very short time — a classic network reconnaissance technique "
            "used to discover running services and potential vulnerabilities."
        ),
        "impact": (
            "Port scanning is typically the precursor to a targeted attack. The attacker collects "
            "intelligence about open services, operating systems, and versions to plan exploitation."
        ),
        "recommendation": [
            "Block the scanning IP at the network perimeter firewall.",
            "Enable port scan detection on your IDS/IPS if available.",
            "Audit all open ports and close any unnecessary services.",
            "Ensure all publicly exposed services are patched and up to date.",
            "Review network segmentation to limit lateral movement potential.",
            "Enable rate-limiting on network connections."
        ],
        "mitre_technique": "T1046 — Network Service Scanning"
    },

    "Unauthorized File Access": {
        "threat_name":      "Unauthorized File Access",
        "category":         "Insider Threat / Privilege Abuse",
        "severity_default": "Medium",
        "simple_summary":   "A user tried to access files they don't have permission to view.",
        "technical_reason": (
            "File access control logs recorded one or more 'Denied' events for a user attempting "
            "to read, write, or delete files outside their authorized scope. This may indicate "
            "accidental misuse, deliberate data gathering, or compromised credentials."
        ),
        "impact": (
            "Unauthorized file access can result in sensitive data disclosure, intellectual property "
            "theft, compliance violations (GDPR, HIPAA), or preparation for data exfiltration."
        ),
        "recommendation": [
            "Review and enforce the principle of least privilege on file permissions.",
            "Audit the affected user's recent activity for further anomalies.",
            "Temporarily suspend the user account pending investigation.",
            "Ensure sensitive directories have proper ACLs configured.",
            "Enable file access auditing for all sensitive folders.",
            "Consider implementing Data Loss Prevention (DLP) controls."
        ],
        "mitre_technique": "T1083 — File and Directory Discovery"
    },

    "Blocked USB Device": {
        "threat_name":      "Blocked USB Device",
        "category":         "Data Exfiltration Attempt",
        "severity_default": "High",
        "simple_summary":   "Someone tried to plug in an unauthorized USB device.",
        "technical_reason": (
            "A USB storage device was connected to a workstation but blocked by endpoint "
            "security policy. This event indicates either an accidental policy violation or "
            "a deliberate attempt to copy data onto removable media."
        ),
        "impact": (
            "Uncontrolled USB access is one of the leading causes of insider data theft and "
            "malware introduction. A single compromised USB drive can infect the entire network."
        ),
        "recommendation": [
            "Physically locate the workstation and the employee involved.",
            "Conduct an interview to determine intent (accidental vs deliberate).",
            "Ensure USB device control policy is enforced on all endpoints.",
            "Maintain a whitelist of approved USB devices.",
            "Review endpoint logs for any data transfer attempts prior to blocking.",
            "Consider disabling USB ports physically on sensitive workstations."
        ],
        "mitre_technique": "T1091 — Replication Through Removable Media"
    },

    "Malware Detected": {
        "threat_name":      "Malware Detected",
        "category":         "Malicious Software",
        "severity_default": "Critical",
        "simple_summary":   "Dangerous software was found on a device in your network.",
        "technical_reason": (
            "The endpoint security system detected a file matching a known malware signature. "
            "The file was either quarantined or deleted depending on policy configuration."
        ),
        "impact": (
            "Malware can lead to ransomware encryption, data theft, botnet enrollment, "
            "keylogging, credential harvesting, or complete system destruction."
        ),
        "recommendation": [
            "Immediately isolate the affected workstation from the network.",
            "Run a full system scan with updated antivirus signatures.",
            "Determine the infection vector (email attachment, USB, download, etc.).",
            "Check if the malware communicated with external C2 servers.",
            "Restore from a clean backup if the system is compromised.",
            "Report the incident to your incident response team.",
            "Patch the OS and all applications to close the initial entry point."
        ],
        "mitre_technique": "T1204 — User Execution / T1059 — Command and Scripting"
    },

    "ML Anomaly": {
        "threat_name":      "AI-Detected Anomaly",
        "category":         "Behavioural Anomaly",
        "severity_default": "Medium",
        "simple_summary":   "Our AI detected unusual behaviour that doesn't match normal patterns.",
        "technical_reason": (
            "The Isolation Forest machine learning model identified a data point with a "
            "significantly different feature profile compared to the established baseline of "
            "normal system behaviour. This could indicate a novel attack, misconfiguration, "
            "or unusual user behaviour."
        ),
        "impact": (
            "Anomalies often precede known attacks or indicate zero-day exploits that signature-based "
            "systems cannot detect. Early investigation is critical."
        ),
        "recommendation": [
            "Review the flagged log entry in detail to understand the anomalous behaviour.",
            "Check for correlated events around the same time period.",
            "Determine if the behaviour was authorized (maintenance window, new user, etc.).",
            "If unexplained, escalate to a senior security analyst.",
            "Retrain the ML model with new data to improve accuracy over time.",
            "Cross-reference with threat intelligence feeds for known IoCs."
        ],
        "mitre_technique": "T1036 — Masquerading / Unknown"
    },
}


def explain_threat(threat_type: str, context: dict = None) -> dict:
    """
    Return a structured XAI explanation for a given threat type.

    Args:
        threat_type: String matching a key in XAI_KNOWLEDGE_BASE (e.g., "Brute Force Attack")
        context:     Optional dict with extra fields like { ip_address, username, count }

    Returns:
        Structured explanation dict with all XAI fields, or a generic fallback.
    """
    ctx = context or {}

    # Look up the knowledge base (case-insensitive partial match)
    entry = None
    for key, value in XAI_KNOWLEDGE_BASE.items():
        if key.lower() in threat_type.lower() or threat_type.lower() in key.lower():
            entry = value
            break

    # Fallback for unknown threat types
    if not entry:
        entry = {
            "threat_name":      threat_type,
            "category":         "Unknown Threat",
            "severity_default": "Medium",
            "simple_summary":   "An unrecognised security event was detected.",
            "technical_reason": f"Threat type '{threat_type}' was flagged by the detection engine.",
            "impact":           "Impact unknown — manual investigation required.",
            "recommendation":   [
                "Investigate the alert manually.",
                "Review relevant logs for context.",
                "Escalate to your security team if the cause is unclear."
            ],
            "mitre_technique":  "Unknown"
        }

    # Build final response
    return {
        "Threat Name":       entry["threat_name"],
        "Severity":          ctx.get("severity", entry["severity_default"]),
        "Reason":            entry["technical_reason"],
        "Impact":            entry["impact"],
        "Recommendation":    entry["recommendation"]
    }


def get_all_threat_types() -> list[str]:
    """Return a list of all threat types supported by the XAI engine."""
    return list(XAI_KNOWLEDGE_BASE.keys())
