"""
Learning Helper Module — Educational Threat Explanations
==========================================================
Provides simple, beginner-friendly explanations for security concepts.
Bridges the gap between technical security events and plain English.

Designed for users without cybersecurity backgrounds.

Author: InteliSecure Team
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.glossary import get_term, search_glossary, get_all_terms


# ─── Threat-to-Glossary Mapping ────────────────────────────────────────────────
THREAT_TO_GLOSSARY_KEYS: dict[str, list[str]] = {
    "Brute Force Attack":        ["brute_force", "credential_stuffing", "mfa"],
    "Port Scan":                 ["port_scan", "firewall", "intrusion_detection"],
    "Unauthorized File Access":  ["insider_threat", "rbac", "least_privilege"],
    "Blocked USB Device":        ["insider_threat", "data_exfiltration"],
    "Malware Detected":          ["malware", "ransomware", "c2"],
    "ML Anomaly":                ["anomaly_detection", "siem"],
}


def explain_threat_simply(threat_type: str) -> dict:
    """
    Return a beginner-friendly explanation of a threat type with
    linked glossary terms.

    Args:
        threat_type: e.g., "Brute Force Attack"

    Returns:
        {
            what_happened, why_it_matters, what_to_do,
            learn_more: [ glossary terms ]
        }
    """
    explanations = {
        "Brute Force Attack": {
            "what_happened": (
                "Someone is trying to guess your password by testing thousands of combinations "
                "very quickly using a computer program. Think of it like someone trying every key "
                "on a giant keyring to open your front door."
            ),
            "why_it_matters": (
                "If they succeed, they get full access to the affected account. This could lead to "
                "stolen data, financial loss, or even complete system takeover."
            ),
            "what_to_do": (
                "Block the attacking computer immediately, enable two-step login verification (MFA), "
                "and have the affected user change their password right away."
            )
        },
        "Port Scan": {
            "what_happened": (
                "Someone is 'knocking on all the doors' of your network to see which ones are unlocked. "
                "Ports are like doors that allow different types of network traffic — and hackers scan "
                "them to find weak entry points."
            ),
            "why_it_matters": (
                "A port scan is usually the first step before an actual attack. The attacker is mapping "
                "your network to plan their next move."
            ),
            "what_to_do": (
                "Block the scanning IP in your firewall immediately. Then check which 'doors' (ports) "
                "are open and close any that are not needed."
            )
        },
        "Unauthorized File Access": {
            "what_happened": (
                "Someone tried to view or change files that they don't have permission to access. "
                "The system blocked them, but this needs investigation."
            ),
            "why_it_matters": (
                "This could indicate an insider threat (a disgruntled employee), a compromised account, "
                "or accidental access to sensitive areas. Any of these needs to be investigated."
            ),
            "what_to_do": (
                "Find out who tried to access the files and why. Review their permissions and consider "
                "temporarily suspending their account while you investigate."
            )
        },
        "Blocked USB Device": {
            "what_happened": (
                "Someone plugged an unauthorized USB drive into a company computer. The security "
                "system blocked it automatically, but someone was trying to use removable storage."
            ),
            "why_it_matters": (
                "USB drives can be used to steal company data or introduce malware into your network. "
                "Even an innocent-looking personal USB drive can carry viruses."
            ),
            "what_to_do": (
                "Talk to the employee involved. If the use was deliberate and unauthorized, treat it "
                "as an incident. Ensure all workstations enforce the USB device policy."
            )
        },
        "Malware Detected": {
            "what_happened": (
                "Dangerous software (a virus, ransomware, or spyware) was found on a device in your "
                "network. The security system has flagged it — now you need to act quickly."
            ),
            "why_it_matters": (
                "Malware can spread through your network, steal data, encrypt files for ransom, or "
                "give hackers remote control over your systems."
            ),
            "what_to_do": (
                "Disconnect the infected device from the network immediately. Don't turn it off — "
                "run a full antivirus scan first. Notify your IT security team right away."
            )
        },
        "ML Anomaly": {
            "what_happened": (
                "Our AI system detected something unusual that doesn't match normal behaviour patterns. "
                "It's not a confirmed attack, but something is out of the ordinary and needs a human to check."
            ),
            "why_it_matters": (
                "AI anomaly detection catches threats that traditional rules miss. This could be an "
                "early warning sign of an attack, a new hacking technique, or just an unusual (but legitimate) event."
            ),
            "what_to_do": (
                "Look at the specific log entry that was flagged. If you can explain it (e.g., a scheduled "
                "backup ran at an unusual time), mark it as resolved. If you can't explain it, escalate to a senior analyst."
            )
        }
    }

    # Get the matching explanation or a default
    base_explanation = explanations.get(threat_type, {
        "what_happened":  f"A security event of type '{threat_type}' was detected.",
        "why_it_matters": "This event requires investigation by your security team.",
        "what_to_do":     "Review the relevant logs and escalate to your security team."
    })

    # Get linked glossary terms
    glossary_keys   = THREAT_TO_GLOSSARY_KEYS.get(threat_type, [])
    linked_glossary = []
    for key in glossary_keys:
        term_data = get_term(key)
        if term_data:
            linked_glossary.append({
                "key":        key,
                "term":       term_data["term"],
                "short_def":  term_data["definition"][:120] + "..."
            })

    return {
        "threat_type":   threat_type,
        "what_happened": base_explanation["what_happened"],
        "why_it_matters": base_explanation["why_it_matters"],
        "what_to_do":    base_explanation["what_to_do"],
        "learn_more":    linked_glossary
    }


def get_learning_path() -> list[dict]:
    """
    Return a structured learning path for beginner security operators.
    Covers the most important concepts in a logical order.
    """
    learning_topics = [
        {
            "order":       1,
            "topic":       "Understanding Threats",
            "description": "Learn what the main types of cyberattacks are.",
            "glossary_keys": ["brute_force", "malware", "phishing", "social_engineering"],
            "estimated_time": "10 minutes"
        },
        {
            "order":       2,
            "topic":       "Network Security Basics",
            "description": "Understand how attackers probe your network.",
            "glossary_keys": ["port_scan", "firewall", "ddos"],
            "estimated_time": "8 minutes"
        },
        {
            "order":       3,
            "topic":       "Protecting Accounts",
            "description": "Learn how to secure user accounts effectively.",
            "glossary_keys": ["mfa", "credential_stuffing", "rbac", "least_privilege"],
            "estimated_time": "12 minutes"
        },
        {
            "order":       4,
            "topic":       "Insider Threats & Data Loss",
            "description": "Understand risks that come from inside your organization.",
            "glossary_keys": ["insider_threat", "data_exfiltration", "encryption"],
            "estimated_time": "10 minutes"
        },
        {
            "order":       5,
            "topic":       "AI in Cybersecurity",
            "description": "Learn how InteliSecure's AI modules protect you.",
            "glossary_keys": ["anomaly_detection", "siem", "intrusion_detection"],
            "estimated_time": "8 minutes"
        },
        {
            "order":       6,
            "topic":       "Incident Response",
            "description": "Know what to do when an attack is detected.",
            "glossary_keys": ["incident_response", "patch", "honeypot"],
            "estimated_time": "15 minutes"
        }
    ]

    # Enrich with full glossary data
    for topic in learning_topics:
        expanded_terms = []
        for key in topic.get("glossary_keys", []):
            term = get_term(key)
            if term:
                expanded_terms.append({"key": key, **term})
        topic["terms"] = expanded_terms

    return learning_topics
