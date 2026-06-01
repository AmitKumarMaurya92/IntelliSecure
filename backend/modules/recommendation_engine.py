"""
Recommendation Engine
======================
Generates actionable, prioritized security recommendations based on:
  - Current threat landscape (active alerts)
  - Security score and risk level
  - Individual threat type context

Each recommendation includes:
  - priority:     P1 (Critical) → P4 (Informational)
  - action:       Short action title
  - description:  Detailed guidance
  - effort:       Low / Medium / High
  - impact:       Low / Medium / High

Author: InteliSecure Team
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── Threat-Specific Recommendation Library ───────────────────────────────────

THREAT_RECOMMENDATIONS: dict[str, list[dict]] = {

    "Brute Force Attack": [
        {
            "priority":    "P1",
            "action":      "Block Offending IP Address",
            "description": "Add the source IP to the firewall blocklist immediately. This stops the ongoing attack.",
            "effort":      "Low",
            "impact":      "High"
        },
        {
            "priority":    "P1",
            "action":      "Enable Multi-Factor Authentication (MFA)",
            "description": "MFA makes stolen passwords useless. Enable on all accounts, especially admin and remote access.",
            "effort":      "Medium",
            "impact":      "High"
        },
        {
            "priority":    "P2",
            "action":      "Set Account Lockout Policy",
            "description": "Configure accounts to lock after 5 consecutive failed attempts with a 15-minute cooldown.",
            "effort":      "Low",
            "impact":      "High"
        },
        {
            "priority":    "P2",
            "action":      "Audit Recent Successful Logins",
            "description": "Check if any logins from the same IP or time period succeeded before detection.",
            "effort":      "Low",
            "impact":      "Medium"
        },
        {
            "priority":    "P3",
            "action":      "Force Password Reset for Targeted Accounts",
            "description": "Require affected users to set new passwords and notify them of the attack.",
            "effort":      "Low",
            "impact":      "Medium"
        }
    ],

    "Port Scan": [
        {
            "priority":    "P1",
            "action":      "Block Scanner IP at Perimeter Firewall",
            "description": "Immediately drop all traffic from the scanning IP using firewall rules.",
            "effort":      "Low",
            "impact":      "High"
        },
        {
            "priority":    "P2",
            "action":      "Audit Open Ports and Services",
            "description": "Run a service audit — close any ports that are not required for business operations.",
            "effort":      "Medium",
            "impact":      "High"
        },
        {
            "priority":    "P2",
            "action":      "Enable IDS/IPS Port Scan Detection",
            "description": "Configure your intrusion detection system to alert on future port scans in real-time.",
            "effort":      "Medium",
            "impact":      "Medium"
        },
        {
            "priority":    "P3",
            "action":      "Review Network Segmentation",
            "description": "Ensure sensitive internal zones are not reachable from the scanned network.",
            "effort":      "High",
            "impact":      "High"
        }
    ],

    "Unauthorized File Access": [
        {
            "priority":    "P1",
            "action":      "Audit User Permissions Immediately",
            "description": "Review the affected user's access rights and revoke any permissions exceeding job requirements.",
            "effort":      "Low",
            "impact":      "High"
        },
        {
            "priority":    "P2",
            "action":      "Temporarily Suspend User Account",
            "description": "Suspend the account pending investigation to prevent further unauthorized access.",
            "effort":      "Low",
            "impact":      "High"
        },
        {
            "priority":    "P2",
            "action":      "Review Surrounding User Activity",
            "description": "Examine the user's full activity log for the past 24 hours for additional anomalies.",
            "effort":      "Low",
            "impact":      "Medium"
        },
        {
            "priority":    "P3",
            "action":      "Implement Least Privilege Access",
            "description": "Enforce the principle of least privilege across all user accounts and shared directories.",
            "effort":      "High",
            "impact":      "High"
        }
    ],

    "Blocked USB Device": [
        {
            "priority":    "P1",
            "action":      "Interview the Involved Employee",
            "description": "Contact the user immediately to determine intent — accidental or deliberate policy violation.",
            "effort":      "Low",
            "impact":      "High"
        },
        {
            "priority":    "P2",
            "action":      "Audit Workstation Data Transfer Logs",
            "description": "Check if any files were transferred before the USB was blocked.",
            "effort":      "Low",
            "impact":      "High"
        },
        {
            "priority":    "P3",
            "action":      "Review and Enforce USB Policy",
            "description": "Ensure the USB device control policy is applied to all workstations. Add approved devices to whitelist.",
            "effort":      "Medium",
            "impact":      "Medium"
        }
    ],

    "Malware Detected": [
        {
            "priority":    "P1",
            "action":      "Isolate the Infected System",
            "description": "Immediately disconnect the affected workstation from the network to prevent malware spread.",
            "effort":      "Low",
            "impact":      "High"
        },
        {
            "priority":    "P1",
            "action":      "Run Full Malware Scan with Updated Signatures",
            "description": "Update antivirus definitions and run a full system scan on the isolated machine.",
            "effort":      "Low",
            "impact":      "High"
        },
        {
            "priority":    "P2",
            "action":      "Determine Infection Vector",
            "description": "Trace how the malware entered: phishing email, malicious download, infected USB, or network exploit.",
            "effort":      "Medium",
            "impact":      "High"
        },
        {
            "priority":    "P2",
            "action":      "Check for C2 Communications",
            "description": "Analyse network logs for outbound connections to known Command & Control servers.",
            "effort":      "Medium",
            "impact":      "High"
        },
        {
            "priority":    "P3",
            "action":      "Restore from Clean Backup",
            "description": "If the system is compromised, restore from the last known-clean backup snapshot.",
            "effort":      "Medium",
            "impact":      "High"
        }
    ],

    "ML Anomaly": [
        {
            "priority":    "P2",
            "action":      "Manually Review the Flagged Log Entry",
            "description": "Examine the anomalous log record for unusual fields such as unusual times, IPs, or data volumes.",
            "effort":      "Low",
            "impact":      "Medium"
        },
        {
            "priority":    "P2",
            "action":      "Check for Correlated Events",
            "description": "Look at other logs from the same time window and source to identify broader attack patterns.",
            "effort":      "Medium",
            "impact":      "Medium"
        },
        {
            "priority":    "P3",
            "action":      "Escalate to Senior Analyst if Unexplained",
            "description": "If the anomaly cannot be explained by a known maintenance window or expected change, escalate.",
            "effort":      "Low",
            "impact":      "Medium"
        }
    ]
}


# ─── General Security Best-Practice Recommendations ────────────────────────────

GENERAL_RECOMMENDATIONS: list[dict] = [
    {
        "priority":    "P3",
        "action":      "Keep All Systems Patched",
        "description": "Apply security patches within 48 hours of release for critical vulnerabilities.",
        "effort":      "Medium",
        "impact":      "High"
    },
    {
        "priority":    "P3",
        "action":      "Enable Centralised Logging",
        "description": "Ensure all systems forward logs to the InteliSecure SIEM for unified correlation.",
        "effort":      "Medium",
        "impact":      "High"
    },
    {
        "priority":    "P4",
        "action":      "Conduct Regular Security Awareness Training",
        "description": "Train all staff quarterly on phishing, social engineering, and data handling best practices.",
        "effort":      "Medium",
        "impact":      "Medium"
    },
    {
        "priority":    "P4",
        "action":      "Perform Regular Penetration Tests",
        "description": "Hire ethical hackers to test your defences at least annually.",
        "effort":      "High",
        "impact":      "High"
    }
]


def get_recommendations_for_threat(threat_type: str) -> list[dict]:
    """
    Return threat-specific recommendations for a given threat type.

    Args:
        threat_type: String (e.g., "Brute Force Attack", "Port Scan")

    Returns:
        List of recommendation dicts sorted by priority.
    """
    # Case-insensitive partial matching
    for key, recs in THREAT_RECOMMENDATIONS.items():
        if key.lower() in threat_type.lower() or threat_type.lower() in key.lower():
            return recs

    # Fallback: general recommendations if no specific match found
    return [
        {
            "priority":    "P2",
            "action":      "Investigate the Alert",
            "description": f"Manually review logs and system state related to: '{threat_type}'.",
            "effort":      "Low",
            "impact":      "Medium"
        }
    ] + GENERAL_RECOMMENDATIONS


def get_general_recommendations() -> list[dict]:
    """Return the general security best-practice recommendations."""
    return GENERAL_RECOMMENDATIONS


def generate_full_report_recommendations(active_threat_types: list[str]) -> dict:
    """
    Generate a complete recommendation report for a list of active threat types.
    Deduplicates and sorts all recommendations by priority.

    Args:
        active_threat_types: List of threat_type strings from current alerts

    Returns:
        Dict: { p1: [...], p2: [...], p3: [...], p4: [...], total_count: int }
    """
    all_recs: list[dict] = []
    seen_actions: set[str] = set()

    for threat_type in active_threat_types:
        for rec in get_recommendations_for_threat(threat_type):
            if rec["action"] not in seen_actions:
                seen_actions.add(rec["action"])
                rec["related_threat"] = threat_type
                all_recs.append(rec)

    # Add general recommendations
    for rec in GENERAL_RECOMMENDATIONS:
        if rec["action"] not in seen_actions:
            seen_actions.add(rec["action"])
            rec["related_threat"] = "General"
            all_recs.append(rec)

    grouped = {"P1": [], "P2": [], "P3": [], "P4": []}
    for rec in all_recs:
        priority = rec.get("priority", "P4")
        grouped.get(priority, grouped["P4"]).append(rec)

    return {
        "p1_critical":  grouped["P1"],
        "p2_high":      grouped["P2"],
        "p3_medium":    grouped["P3"],
        "p4_low":       grouped["P4"],
        "total_count":  len(all_recs)
    }
