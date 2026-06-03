"""
Cybersecurity Glossary Module
================================
Provides plain-language definitions for 30+ cybersecurity terms.
Designed to make IntelliSecure accessible to non-technical users.

Author: IntelliSecure Team
"""

# â”€â”€â”€ Full Cybersecurity Glossary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

GLOSSARY: dict[str, dict] = {
    "brute_force": {
        "term":       "Brute Force Attack",
        "definition": "An automated attack where hackers try thousands of password combinations very quickly until they guess the correct one.",
        "example":    "An attacker uses a script to try 'password123', 'abc123', '111111'... until they access your account.",
        "severity":   "Critical",
        "category":   "Credential Attack"
    },
    "port_scan": {
        "term":       "Port Scan",
        "definition": "A technique hackers use to find which 'doors' (ports) are open on your computer or network â€” like trying every lock in a building.",
        "example":    "An attacker scans your server to find that port 22 (SSH) and port 3389 (Remote Desktop) are open and then targets those.",
        "severity":   "High",
        "category":   "Reconnaissance"
    },
    "malware": {
        "term":       "Malware",
        "definition": "Malicious software designed to damage, disrupt, or gain unauthorized access to computers. Includes viruses, ransomware, spyware, and trojans.",
        "example":    "A virus that encrypts all your files and demands payment to unlock them (ransomware).",
        "severity":   "Critical",
        "category":   "Malicious Software"
    },
    "ransomware": {
        "term":       "Ransomware",
        "definition": "A type of malware that locks your files and demands money (ransom) to unlock them.",
        "example":    "WannaCry ransomware infected 200,000+ computers worldwide in 2017 and demanded Bitcoin payments.",
        "severity":   "Critical",
        "category":   "Malicious Software"
    },
    "phishing": {
        "term":       "Phishing",
        "definition": "Fake emails or websites designed to trick you into entering your password or personal information.",
        "example":    "An email claiming to be from your bank asking you to 'verify your account' by clicking a link.",
        "severity":   "High",
        "category":   "Social Engineering"
    },
    "ddos": {
        "term":       "DDoS Attack",
        "definition": "Distributed Denial of Service â€” flooding a website or server with so much fake traffic that real users can't access it.",
        "example":    "Hackers use thousands of infected computers to overload a gaming company's servers.",
        "severity":   "High",
        "category":   "Availability Attack"
    },
    "sql_injection": {
        "term":       "SQL Injection",
        "definition": "A technique where hackers insert malicious database commands into web forms to steal or delete data.",
        "example":    "Entering ' OR 1=1;-- into a login form to bypass authentication.",
        "severity":   "Critical",
        "category":   "Application Attack"
    },
    "mfa": {
        "term":       "Multi-Factor Authentication (MFA)",
        "definition": "Using two or more verification steps to log in â€” like a password plus a code sent to your phone.",
        "example":    "After typing your password, Gmail sends a 6-digit code to your phone that you must also enter.",
        "severity":   "Low",
        "category":   "Security Control"
    },
    "firewall": {
        "term":       "Firewall",
        "definition": "A security system that monitors and controls incoming and outgoing network traffic â€” like a security guard for your network.",
        "example":    "A firewall blocks unauthorized access from the internet while allowing normal web browsing.",
        "severity":   "Low",
        "category":   "Security Control"
    },
    "vpn": {
        "term":       "VPN (Virtual Private Network)",
        "definition": "Creates an encrypted tunnel for your internet traffic so no one can spy on what you're doing online.",
        "example":    "Employees working from home use a VPN to securely access company files.",
        "severity":   "Low",
        "category":   "Security Control"
    },
    "zero_day": {
        "term":       "Zero-Day Vulnerability",
        "definition": "A newly discovered software flaw that even the software maker doesn't know about yet â€” and has had 'zero days' to fix.",
        "example":    "A hacker finds a bug in Windows before Microsoft knows about it and uses it to attack systems.",
        "severity":   "Critical",
        "category":   "Vulnerability"
    },
    "social_engineering": {
        "term":       "Social Engineering",
        "definition": "Manipulating people psychologically to reveal confidential information instead of hacking computers directly.",
        "example":    "Calling the IT helpdesk pretending to be the CEO and asking for a password reset.",
        "severity":   "High",
        "category":   "Social Engineering"
    },
    "insider_threat": {
        "term":       "Insider Threat",
        "definition": "A security risk that comes from people inside an organization â€” employees, contractors, or business partners.",
        "example":    "An angry employee copies confidential client data to a USB drive before quitting.",
        "severity":   "High",
        "category":   "Insider Risk"
    },
    "encryption": {
        "term":       "Encryption",
        "definition": "Scrambling data so it can only be read by someone with the correct key â€” making it unreadable to everyone else.",
        "example":    "WhatsApp uses end-to-end encryption so only you and the recipient can read your messages.",
        "severity":   "Low",
        "category":   "Security Control"
    },
    "intrusion_detection": {
        "term":       "Intrusion Detection System (IDS)",
        "definition": "Software that monitors your network for suspicious activity and alerts you when something unusual is detected.",
        "example":    "IntelliSecure's threat detector is an IDS â€” it alerts you when brute force attacks are detected.",
        "severity":   "Low",
        "category":   "Security Tool"
    },
    "patch": {
        "term":       "Security Patch",
        "definition": "A software update that fixes a known security vulnerability.",
        "example":    "Microsoft releases monthly 'Patch Tuesday' updates to fix security holes in Windows.",
        "severity":   "Medium",
        "category":   "Security Practice"
    },
    "rbac": {
        "term":       "Role-Based Access Control (RBAC)",
        "definition": "A security model where users are given only the permissions they need for their job â€” nothing more.",
        "example":    "A cashier can process payments but cannot access payroll records.",
        "severity":   "Low",
        "category":   "Security Control"
    },
    "credential_stuffing": {
        "term":       "Credential Stuffing",
        "definition": "Using leaked username/password pairs from one data breach to try to log into other websites.",
        "example":    "Hackers use passwords leaked from a LinkedIn breach to try to log into Gmail and banking sites.",
        "severity":   "High",
        "category":   "Credential Attack"
    },
    "data_exfiltration": {
        "term":       "Data Exfiltration",
        "definition": "The unauthorized transfer of data from a computer or network to an attacker's location.",
        "example":    "Malware sends copies of your confidential files to a hacker's server in another country.",
        "severity":   "Critical",
        "category":   "Data Theft"
    },
    "anomaly_detection": {
        "term":       "Anomaly Detection",
        "definition": "Using AI/ML to identify unusual patterns that deviate from normal behaviour â€” the basis of IntelliSecure's ML module.",
        "example":    "The system flags a login at 3 AM from a country the user has never visited as an anomaly.",
        "severity":   "Medium",
        "category":   "Security Technology"
    },
    "jwt": {
        "term":       "JWT (JSON Web Token)",
        "definition": "A secure way to transmit user identity information between systems â€” used for authentication in IntelliSecure.",
        "example":    "When you log in, IntelliSecure gives you a JWT token that proves your identity for future requests.",
        "severity":   "Low",
        "category":   "Authentication"
    },
    "mitre_attack": {
        "term":       "MITRE ATT&CK Framework",
        "definition": "A globally recognized knowledge base of attacker tactics, techniques, and procedures used for threat intelligence.",
        "example":    "IntelliSecure maps each detected threat to its MITRE ATT&CK technique code (e.g., T1110 for Brute Force).",
        "severity":   "Low",
        "category":   "Security Framework"
    },
    "incident_response": {
        "term":       "Incident Response",
        "definition": "The organized approach to addressing and managing a cybersecurity attack or breach.",
        "example":    "When ransomware hits, the incident response team isolates infected machines, restores backups, and notifies stakeholders.",
        "severity":   "Medium",
        "category":   "Security Process"
    },
    "least_privilege": {
        "term":       "Principle of Least Privilege",
        "definition": "Giving users and systems the minimum level of access rights needed to perform their work.",
        "example":    "A developer only gets access to the code they're working on â€” not the production database or payroll system.",
        "severity":   "Low",
        "category":   "Security Principle"
    },
    "honeypot": {
        "term":       "Honeypot",
        "definition": "A decoy system set up to attract and study hackers â€” helping security teams understand attack methods.",
        "example":    "A fake vulnerable server placed on the network to lure attackers away from real systems.",
        "severity":   "Low",
        "category":   "Security Tool"
    },
    "siem": {
        "term":       "SIEM (Security Information and Event Management)",
        "definition": "A platform that collects and analyzes security logs from across your organization in real-time. IntelliSecure is a lightweight SIEM.",
        "example":    "IntelliSecure aggregates login logs, network logs, file access logs, and malware logs in one dashboard.",
        "severity":   "Low",
        "category":   "Security Technology"
    },
    "c2": {
        "term":       "Command & Control (C2)",
        "definition": "Servers used by hackers to remotely control malware on infected computers.",
        "example":    "After infecting a computer with malware, the attacker uses a C2 server to give it commands remotely.",
        "severity":   "Critical",
        "category":   "Attack Infrastructure"
    }
}


def get_term(term_key: str) -> dict | None:
    """
    Look up a glossary term by key.

    Args:
        term_key: Lowercase underscore key (e.g., 'brute_force', 'malware')

    Returns:
        Glossary entry dict or None if not found.
    """
    return GLOSSARY.get(term_key.lower().replace(" ", "_"), None)


def search_glossary(query: str) -> list[dict]:
    """
    Search glossary by term name or definition content (case-insensitive).

    Args:
        query: Search string

    Returns:
        List of matching glossary entries.
    """
    query = query.lower()
    results = []
    for key, entry in GLOSSARY.items():
        if (query in entry["term"].lower() or
            query in entry["definition"].lower() or
            query in entry.get("category", "").lower() or
            query in key):
            results.append({"key": key, **entry})
    return results


def get_all_terms() -> list[dict]:
    """Return all glossary entries sorted alphabetically by term name."""
    return sorted(
        [{"key": k, **v} for k, v in GLOSSARY.items()],
        key=lambda x: x["term"]
    )


def get_terms_by_category(category: str) -> list[dict]:
    """Return all terms in a given category."""
    return [
        {"key": k, **v} for k, v in GLOSSARY.items()
        if v.get("category", "").lower() == category.lower()
    ]


def get_all_categories() -> list[str]:
    """Return a sorted list of all unique glossary categories."""
    return sorted(set(v.get("category", "General") for v in GLOSSARY.values()))
