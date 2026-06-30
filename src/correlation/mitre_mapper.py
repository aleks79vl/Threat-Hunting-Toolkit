MITRE_MAPPING = {
    "SQL Injection Attempt Detected": {
        "technique": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },

    "XSS Attempt Detected": {
        "technique": "T1189",
        "name": "Drive-by Compromise",
        "tactic": "Initial Access",
    },

    "Directory Traversal Attempt Detected": {
        "technique": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },

    "Possible Admin Brute Force Detected": {
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
    },

    "Windows Failed Logon Detected": {
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
    },

    "Suspicious PowerShell Process": {
        "technique": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
    },

    "User Added to Administrators Group": {
        "technique": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence",
    },

    "Windows Audit Log Cleared": {
        "technique": "T1070.001",
        "name": "Clear Windows Event Logs",
        "tactic": "Defense Evasion",
    },

    "Firewall Allowed Critical Port Access": {
        "technique": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
    },

    "Firewall Blocked Critical Port Access": {
        "technique": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
    },

    "Possible Web Enumeration Detected": {
        "technique": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
    },
}

def get_mitre_mapping(title: str) -> dict:
    return MITRE_MAPPING.get(
        title,
        {
            "technique": "Unknown",
            "name": "Unknown",
            "tactic": "Unknown",
        },
    )