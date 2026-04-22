MITRE_KB = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
        "subtechniques": ["T1110.001 - Password Guessing", "T1110.003 - Password Spraying", "T1110.004 - Credential Stuffing"],
        "detection": "Monitor authentication logs for repeated failures followed by success. Alert on >5 failures in 60 seconds.",
        "mitigation": "Account lockout policies, MFA, fail2ban, IP blacklisting after threshold.",
        "severity": "HIGH",
        "ioc": ["Multiple failed logins", "Login from unusual IP", "Login outside business hours"]
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.",
        "subtechniques": [],
        "detection": "Monitor for unusual network traffic patterns, port scanning signatures in IDS/IPS.",
        "mitigation": "Network segmentation, firewall rules, IDS/IPS rules for scan detection.",
        "severity": "MEDIUM",
        "ioc": ["Sequential port connections", "Nmap signatures", "High connection rate to multiple ports"]
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.",
        "subtechniques": ["T1078.001 - Default Accounts", "T1078.002 - Domain Accounts", "T1078.003 - Local Accounts"],
        "detection": "Monitor for logon behavior anomalies, unusual access times, abnormal resource access.",
        "mitigation": "MFA, privileged account management, regular account audits.",
        "severity": "HIGH",
        "ioc": ["Login at unusual hours", "Access from new location", "Privilege escalation after login"]
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "subtechniques": ["T1059.001 - PowerShell", "T1059.004 - Unix Shell", "T1059.006 - Python"],
        "detection": "Monitor process creation, command line arguments, script execution logs.",
        "mitigation": "Restrict script execution, application whitelisting, PowerShell constrained mode.",
        "severity": "HIGH",
        "ioc": ["Unusual shell spawning", "Encoded commands", "Script execution from temp directories"]
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": "Adversaries may inject code into processes in order to evade process-based defenses.",
        "subtechniques": ["T1055.001 - DLL Injection", "T1055.012 - Process Hollowing"],
        "detection": "Monitor for unusual process relationships, memory anomalies.",
        "mitigation": "Endpoint protection, behavior monitoring, memory protection.",
        "severity": "CRITICAL",
        "ioc": ["Unusual parent-child process", "Memory injection patterns", "Unexpected DLL loads"]
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections.",
        "subtechniques": ["T1021.001 - Remote Desktop Protocol", "T1021.004 - SSH"],
        "detection": "Monitor remote service logins, failed attempts, unusual access patterns.",
        "mitigation": "MFA for remote access, VPN, network segmentation.",
        "severity": "HIGH",
        "ioc": ["SSH from unknown IP", "RDP brute force", "Login to multiple hosts in short time"]
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system.",
        "subtechniques": [],
        "detection": "Monitor application logs for exploitation patterns, WAF alerts.",
        "mitigation": "Patch management, WAF, network segmentation.",
        "severity": "CRITICAL",
        "ioc": ["SQL injection patterns", "XSS attempts", "Path traversal", "Unusual HTTP methods"]
    },
    "DEFAULT": {
        "name": "Unknown Technique",
        "tactic": "Unknown",
        "description": "No specific MITRE ATT&CK technique identified. Manual analysis required.",
        "subtechniques": [],
        "detection": "Review logs manually and correlate with other events.",
        "mitigation": "Follow incident response procedures.",
        "severity": "MEDIUM",
        "ioc": ["Review full_log for indicators"]
    }
}

def get_mitre_context(mitre_ids):
    """
    Retourne le contexte MITRE pour une liste de TTP IDs.
    Si aucun TTP connu, retourne le contexte DEFAULT.
    """
    if not mitre_ids:
        return [MITRE_KB["DEFAULT"]]
    
    results = []
    for mid in mitre_ids:
        # Cherche la technique principale (T1110 depuis T1110.001)
        base_id = mid.split(".")[0]
        if base_id in MITRE_KB:
            results.append({**MITRE_KB[base_id], "id": mid})
        else:
            results.append({**MITRE_KB["DEFAULT"], "id": mid})
    
    return results if results else [MITRE_KB["DEFAULT"]]

if __name__ == "__main__":
    print("=== Test MITRE KB ===")
    context = get_mitre_context(["T1110", "T1046"])
    for c in context:
        print(f"[{c['id']}] {c['name']} — {c['tactic']} — Sévérité: {c['severity']}")
