import json
import paramiko  # nosec B402
import urllib3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_wazuh_alert(alert_json):
    alert = alert_json if isinstance(alert_json, dict) else json.loads(alert_json)
    return {
        "id": alert.get("id", f"WZ-{datetime.now().strftime('%H%M%S')}"),
        "timestamp": alert.get("timestamp", datetime.now().isoformat()),
        "agent_name": alert.get("agent", {}).get("name", "unknown"),
        "agent_ip": alert.get("agent", {}).get("ip", "unknown"),
        "rule_id": alert.get("rule", {}).get("id", "N/A"),
        "rule_level": int(alert.get("rule", {}).get("level", 0)),
        "rule_description": alert.get("rule", {}).get("description", "N/A"),
        "rule_groups": alert.get("rule", {}).get("groups", []),
        "mitre_id": alert.get("rule", {}).get("mitre", {}).get("id", []),
        "mitre_technique": alert.get("rule", {}).get("mitre", {}).get("technique", []),
        "mitre_tactic": alert.get("rule", {}).get("mitre", {}).get("tactic", []),
        "full_log": alert.get("full_log", ""),
        "location": alert.get("location", ""),
        "data": alert.get("data", {})
    }

def get_wazuh_alerts_ssh(host="172.16.1.10", user="msh", key="/home/msh-cyber/.ssh/id_rsa", limit=20):
    """
    Récupère les vraies alertes Wazuh via SSH en lisant alerts.json directement.
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507
        client.connect(host, username=user, key_filename=key, timeout=5)
        cmd = f"sudo tail -n 200 /var/ossec/logs/alerts/alerts.json 2>/dev/null | grep '^{{' | tail -n {limit}"
        stdin, stdout, stderr = client.exec_command(cmd)  # nosec B601
        output = stdout.read().decode().strip()
        client.close()

        alerts = []
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                alerts.append(parse_wazuh_alert(raw))
            except:
                continue
        return alerts

    except Exception as e:
        print(f"[!] Erreur SSH Wazuh: {e}")
        return []

def get_simulated_alerts():
    return [
        {
            "id": "SIM-001",
            "timestamp": datetime.now().isoformat(),
            "agent_name": "msh-cyber",
            "agent_ip": "172.16.1.1",
            "rule_id": "5763",
            "rule_level": 10,
            "rule_description": "Multiple authentication failures followed by a success.",
            "rule_groups": ["authentication_failures", "authentication_success"],
            "mitre_id": ["T1110"],
            "mitre_technique": ["Brute Force"],
            "mitre_tactic": ["Credential Access"],
            "full_log": "sshd: pam_unix(sshd:auth): authentication failure; user=root; rhost=172.16.228.130",
            "location": "/var/log/auth.log",
            "data": {}
        },
        {
            "id": "SIM-002",
            "timestamp": datetime.now().isoformat(),
            "agent_name": "gitserver",
            "agent_ip": "172.16.1.20",
            "rule_id": "40101",
            "rule_level": 8,
            "rule_description": "Nmap port scan detected.",
            "rule_groups": ["recon", "network_scan"],
            "mitre_id": ["T1046"],
            "mitre_technique": ["Network Service Discovery"],
            "mitre_tactic": ["Discovery"],
            "full_log": "SURICATA ALERT: ET SCAN Nmap Scripting Engine User-Agent Detected",
            "location": "suricata",
            "data": {}
        },
        {
            "id": "SIM-003",
            "timestamp": datetime.now().isoformat(),
            "agent_name": "dockerserver",
            "agent_ip": "172.16.1.30",
            "rule_id": "533",
            "rule_level": 7,
            "rule_description": "Listened ports status changed (new port opened or closed).",
            "rule_groups": ["ossec"],
            "mitre_id": [],
            "mitre_technique": [],
            "mitre_tactic": [],
            "full_log": "ossec: output: netstat: tcp 0.0.0.0:5001 0.0.0.0:* LISTEN",
            "location": "netstat listening ports",
            "data": {}
        },
        {
            "id": "SIM-004",
            "timestamp": datetime.now().isoformat(),
            "agent_name": "msh-cyber",
            "agent_ip": "172.16.1.1",
            "rule_id": "510",
            "rule_level": 7,
            "rule_description": "Host-based anomaly detection event (rootcheck).",
            "rule_groups": ["ossec", "rootcheck"],
            "mitre_id": ["T1059"],
            "mitre_technique": ["Command and Scripting Interpreter"],
            "mitre_tactic": ["Execution"],
            "full_log": "Trojaned version of file '/bin/diff' detected.",
            "location": "rootcheck",
            "data": {}
        },
        {
            "id": "SIM-005",
            "timestamp": datetime.now().isoformat(),
            "agent_name": "gitserver",
            "agent_ip": "172.16.1.20",
            "rule_id": "5501",
            "rule_level": 3,
            "rule_description": "PAM: Login session opened for gitlab-runner.",
            "rule_groups": ["pam", "authentication_success"],
            "mitre_id": ["T1078"],
            "mitre_technique": ["Valid Accounts"],
            "mitre_tactic": ["Defense Evasion", "Persistence"],
            "full_log": "pam_unix(su:session): session opened for user gitlab-runner(uid=990) by (uid=0)",
            "location": "/var/log/auth.log",
            "data": {}
        }
    ]

if __name__ == "__main__":
    print("=== Test alertes simulées ===")
    alerts = get_simulated_alerts()
    for a in alerts:
        print(f"[{a['rule_level']}] {a['agent_name']} — {a['rule_description']}")
