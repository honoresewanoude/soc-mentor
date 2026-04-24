import json
import paramiko  # nosec B402
import urllib3
import os
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_wazuh_alert(alert_json):
    """
    Transforme le JSON brut de Wazuh en un dictionnaire structuré pour SOC Mentor.
    """
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


def get_wazuh_alerts_ssh(host=None, user=None, key=None, limit=20):
    """
    Récupère les alertes Wazuh via SSH.
    Toutes les valeurs sensibles sont lues depuis les variables d'environnement.
    """
    # Lecture depuis .env — aucune valeur hardcodée
    host = host or os.getenv("WAZUH_HOST", "172.16.1.10")
    user = user or os.getenv("WAZUH_USER", "msh")       # même var que dans .env
    key  = key  or os.getenv("SSH_KEY_PATH", "/app/id_rsa")  # même chemin que dans .env

    print(f"[SSH] Connexion → {user}@{host} (clé: {key})")

    # Vérification que la clé existe avant de tenter la connexion
    if not os.path.exists(key):
        msg = f"Clé SSH introuvable : {key}. Vérifiez SSH_KEY_PATH dans .env et le volume Docker."
        print(f"[!] {msg}")
        raise FileNotFoundError(msg)

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507
        client.connect(host, username=user, key_filename=key, timeout=5)

        cmd = (
            f"sudo tail -n 200 /var/ossec/logs/alerts/alerts.json 2>/dev/null "
            f"| grep '^{{' | tail -n {limit}"
        )
        stdin, stdout, stderr = client.exec_command(cmd)  # nosec B601
        output = stdout.read().decode().strip()
        err    = stderr.read().decode().strip()
        client.close()

        if err:
            print(f"[SSH] stderr: {err}")

        alerts = []
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                alerts.append(parse_wazuh_alert(raw))
            except json.JSONDecodeError:
                continue

        print(f"[SSH] {len(alerts)} alertes récupérées")
        return alerts

    except FileNotFoundError:
        raise  # re-propagé pour affichage dans l'UI
    except Exception as e:
        msg = f"Connexion SSH échouée ({user}@{host}) : {e}"
        print(f"[!] {msg}")
        raise ConnectionError(msg)


def get_simulated_alerts():
    """
    Alertes de test pour le développement local (sans Wazuh).
    """
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
        }
    ]


if __name__ == "__main__":
    print("=== Test SOC Mentor Parser ===")
    sim_alerts = get_simulated_alerts()
    for a in sim_alerts:
        print(f"[{a['rule_level']}] {a['agent_name']} — {a['rule_description']}")

    print("\n--- Tentative SSH Wazuh ---")
    try:
        ssh_alerts = get_wazuh_alerts_ssh()
        print(f"{len(ssh_alerts)} alerte(s) récupérée(s)")
    except Exception as e:
        print(f"SSH non disponible : {e}")
