import json
import requests
import urllib3
import os
from datetime import datetime, timezone
from dotenv import load_dotenv
load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



# Normalisation d'une alerte brute OpenSearch → dict SOC Mentor


def parse_wazuh_alert(hit: dict) -> dict:
    """
    Transforme un hit OpenSearch (_source) en dict structuré pour SOC Mentor.
    Compatible avec les alertes simulées (pas de _source).
    """
    src = hit.get("_source", hit)

    return {
        "id": hit.get("_id", src.get("id", f"WZ-{datetime.now().strftime('%H%M%S')}")),
        "timestamp": src.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "agent_name": src.get("agent", {}).get("name", "unknown"),
        "agent_ip": src.get("agent", {}).get("ip", "unknown"),
        "rule_id": src.get("rule", {}).get("id", "N/A"),
        "rule_level": int(src.get("rule", {}).get("level", 0)),
        "rule_description": src.get("rule", {}).get("description", "N/A"),
        "rule_groups": src.get("rule", {}).get("groups", []),
        "mitre_id": src.get("rule", {}).get("mitre", {}).get("id", []),
        "mitre_technique": src.get("rule", {}).get("mitre", {}).get("technique", []),
        "mitre_tactic": src.get("rule", {}).get("mitre", {}).get("tactic", []),
        "full_log": src.get("full_log", ""),
        "location": src.get("location", ""),
        "data": src.get("data", {}),
        "ingestion_source": "opensearch",
    }



# Récupération des alertes via OpenSearch


def get_wazuh_alerts_api(
    opensearch_url: str = None,
    user: str = None,
    password: str = None,
    limit: int = 20,
    min_level: int = 3,
    verify_ssl: bool = False,
) -> list[dict]:
    """
    Récupère les alertes Wazuh depuis OpenSearch (index wazuh-alerts-4.x-*).

    Variables d'environnement :
        OPENSEARCH_URL      — ex: https://localhost:9200  (tunnel SSH recommandé)
        OPENSEARCH_USER     — défaut: admin
        OPENSEARCH_PASSWORD — mot de passe admin OpenSearch

    Le tunnel SSH doit être actif :
        ssh -L 9200:127.0.0.1:9200 msh@172.16.1.10 -N
    """
    base_url = opensearch_url or os.getenv("OPENSEARCH_URL", "https://localhost:9200")
    user     = user     or os.getenv("OPENSEARCH_USER", "admin")
    password = password or os.getenv("OPENSEARCH_PASSWORD", "")

    if not password:
        raise ValueError(
            "OPENSEARCH_PASSWORD manquant. Ajoutez-le dans votre .env."
        )

    index = "wazuh-alerts-4.x-*"
    url   = f"{base_url}/{index}/_search"

    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "range": {
                "rule.level": {"gte": min_level}
            }
        },
        "_source": [
            "id", "timestamp", "agent", "rule",
            "full_log", "location", "data"
        ]
    }

    print(f"[OpenSearch] Requête → {url} (limit={limit}, level>={min_level})")

    resp = requests.post(
        url,
        auth=(user, password),
        json=query,
        verify=verify_ssl,
        timeout=15,
    )

    if resp.status_code != 200:
        raise ConnectionError(
            f"Erreur OpenSearch (HTTP {resp.status_code}) : {resp.text[:300]}"
        )

    hits = resp.json().get("hits", {}).get("hits", [])
    alerts = [parse_wazuh_alert(h) for h in hits]

    print(f"[OpenSearch] {len(alerts)} alerte(s) récupérée(s).")
    return alerts



# Alertes simulées (développement sans Wazuh / sans tunnel)


def get_simulated_alerts() -> list[dict]:
    return [
        {
            "id": "SIM-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
            "data": {},
            "ingestion_source": "simulated",
        },
        {
            "id": "SIM-002",
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
            "data": {},
            "ingestion_source": "simulated",
        },
        {
            "id": "SIM-003",
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
            "data": {},
            "ingestion_source": "simulated",
        },
    ]



# Point d'entrée test


if __name__ == "__main__":
    print("=== Test SOC Mentor Parser (OpenSearch) ===\n")

    print("--- Alertes simulées ---")
    for a in get_simulated_alerts():
        print(f"  [{a['rule_level']}] {a['agent_name']} — {a['rule_description']}")

    print("\n--- Tentative OpenSearch (tunnel SSH requis) ---")
    try:
        alerts = get_wazuh_alerts_api()
        for a in alerts[:5]:
            print(f"  [{a['rule_level']}] {a['agent_name']} — {a['rule_description']}")
        if len(alerts) > 5:
            print(f"  ... et {len(alerts) - 5} autres.")
    except Exception as e:
        print(f"  OpenSearch non disponible : {e}")
        print("  → Activez le tunnel SSH ou utilisez get_simulated_alerts().")
