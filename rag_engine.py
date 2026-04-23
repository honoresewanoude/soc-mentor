"""
RAG Engine — Retrieval Augmented Generation pour SOC Mentor
Utilise ChromaDB + sentence-transformers pour retrouver le contexte
MITRE ATT&CK le plus pertinent avant d'appeler Claude.
"""
import os
import chromadb
from chromadb.utils import embedding_functions

# Base de connaissances MITRE ATT&CK étendue
MITRE_DOCUMENTS = [
    {"id": "T1110", "text": "T1110 Brute Force Credential Access: Adversaries use brute force techniques to gain access. Includes password guessing, spraying, credential stuffing. Detection: monitor failed logins, lockout events. Mitigation: MFA, account lockout, fail2ban."},
    {"id": "T1110.001", "text": "T1110.001 Password Guessing SSH RDP: Repeated login attempts with different passwords. Alert on >5 failures in 60 seconds from same IP. Block source IP after threshold."},
    {"id": "T1046", "text": "T1046 Network Service Discovery Nmap scan: Adversaries scan network to find open ports and services. Detection: IDS signatures for Nmap, sequential port connections. Mitigation: firewall rules, network segmentation."},
    {"id": "T1078", "text": "T1078 Valid Accounts Defense Evasion Persistence: Use of legitimate credentials for unauthorized access. Detection: login anomalies, unusual hours, new locations. Mitigation: MFA, privileged account management."},
    {"id": "T1059", "text": "T1059 Command Scripting Interpreter Execution bash python powershell: Abuse of interpreters to execute malicious commands. Detection: process creation logs, encoded commands. Mitigation: application whitelisting, script restrictions."},
    {"id": "T1055", "text": "T1055 Process Injection Defense Evasion Privilege Escalation: Injecting code into running processes. Detection: unusual process relationships, memory anomalies. Mitigation: endpoint protection, behavior monitoring."},
    {"id": "T1021", "text": "T1021 Remote Services Lateral Movement SSH RDP: Using valid accounts to connect via remote services. Detection: unusual remote logins, failed then success pattern. Mitigation: MFA, VPN, network segmentation."},
    {"id": "T1548", "text": "T1548 Abuse Elevation Control Privilege Escalation sudo: Bypassing access controls to gain elevated privileges. Detection: sudo usage logs, setuid file changes. Mitigation: least privilege, sudo monitoring."},
    {"id": "T1190", "text": "T1190 Exploit Public Facing Application Initial Access: Exploiting vulnerabilities in internet-facing applications. Detection: WAF alerts, anomalous HTTP traffic, error spikes. Mitigation: patch management, WAF, input validation."},
    {"id": "T1531", "text": "T1531 Account Access Removal Impact: Deleting accounts or changing credentials to disrupt access. Detection: account deletion events, password changes. Mitigation: privileged account monitoring, MFA."},
    {"id": "T1562", "text": "T1562 Impair Defenses Defense Evasion: Disabling security tools, logs, or defenses. Detection: service stop events, log clearing. Mitigation: protect security tools, log forwarding."},
    {"id": "T1070", "text": "T1070 Indicator Removal Defense Evasion: Clearing logs, deleting files to remove evidence. Detection: log clearing events, file deletion patterns. Mitigation: centralized logging, SIEM."},
    {"id": "T1003", "text": "T1003 OS Credential Dumping Credential Access: Extracting credentials from OS memory or files. Detection: LSASS access, SAM database reads. Mitigation: credential guard, privileged access workstations."},
    {"id": "T1136", "text": "T1136 Create Account Persistence: Creating new accounts for persistent access. Detection: new account creation events, unusual account attributes. Mitigation: account creation monitoring, privileged access management."},
    {"id": "DEFAULT", "text": "Unknown security event anomaly detection: Manual investigation required. Review full logs, correlate with other events, check for indicators of compromise. Follow incident response procedures."}
]

_collection = None

def get_collection():
    """Initialise ou retourne la collection ChromaDB."""
    global _collection
    if _collection is not None:
        return _collection

    # Utilise un modèle léger pour les embeddings
    ef = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )

    client = chromadb.Client()
    _collection = client.get_or_create_collection(
        name="mitre_attack",
        embedding_function=ef
    )

    # Peuple la collection si vide
    if _collection.count() == 0:
        print("[RAG] Initialisation de la base MITRE ATT&CK...")
        _collection.add(
            documents=[d["text"] for d in MITRE_DOCUMENTS],
            ids=[d["id"] for d in MITRE_DOCUMENTS]
        )
        print(f"[RAG] {len(MITRE_DOCUMENTS)} techniques indexées.")

    return _collection

def retrieve_mitre_context(alert, n_results=3):
    """
    Recherche les techniques MITRE les plus pertinentes pour une alerte.
    Combine la recherche sémantique avec les TTP déjà identifiés.
    """
    collection = get_collection()

    # Construit la requête depuis l'alerte
    query = f"{alert.get('rule_description', '')} {alert.get('full_log', '')} {' '.join(alert.get('mitre_technique', []))}"

    # Recherche sémantique
    results = collection.query(
        query_texts=[query],
        n_results=min(n_results, len(MITRE_DOCUMENTS))
    )

    retrieved = []
    seen_ids = set()

    # Ajoute les résultats de la recherche sémantique
    for doc, doc_id in zip(results["documents"][0], results["ids"][0]):
        if doc_id not in seen_ids:
            retrieved.append({"id": doc_id, "text": doc})
            seen_ids.add(doc_id)

    # Ajoute les TTP déjà identifiés par Wazuh
    for mitre_id in alert.get("mitre_id", []):
        base_id = mitre_id.split(".")[0]
        if base_id not in seen_ids:
            for doc in MITRE_DOCUMENTS:
                if doc["id"] == base_id:
                    retrieved.append({"id": base_id, "text": doc["text"]})
                    seen_ids.add(base_id)
                    break

    return retrieved[:5]  # Max 5 contextes

if __name__ == "__main__":
    print("=== Test RAG Engine ===")
    test_alert = {
        "rule_description": "Multiple authentication failures followed by success",
        "full_log": "sshd: authentication failure user=root rhost=172.16.228.130",
        "mitre_id": ["T1110"],
        "mitre_technique": ["Brute Force"]
    }
    context = retrieve_mitre_context(test_alert)
    print(f"\n{len(context)} contextes MITRE récupérés :")
    for c in context:
        print(f"  [{c['id']}] {c['text'][:80]}...")
