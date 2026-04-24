import anthropic
from config import ANTHROPIC_API_KEY, MODEL, MAX_TOKENS

# Import dynamique du RAG — fonctionne avec ou sans torch/chromadb
try:
    from rag_engine import retrieve_mitre_context
    RAG_AVAILABLE = True
    print("[LLM] RAG engine chargé (ChromaDB + sentence-transformers)")
except ImportError:
    RAG_AVAILABLE = False
    print("[LLM] RAG non disponible — fallback sur base MITRE intégrée")

# Base MITRE de fallback (utilisée si RAG non disponible en Docker)
MITRE_FALLBACK = {
    "T1110": "T1110 Brute Force Credential Access: tentatives répétées de connexion. Mitigation: MFA, fail2ban, lockout.",
    "T1046": "T1046 Network Service Discovery: scan de ports/services. Mitigation: firewall, segmentation réseau.",
    "T1078": "T1078 Valid Accounts: utilisation de comptes légitimes compromis. Mitigation: MFA, surveillance des logins.",
    "T1059": "T1059 Command Scripting: exécution de scripts malveillants. Mitigation: whitelisting, audit des processus.",
    "T1021": "T1021 Remote Services Lateral Movement SSH/RDP. Mitigation: MFA, VPN, segmentation.",
    "T1548": "T1548 Privilege Escalation sudo/setuid. Mitigation: least privilege, audit sudo.",
    "T1190": "T1190 Exploit Public Facing Application: exploitation de vulnérabilités web. Mitigation: WAF, patch management.",
    "T1562": "T1562 Impair Defenses: désactivation des outils de sécurité. Mitigation: protéger les services de sécurité.",
    "T1070": "T1070 Indicator Removal: effacement des logs. Mitigation: centralisation des logs, SIEM.",
    "T1003": "T1003 OS Credential Dumping: extraction de credentials mémoire. Mitigation: credential guard, PAW.",
    "T1136": "T1136 Create Account: création de comptes persistants. Mitigation: surveillance création comptes.",
}

def retrieve_mitre_fallback(alert):
    """Contexte MITRE depuis la base intégrée (sans RAG)."""
    results = []
    for mitre_id in alert.get("mitre_id", []):
        base_id = mitre_id.split(".")[0]
        if base_id in MITRE_FALLBACK:
            results.append({"id": base_id, "text": MITRE_FALLBACK[base_id]})
    if not results:
        results.append({
            "id": "GENERIC",
            "text": "Événement de sécurité non catégorisé. Investigation manuelle requise."
        })
    return results

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

SYSTEM_PROMPT = """Tu es un analyste SOC senior (Expert Incident Response).
Tu reçois une alerte technique de Wazuh enrichie par un moteur RAG (MITRE ATT&CK).
Ton rôle est de transformer ces données brutes en une fiche d'investigation actionnable.
Sois précis, utilise un ton professionnel et structure ta réponse en Markdown."""

def build_prompt(alert, mitre_context):
    mitre_text = ""
    if mitre_context:
        for m in mitre_context:
            mitre_text += f"\n- TECHNIQUE {m['id']} : {m['text']}"
    else:
        mitre_text = "Aucun contexte spécifique trouvé dans la base de connaissances."

    source = "RAG ChromaDB (sémantique)" if RAG_AVAILABLE else "Base MITRE intégrée"

    return f"""
### DONNÉES DE L'ALERTE
- **Description** : {alert.get('rule_description', 'N/A')}
- **Niveau Wazuh** : {alert.get('rule_level', 'N/A')}
- **Agent** : {alert.get('agent_name', 'Inconnu')}
- **Log Complet** : `{alert.get('full_log', 'N/A')}`

### CONTEXTE MITRE ATT&CK ({source})
{mitre_text}

---
### INSTRUCTIONS DE RÉDACTION
Génère une fiche d'investigation avec les sections suivantes :
1. **RÉSUMÉ DE L'INCIDENT** (Analyse de la menace en 2 lignes)
2. **CRITICITÉ** (Faible/Moyen/Elevé/Critique + Justification)
3. **VÉRIFICATIONS PRIORITAIRES** (3 points techniques à checker immédiatement)
4. **PLAN DE REMÉDIATION** (Actions concrètes pour stopper l'attaque)
5. **REQUÊTE DE CHASSE (Hunting)** (Exemple de commande ou log à chercher ailleurs)
"""

def analyze_alert(alert):
    try:
        # RAG complet si disponible (local), sinon base intégrée (Docker)
        if RAG_AVAILABLE:
            mitre_context = retrieve_mitre_context(alert)
        else:
            mitre_context = retrieve_mitre_fallback(alert)

        prompt_content = build_prompt(alert, mitre_context)

        message = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt_content}]
        )

        return {
            "success": True,
            "fiche": message.content[0].text,
            "tokens_used": message.usage.input_tokens + message.usage.output_tokens,
            "mitre_found": [m['id'] for m in mitre_context],
            "rag_used": RAG_AVAILABLE
        }

    except Exception as e:
        print(f"[!] Erreur LLM Engine : {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "fiche": "Désolé, l'analyse automatique n'est pas disponible pour le moment."
        }

if __name__ == "__main__":
    test_alert = {
        "rule_description": "sshd: repeated authentication failures",
        "full_log": "Jan 10 10:00:01 kali sshd[1234]: Failed password for root from 192.168.1.50 port 54321 ssh2",
        "rule_level": 10,
        "agent_name": "serveur-prod",
        "mitre_id": ["T1110"],
        "mitre_technique": ["Brute Force"]
    }
    print("Test analyse en cours...")
    result = analyze_alert(test_alert)
    if result["success"]:
        print(f"RAG utilisé : {result['rag_used']}")
        print(f"Techniques : {result['mitre_found']}")
        print(result["fiche"])
