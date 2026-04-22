import anthropic
from config import ANTHROPIC_API_KEY, MODEL, MAX_TOKENS
from mitre_kb import get_mitre_context

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

SYSTEM_PROMPT = """Tu es un analyste SOC senior avec 10 ans d'expérience.
Tu reçois une alerte de sécurité avec son contexte MITRE ATT&CK.
Tu dois générer une fiche d'investigation structurée en français pour aider un analyste N1/N2.
Sois précis, concis et actionnable. Utilise uniquement les informations fournies."""

def build_prompt(alert, mitre_context):
    """
    Construit le prompt enrichi avec l'alerte et le contexte MITRE.
    """
    mitre_text = ""
    for m in mitre_context:
        mitre_text += f"""
Technique : {m.get('id', 'N/A')} — {m['name']}
Tactique   : {m['tactic']}
Description: {m['description']}
Détection  : {m['detection']}
Mitigation : {m['mitigation']}
IoC types  : {', '.join(m['ioc'])}
"""

    return f"""
ALERTE DE SÉCURITÉ
==================
ID         : {alert['id']}
Timestamp  : {alert['timestamp']}
Agent      : {alert['agent_name']} ({alert['agent_ip']})
Règle ID   : {alert['rule_id']}
Niveau     : {alert['rule_level']}/15
Description: {alert['rule_description']}
Groupes    : {', '.join(alert['rule_groups'])}
Log brut   : {alert['full_log']}

CONTEXTE MITRE ATT&CK
=====================
{mitre_text if mitre_text else 'Aucun TTP MITRE identifié'}

INSTRUCTIONS
============
Génère une fiche d'investigation SOC avec exactement cette structure :

RÉSUMÉ
------
[2-3 phrases résumant l'incident]

NIVEAU DE CRITICITÉ
-------------------
[CRITIQUE / ÉLEVÉ / MOYEN / FAIBLE] — [justification en 1 phrase]

TTP MITRE IMPLIQUÉS
-------------------
[Liste des techniques avec leur signification]

INDICATEURS CLÉS À VÉRIFIER
-----------------------------
[Liste de 3-5 éléments concrets à vérifier]

ACTIONS IMMÉDIATES (N1)
------------------------
[Liste numérotée de 3-5 actions à faire maintenant]

CONDITIONS D'ESCALADE VERS N2
-------------------------------
[Liste de 3 conditions qui nécessitent d'escalader]

COMMANDES D'INVESTIGATION
--------------------------
[2-3 commandes Linux/shell utiles pour investiguer]
"""

def analyze_alert(alert):
    """
    Analyse une alerte et retourne la fiche réflexe générée par Claude.
    """
    try:
        mitre_context = get_mitre_context(alert.get("mitre_id", []))
        prompt = build_prompt(alert, mitre_context)

        message = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        return {
            "success": True,
            "alert_id": alert["id"],
            "agent": alert["agent_name"],
            "rule_description": alert["rule_description"],
            "rule_level": alert["rule_level"],
            "fiche": message.content[0].text,
            "tokens_used": message.usage.input_tokens + message.usage.output_tokens
        }

    except Exception as e:
        return {
            "success": False,
            "alert_id": alert.get("id", "N/A"),
            "error": str(e),
            "fiche": None
        }

if __name__ == "__main__":
    from parser import get_simulated_alerts
    print("=== Test LLM Engine ===")
    alerts = get_simulated_alerts()
    result = analyze_alert(alerts[0])
    if result["success"]:
        print(f"Tokens utilisés : {result['tokens_used']}")
        print("\n" + result["fiche"])
    else:
        print(f"Erreur : {result['error']}")
