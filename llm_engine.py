import anthropic
import os
from config import ANTHROPIC_API_KEY, MODEL, MAX_TOKENS
from rag_engine import retrieve_mitre_context

# Initialisation du client Anthropic
client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

SYSTEM_PROMPT = """Tu es un analyste SOC senior (Expert Incident Response).
Tu reçois une alerte technique de Wazuh enrichie par un moteur RAG (MITRE ATT&CK).
Ton rôle est de transformer ces données brutes en une fiche d'investigation actionnable.
Sois précis, utilise un ton professionnel et structure ta réponse en Markdown."""

def build_prompt(alert, mitre_context):
    """
    Assemble l'alerte et le contexte récupéré par ChromaDB pour créer le prompt final.
    """
    # Formatage du contexte MITRE récupéré par le RAG
    mitre_text = ""
    if mitre_context:
        for m in mitre_context:
            mitre_text += f"\n- TECHNIQUE {m['id']} : {m['text']}"
    else:
        mitre_text = "Aucun contexte spécifique trouvé dans la base de connaissances."

    return f"""
### DONNÉES DE L'ALERTE
- **Description** : {alert.get('rule_description', 'N/A')}
- **Niveau Wazuh** : {alert.get('rule_level', 'N/A')}
- **Agent** : {alert.get('agent_name', 'Inconnu')}
- **Log Complet** : `{alert.get('full_log', 'N/A')}`

### CONTEXTE MITRE ATT&CK (Récupéré via RAG)
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
    """
    Fonction principale appelée par app.py pour obtenir l'analyse de l'IA.
    """
    try:
        # 1. On interroge le moteur RAG pour avoir les techniques MITRE proches
        mitre_context = retrieve_mitre_context(alert)
        
        # 2. On construit le message enrichi
        prompt_content = build_prompt(alert, mitre_context)

        # 3. Envoi à Claude
        message = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": prompt_content}
            ]
        )

        return {
            "success": True,
            "fiche": message.content[0].text,
            "tokens_used": message.usage.input_tokens + message.usage.output_tokens,
            "mitre_found": [m['id'] for m in mitre_context]
        }

    except Exception as e:
        print(f"Erreur LLM Engine : {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "fiche": "Désolé, l'analyse automatique n'est pas disponible pour le moment."
        }

# Bloc de test rapide
if __name__ == "__main__":
    test_alert = {
        "rule_description": "sshd: repeated authentication failures",
        "full_log": "Jan 10 10:00:01 kali sshd[1234]: Failed password for root from 192.168.1.50 port 54321 ssh2",
        "rule_level": 10,
        "agent_name": "serveur-prod"
    }
    print("Test de l'analyse avec RAG en cours...")
    result = analyze_alert(test_alert)
    if result["success"]:
        print(f"Succès ! Techniques identifiées : {result['mitre_found']}")
        print("-" * 30)
        print(result["fiche"])
