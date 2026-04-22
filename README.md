# 🛡️ SOC Mentor - AI-Powered SOC Investigation Assistant

> Agent IA d'aide à l'investigation d'alertes SOC - Powered by Claude AI · MITRE ATT&CK · Wazuh SIEM

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-green?style=flat-square&logo=flask)
![Claude AI](https://img.shields.io/badge/Claude-AI-orange?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=flat-square&logo=docker)

##  Présentation

SOC Mentor est un outil d'aide à l'investigation d'alertes de sécurité conçu pour les analystes SOC N1/N2. Il reçoit des alertes depuis Wazuh SIEM, les enrichit avec le contexte MITRE ATT&CK, et génère automatiquement une fiche d'investigation structurée via l'API Claude (Anthropic).

### Ce que fait SOC Mentor :
- 📥 **Ingestion d'alertes** : depuis Wazuh SIEM (live) ou alertes simulées (tests)
- 🔍 **Enrichissement MITRE** : mapping automatique des TTP ATT&CK
- 🤖 **Analyse IA** : Claude génère une fiche réflexe complète en français
- 📋 **Fiche d'investigation** : résumé, criticité, actions N1, escalade N2, commandes Linux
- 🚀 **Déploiement CI/CD** : pipeline GitLab avec Bandit + Docker + Ansible

##  Architecture

```
Alertes Wazuh (JSON)
        │
        ▼
parser.py ──── Extraction des champs clés
        │
        ▼
mitre_kb.py ── Enrichissement contexte MITRE ATT&CK
        │
        ▼
llm_engine.py ─ Appel API Claude (Anthropic)
        │
        ▼
app.py ──────── Dashboard Flask (port 5001)
        │
        ▼
Fiche d'investigation structurée
```

##  Installation

### Prérequis
- Python 3.11+
- Clé API Anthropic (`console.anthropic.com`)
- Docker (optionnel)
- Wazuh SIEM (optionnel - mode simulé disponible)

### Installation locale

```bash
# Cloner le repo
git clone https://github.com/honoresewanoude/soc-mentor.git
cd soc-mentor

# Installer les dépendances
pip3 install -r requirements.txt

# Configurer la clé API
cp .env.example .env
# Éditer .env et ajouter votre clé Anthropic

# Lancer l'application
python3 app.py
```

Accéder au dashboard : `http://localhost:5001`

### Déploiement Docker

```bash
docker build -t soc-mentor .
docker run -d -p 5001:5001 -e ANTHROPIC_API_KEY=sk-ant-... soc-mentor
```

##  Structure du projet

```
soc-mentor/
├── app.py              # Serveur Flask - routes API + dashboard
├── parser.py           # Parser d'alertes Wazuh + alertes simulées
├── mitre_kb.py         # Base de connaissances MITRE ATT&CK locale
├── llm_engine.py       # Moteur LLM - appels API Claude
├── config.py           # Configuration centralisée
├── templates/
│   └── index.html      # Dashboard web
├── data/               # Données statiques
├── ansible/
│   ├── deploy.yml      # Playbook de déploiement
│   └── inventory.ini   # Serveurs cibles
├── .gitlab-ci.yml      # Pipeline CI/CD (Bandit + Docker + Ansible)
├── Dockerfile          # Image Docker
├── requirements.txt    # Dépendances Python
├── .env.example        # Template configuration (sans secrets)
└── README.md
```

##  Pipeline DevSecOps

Le projet intègre un pipeline CI/CD GitLab en 3 stages :

| Stage | Outil | Action |
|-------|-------|--------|
| **security** | Bandit | Analyse statique du code Python - bloque si vulnérabilité HIGH |
| **build** | Docker | Construction de l'image `soc-mentor:latest` |
| **deploy** | Ansible | Déploiement sur serveur de production via SSH |

##  Exemple de fiche générée

```
FICHE D'INVESTIGATION SOC - SIM-001


RÉSUMÉ
Tentative de brute force SSH détectée sur msh-cyber (172.16.1.1)
ciblant le compte root depuis 172.16.228.130. Pattern T1110.

NIVEAU DE CRITICITÉ
ÉLEVÉ - Accès root potentiellement compromis.

TTP MITRE IMPLIQUÉS
- T1110 - Brute Force (Credential Access)
- T1021.004 - SSH (Lateral Movement)

ACTIONS IMMÉDIATES (N1)
1. Vérifier les sessions actives : w && ss -tunapl | grep :22
2. Bloquer l'IP source dans le firewall
3. Auditer /var/log/auth.log
...
```

##  Auteur

**Honoré Sèwanoudé MITCHOZOUNNOU** - Futur ingénieur ESIR Rennes (Cybersécurité & Cloud)
- GitHub : [honoresewanoude](https://github.com/honoresewanoude)
- Portfolio : [honoresewanoude.github.io](https://honoresewanoude.github.io)
- Email : honoresewanoude@gmail.com

---

*Projet réalisé dans le cadre d'un home lab cybersécurité - Avril 2026*
