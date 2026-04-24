# 🛡️ SOC Mentor - AI-Powered SOC Investigation Assistant

> Agent IA d'aide à l'investigation d'alertes SOC - Powered by Claude AI · MITRE ATT&CK · Wazuh SIEM

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-green?style=flat-square&logo=flask)
![Claude AI](https://img.shields.io/badge/Claude-AI-orange?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=flat-square&logo=docker)

## Présentation

SOC Mentor est un outil d'aide à l'investigation d'alertes de sécurité conçu pour les analystes SOC N1/N2. Il reçoit des alertes depuis Wazuh SIEM, les enrichit avec le contexte MITRE ATT&CK, et génère automatiquement une fiche d'investigation structurée via l'API Claude (Anthropic).

### Ce que fait SOC Mentor :
- 📥 **Ingestion d'alertes** : depuis Wazuh SIEM (live via SSH) ou alertes simulées (tests)
- 🔍 **Enrichissement MITRE** : mapping automatique des TTP ATT&CK via RAG (local) ou base intégrée (Docker)
- 🤖 **Analyse IA** : Claude génère une fiche réflexe complète en français
- 📋 **Fiche d'investigation** : résumé, criticité, vérifications prioritaires, remédiation, hunting
- 🚀 **Déploiement CI/CD** : pipeline GitLab avec Bandit + Docker + Ansible

---

## Architecture

```
Kali Linux (local)          GitLab CI/CD            Docker Server
┌─────────────────┐    push  ┌──────────────┐  ansible  ┌─────────────────┐
│  git push       │ ──────▶  │  Pipeline    │ ────────▶ │  soc-mentor     │
│  venv + RAG     │          │  build/test  │           │  :5001          │
└─────────────────┘          └──────────────┘           └─────────────────┘
                                                                │
                                                         ┌──────▼──────┐
                                                         │  Wazuh SIEM │
                                                         │  172.16.1.10│
                                                         └─────────────┘
```

```
Alertes Wazuh (JSON)
        │
        ▼
parser.py ──── Extraction des champs clés (SSH → alerts.json)
        │
        ▼
rag_engine.py - Enrichissement MITRE ATT&CK (ChromaDB - local uniquement)
        │
        ▼
llm_engine.py - Appel API Claude (Anthropic)
        │
        ▼
app.py ──────── Dashboard Flask (port 5001)
        │
        ▼
Fiche d'investigation structurée
```

**Mode Docker (production)** - RAG désactivé, fallback base MITRE intégrée (~300MB)  
**Mode local (développement)** - RAG complet avec ChromaDB + sentence-transformers (~3GB)

---

## ⚠️ Prérequis SSH - Clé ED25519 obligatoire

> La version de `cryptography` utilisée dans le conteneur Docker est **incompatible avec les clés DSA**. Vous devez utiliser une clé **ED25519** ou **RSA**.

### Générer une clé ED25519

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_soc_mentor -N ""
```

### Autoriser la clé sur le serveur Wazuh

```bash
ssh-copy-id -i ~/.ssh/id_soc_mentor.pub <WAZUH_USER>@<WAZUH_HOST>

# Tester la connexion
ssh -i ~/.ssh/id_soc_mentor <WAZUH_USER>@<WAZUH_HOST>
```

### Copier la clé dans le projet

```bash
cp ~/.ssh/id_soc_mentor ~/soc-mentor/id_rsa
```

> 💡 Le fichier `id_rsa` à la racine est dans `.gitignore` - il ne sera jamais commité.

---

## Installation locale (avec RAG complet)

### Prérequis
- Python 3.11+
- Clé API Anthropic (`console.anthropic.com`)
- Clé SSH ED25519 autorisée sur le serveur Wazuh (voir section ci-dessus)
- Wazuh SIEM (optionnel — mode simulé disponible si inaccessible)

```bash
# 1. Cloner le repo
git clone <url-du-repo>
cd soc-mentor

# 2. Créer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate

# 3. Installer les dépendances core
pip install -r requirements.txt

# 4. Installer le RAG (optionnel - nécessite ~3GB)
pip install -r requirements-rag.txt

# 5. Configurer les variables d'environnement
cp .env.example .env
nano .env
```

### Contenu du `.env` local

```env
# Claude API (obligatoire)
ANTHROPIC_API_KEY=sk-ant-votre-cle-ici

# Wazuh SSH (optionnel - alertes simulées si absent)
WAZUH_HOST=<IP-WAZUH>
WAZUH_USER=<USER-SSH-WAZUH>
SSH_KEY_PATH=/chemin/vers/votre/id_rsa

# Application
APP_HOST=0.0.0.0
APP_PORT=5001
```

```bash
# 6. Lancer
python app.py
# → http://localhost:5001
```

---

## Déploiement Docker (manuel)

```bash
docker build -t soc-mentor .
docker run -d \
  --network host \
  -v /chemin/vers/id_rsa:/app/id_rsa:ro \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  -e WAZUH_HOST=<IP-WAZUH> \
  -e WAZUH_USER=<USER-SSH> \
  -e SSH_KEY_PATH=/app/id_rsa \
  soc-mentor
```

---

## Déploiement via pipeline GitLab CI/CD

### Infrastructure requise
- **Gitserver** : GitLab + GitLab Runner (shell executor)
- **Dockerserver** : Docker installé, accessible SSH depuis le gitserver

### Étape 1 - Variable GitLab (UI)

`Settings -> CI/CD -> Variables -> Add variable`

| Key | Value | Options |
|---|---|---|
| `ANTHROPIC_API_KEY` | `sk-ant-...` | ✅ Masked, ✅ Protected |

### Étape 2 - Fichier secret sur le gitserver

```bash
# Sur le gitserver en tant que root
echo "ANTHROPIC_API_KEY=sk-ant-votre-cle" > /home/gitlab-runner/.env-soc-mentor
chmod 600 /home/gitlab-runner/.env-soc-mentor
chown gitlab-runner:gitlab-runner /home/gitlab-runner/.env-soc-mentor
```

### Étape 3 - Clé SSH ED25519 sur le gitserver

```bash
# Depuis votre machine locale
scp /chemin/vers/id_rsa <GITLAB_USER>@<GITLAB_HOST>:/tmp/wazuh_id_rsa_new

# Puis sur le gitserver
ssh <GITLAB_USER>@<GITLAB_HOST>
sudo cp /tmp/wazuh_id_rsa_new /home/gitlab-runner/.ssh/wazuh_id_rsa
sudo chmod 600 /home/gitlab-runner/.ssh/wazuh_id_rsa
sudo chown gitlab-runner:gitlab-runner /home/gitlab-runner/.ssh/wazuh_id_rsa
rm /tmp/wazuh_id_rsa_new
exit
```

> ⚠️ La clé doit être de type **ED25519** ou **RSA**. Une clé DSA provoquera une erreur `ValueError: q must be exactly 160, 224, or 256 bits long` au moment de la connexion SSH dans le conteneur.

### Étape 4 - Adapter l'inventaire Ansible

```ini
# ansible/inventory.ini
[docker_server]
<IP-DOCKER-SERVER> ansible_user=<USER> ansible_ssh_private_key_file=/home/gitlab-runner/.ssh/id_rsa
```

### Étape 5 - Pusher

```bash
git add .
git commit -m "deploy: initial"
git push
```

Le pipeline effectue automatiquement :

| Stage | Outil | Action |
|---|---|---|
| **security** | Bandit | Analyse statique Python - bloque si vulnérabilité HIGH |
| **build** | Docker | Construction de l'image `soc-mentor:latest` |
| **deploy** | Ansible | Déploiement sur dockerserver via SSH |

---

## Fonctionnement

### Mode Wazuh Live
- Connexion SSH vers le serveur Wazuh
- Lecture de `/var/ossec/logs/alerts/alerts.json`
- Affichage des 20 dernières alertes
- Fallback automatique sur alertes simulées si Wazuh inaccessible

### Analyse Claude AI
- Clic sur **"Analyser avec Claude AI"**
- Enrichissement MITRE ATT&CK (RAG ChromaDB en local, base intégrée en Docker)
- Génération d'une fiche d'investigation structurée

### Exemple de fiche générée

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

VÉRIFICATIONS PRIORITAIRES
1. Vérifier les sessions actives : w && ss -tunapl | grep :22
2. Bloquer l'IP source dans le firewall
3. Auditer /var/log/auth.log

PLAN DE REMÉDIATION
- Activer fail2ban avec seuil 5 tentatives
- Forcer l'authentification par clé SSH uniquement
- Activer MFA sur les accès SSH critiques

REQUÊTE DE CHASSE (Hunting)
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn
```

---

## Structure du projet

```
soc-mentor/
├── app.py                # API Flask + routes
├── config.py             # Configuration centralisée
├── parser.py             # Parseur alertes Wazuh (SSH) + simulées
├── llm_engine.py         # Moteur Claude AI (RAG dynamique)
├── rag_engine.py         # RAG ChromaDB + MITRE ATT&CK (local)
├── mitre_kb.py           # Base de connaissances MITRE
├── requirements.txt      # Dépendances production (Docker)
├── requirements-rag.txt  # Dépendances RAG (local uniquement ~3GB)
├── Dockerfile
├── .env.example          # Template configuration (sans secrets)
├── .gitlab-ci.yml        # Pipeline CI/CD
├── ansible/
│   ├── deploy.yml        # Playbook de déploiement
│   └── inventory.ini     # Inventaire serveurs
└── templates/
    └── index.html        # Dashboard web
```

---

## Notes techniques

**Pourquoi le RAG n'est pas dans Docker ?**  
`sentence-transformers` + `torch` représentent ~3GB de dépendances. Par contrainte d'espace disque sur l'infrastructure de lab, le RAG est désactivé en production Docker. Un fallback automatique sur une base MITRE intégrée assure la continuité du service. En local avec le venv complet, le RAG ChromaDB est actif et enrichit les analyses de manière sémantique.

**Pourquoi ED25519 et pas DSA ?**  
La bibliothèque `cryptography` (version récente) a déprécié le support DSA. Une clé DSA provoque une erreur `ValueError` dans Paramiko au moment de signer la connexion SSH. ED25519 est plus léger, plus rapide et recommandé par les bonnes pratiques actuelles.

**Sécurité**
- Aucune clé ou mot de passe dans le code ou le repo Git
- Clés SSH montées en volume read-only dans Docker
- Variables sensibles via GitLab CI/CD Variables (masked)
- Analyse statique Bandit à chaque pipeline

---

## Auteur

**Honoré Sèwanoudé MITCHOZOUNNOU** — Futur ingénieur ESIR Rennes (Cybersécurité & Réseaux)  
- Portfolio : [honoresewanoude.github.io](https://honoresewanoude.github.io)  
- Email : honoresewanoude@gmail.com

---

*Projet réalisé dans le cadre d'un home lab cybersécurité - Mars 2026*
