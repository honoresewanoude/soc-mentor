FROM python:3.11-slim

WORKDIR /app

# Dépendances système
RUN apt-get update && apt-get install -y \
    openssh-client \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Installer torch CPU (avant le reste pour éviter conflits lourds)
RUN pip install --no-cache-dir torch==2.2.1+cpu \
    --extra-index-url https://download.pytorch.org/whl/cpu

# Copier les requirements
COPY requirements.txt .

# Installer les dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code
COPY . .

# Créer le dossier pour la clé SSH (montée via volume)
RUN mkdir -p /app/ssh

EXPOSE 5001

# Variables d'environnement (à surcharger via .env ou docker-compose)
ENV ANTHROPIC_API_KEY=""
ENV SSH_KEY_PATH="/app/ssh/id_rsa"
ENV WAZUH_HOST="172.16.1.10"
ENV WAZUH_SSH_USER="msh"
ENV APP_HOST="0.0.0.0"
ENV APP_PORT="5001"

CMD ["python", "app.py"]
