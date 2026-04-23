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

# Installer les dépendances (SANS override derrière)
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code
COPY . .

# Config
EXPOSE 5001
ENV ANTHROPIC_API_KEY=""

# Lancer l'app
CMD ["python", "app.py"]
