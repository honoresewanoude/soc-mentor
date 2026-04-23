FROM python:3.11-slim

WORKDIR /app

# 1. Install system dependencies
RUN apt-get update && apt-get install -y \
    openssh-client \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 2. OPTIMISATION CRITIQUE : Forcer Torch en version CPU avant le reste
# Cela évite de télécharger 4Go de drivers NVIDIA inutiles dans ton SOC
RUN pip install --no-cache-dir torch==2.2.1+cpu --extra-index-url https://download.pytorch.org/whl/cpu

# 3. Install Python dependencies (le reste de ton requirements.txt)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copy application files
COPY app.py .
COPY config.py .
COPY parser.py .
COPY mitre_kb.py .
COPY llm_engine.py .
# Ajoute le nouveau fichier RAG s'il n'y est pas
COPY rag_engine.py . 
COPY templates/ templates/
COPY data/ data/

# Port exposé
EXPOSE 5001

# Variable d'environnement requise
ENV ANTHROPIC_API_KEY=""

CMD ["python", "app.py"]
