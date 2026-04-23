FROM python:3.11-slim

WORKDIR /app

# 1. Dépendances système
RUN apt-get update && apt-get install -y \
    openssh-client \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 2. FORCE TORCH CPU + NUMPY + HTTPX (Avant tout le reste)
# On fait ça en premier pour bloquer l'installation des versions NVIDIA lourdes
RUN pip install --no-cache-dir torch==2.2.1+cpu --extra-index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir "numpy<2.0.0" "httpx>=0.27.0" "httpcore>=1.0.0"

# 3. Installation des autres dépendances
COPY requirements.txt .
# pip ne réinstallera pas torch/numpy/httpx car ils sont déjà là
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copie des fichiers
COPY app.py config.py parser.py mitre_kb.py llm_engine.py rag_engine.py ./
COPY templates/ templates/
COPY data/ data/

EXPOSE 5001
ENV ANTHROPIC_API_KEY=""

CMD ["python", "app.py"]
