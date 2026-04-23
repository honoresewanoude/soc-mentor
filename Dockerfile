FROM python:3.11-slim

WORKDIR /app

# 1. Install system dependencies
RUN apt-get update && apt-get install -y \
    openssh-client \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 2. OPTIMISATION ET CORRECTIFS (Taille + NumPy + Anthropic/Httpx)
RUN pip install --no-cache-dir torch==2.2.1+cpu --extra-index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir "numpy<2.0.0"
# FIX CRITIQUE : Force la mise à jour de httpx pour Anthropic
RUN pip install --no-cache-dir -U httpx httpcore

# 3. Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copy application files
COPY app.py config.py parser.py mitre_kb.py llm_engine.py rag_engine.py ./
COPY templates/ templates/
COPY data/ data/

# Port exposé
EXPOSE 5001

# Variable d'environnement requise
ENV ANTHROPIC_API_KEY=""

CMD ["python", "app.py"]
