FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    openssh-client \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Installation des requirements de base
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# CORRECTIF FINAL : On force la mise à jour APRES les requirements
# On règle NumPy et Httpx d'un coup
RUN pip install --no-cache-dir torch==2.2.1+cpu --extra-index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir "numpy<2.0.0" "httpx>=0.27.0" "httpcore>=1.0.0"

COPY app.py config.py parser.py mitre_kb.py llm_engine.py rag_engine.py ./
COPY templates/ templates/
COPY data/ data/

EXPOSE 5001
ENV ANTHROPIC_API_KEY=""

CMD ["python", "app.py"]
