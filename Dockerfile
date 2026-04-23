FROM python:3.11-slim

WORKDIR /app

# 1. Install system dependencies
RUN apt-get update && apt-get install -y \
    openssh-client \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 2. OPTIMISATION ET CORRECTIFS (Taille + Compatibilité NumPy)
# On force Torch CPU pour gagner 4 Go
RUN pip install --no-cache-dir torch==2.2.1+cpu --extra-index-url https://download.pytorch.org/whl/cpu
# On force NumPy < 2.0 pour éviter le crash de ChromaDB (l'AttributeError : np.float_)
RUN pip install --no-cache-dir "numpy<2.0.0"

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
