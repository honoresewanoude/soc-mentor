FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY config.py .
COPY parser.py .
COPY mitre_kb.py .
COPY llm_engine.py .
COPY templates/ templates/
COPY data/ data/

# Port exposé
EXPOSE 5001

# Variable d'environnement requise
ENV ANTHROPIC_API_KEY=""

CMD ["python", "app.py"]
