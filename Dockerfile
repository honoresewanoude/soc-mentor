FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y openssh-client build-essential && rm -rf /var/lib/apt/lists/*

# On installe torch-cpu d'abord pour le poids
RUN pip install --no-cache-dir torch==2.2.1+cpu --extra-index-url https://download.pytorch.org/whl/cpu

COPY requirements.txt .

# LA LIGNE MAGIQUE : On force httpx juste avant de copier le code
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -U "httpx>=0.27.0" "httpcore>=1.0.0" "numpy<2.0.0"

COPY . .

EXPOSE 5001
ENV ANTHROPIC_API_KEY=""

CMD ["python", "app.py"]
