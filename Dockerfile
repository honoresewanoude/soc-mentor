FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5001

ENV ANTHROPIC_API_KEY=""
ENV SSH_KEY_PATH="/app/id_rsa"
ENV WAZUH_HOST="172.16.1.10"
ENV WAZUH_USER="msh"
ENV APP_HOST="0.0.0.0"
ENV APP_PORT="5001"

CMD ["python", "app.py"]
