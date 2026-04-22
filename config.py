import os
from dotenv import load_dotenv

load_dotenv()

# API Claude
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
MODEL = "claude-haiku-4-5"
MAX_TOKENS = 1500

# Wazuh - On retire les mots de passe par défaut pour la sécurité !
WAZUH_URL = os.getenv("WAZUH_URL", "https://172.16.1.10")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")

# Configuration de l'application
APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("APP_PORT", 5001))
