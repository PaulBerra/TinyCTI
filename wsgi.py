#!/usr/bin/env python3
"""
TinyCTI WSGI Application pour Gunicorn
Permet de lancer l'interface web TinyCTI avec Gunicorn pour la production

Usage:
    gunicorn -c gunicorn.conf.py wsgi:app
    gunicorn --bind 0.0.0.0:5000 --workers 2 wsgi:app
"""

import os
import sys
import logging
from pathlib import Path

# Ajoute le répertoire courant au PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent))

try:
    from tinycti import TinyCTI, TinyCTIAPI
except ImportError as e:
    print(f"Erreur import TinyCTI: {e}")
    print("Assurez-vous que tinycti.py est dans le même répertoire")
    sys.exit(1)

# Configuration
CONFIG_FILE = os.environ.get("TINYCTI_CONFIG", "config.yaml")
API_HOST = os.environ.get("TINYCTI_API_HOST", "127.0.0.1")
API_PORT = int(os.environ.get("TINYCTI_API_PORT", "5000"))

# Logger pour WSGI
logger = logging.getLogger("tinycti.wsgi")


def create_app():
    """Crée l'application WSGI TinyCTI"""
    try:
        # Initialise TinyCTI
        tinycti = TinyCTI(CONFIG_FILE)

        # Crée l'API
        api = TinyCTIAPI(tinycti, API_HOST, API_PORT)

        logger.info(f"Application TinyCTI WSGI créée avec config: {CONFIG_FILE}")

        return api.app

    except Exception as e:
        logger.error(f"Erreur création application WSGI: {e}")
        raise


# Crée l'application pour Gunicorn
app = create_app()

if __name__ == "__main__":
    # Test en mode dev
    app.run(host=API_HOST, port=API_PORT, debug=True)
