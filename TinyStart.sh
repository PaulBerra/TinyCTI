#!/bin/bash
# Scripts de démarrage TinyCTI pour différents scénarios

# ==========================================
# Script 1: start-tinycti-daemon.sh
# Démarre TinyCTI en mode daemon avec API
# ==========================================

cat > start-tinycti-daemon.sh << 'EOF'
#!/bin/bash
# Démarrage TinyCTI en mode daemon avec API

set -e

# Configuration par défaut
TINYCTI_DIR="/opt/tinycti"
CONFIG_FILE="config.yaml"
LOG_FILE="tinycti-daemon.log"
PID_FILE="tinycti-daemon.pid"

# Variables d'environnement
export TINYCTI_CONFIG="$CONFIG_FILE"
export TINYCTI_LOG_LEVEL="INFO"

cd "$TINYCTI_DIR"

# Vérifie si déjà en cours
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "TinyCTI daemon déjà en cours (PID: $PID)"
        exit 1
    else
        rm -f "$PID_FILE"
    fi
fi

echo "Démarrage TinyCTI daemon..."
echo "Configuration: $CONFIG_FILE"
echo "Logs: $LOG_FILE"

# Lance en arrière-plan
nohup python3 tinycti.py --daemon > "$LOG_FILE" 2>&1 &
PID=$!
echo $PID > "$PID_FILE"

echo "TinyCTI daemon démarré (PID: $PID)"
echo "Pour suivre les logs: tail -f $LOG_FILE"
echo "Pour arrêter: ./stop-tinycti-daemon.sh"
EOF

chmod +x start-tinycti-daemon.sh

# ==========================================
# Script 2: stop-tinycti-daemon.sh
# Arrête le daemon TinyCTI
# ==========================================

cat > stop-tinycti-daemon.sh << 'EOF'
#!/bin/bash
# Arrêt TinyCTI daemon

PID_FILE="tinycti-daemon.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "Fichier PID non trouvé ($PID_FILE)"
    exit 1
fi

PID=$(cat "$PID_FILE")

if ! kill -0 "$PID" 2>/dev/null; then
    echo "Processus $PID non trouvé"
    rm -f "$PID_FILE"
    exit 1
fi

echo "Arrêt du daemon TinyCTI (PID: $PID)..."

# Arrêt propre avec SIGTERM
kill -TERM "$PID"

# Attend l'arrêt (max 30 secondes)
for i in {1..30}; do
    if ! kill -0 "$PID" 2>/dev/null; then
        rm -f "$PID_FILE"
        echo "TinyCTI daemon arrêté"
        exit 0
    fi
    sleep 1
done

# Force l'arrêt si nécessaire
echo "Arrêt forcé..."
kill -KILL "$PID" 2>/dev/null || true
rm -f "$PID_FILE"
echo "TinyCTI daemon arrêté (forcé)"
EOF

chmod +x stop-tinycti-daemon.sh

# ==========================================
# Script 3: start-tinycti-api.sh
# Démarre uniquement l'API avec Gunicorn
# ==========================================

cat > start-tinycti-api.sh << 'EOF'
#!/bin/bash
# Démarrage API TinyCTI avec Gunicorn

set -e

# Configuration
export TINYCTI_CONFIG="${TINYCTI_CONFIG:-config.yaml}"
export TINYCTI_BIND="${TINYCTI_BIND:-127.0.0.1:5000}"
export TINYCTI_WORKERS="${TINYCTI_WORKERS:-2}"
export TINYCTI_LOG_LEVEL="${TINYCTI_LOG_LEVEL:-info}"

echo "Démarrage API TinyCTI avec Gunicorn..."
echo "Configuration: $TINYCTI_CONFIG"
echo "Bind: $TINYCTI_BIND"
echo "Workers: $TINYCTI_WORKERS"

# Vérifie les dépendances
if ! command -v gunicorn &> /dev/null; then
    echo "Erreur: gunicorn non installé"
    echo "Installation: pip install gunicorn"
    exit 1
fi

if [ ! -f "wsgi.py" ]; then
    echo "Erreur: wsgi.py non trouvé"
    exit 1
fi

# Lance Gunicorn
exec gunicorn \
    --config gunicorn.conf.py \
    --bind "$TINYCTI_BIND" \
    --workers "$TINYCTI_WORKERS" \
    --log-level "$TINYCTI_LOG_LEVEL" \
    wsgi:app
EOF

chmod +x start-tinycti-api.sh

# ==========================================
# Script 4: tinycti-collect.sh
# Collecte manuelle one-shot
# ==========================================

cat > tinycti-collect.sh << 'EOF'
#!/bin/bash
# Collecte manuelle TinyCTI (one-shot)

set -e

CONFIG_FILE="${1:-config.yaml}"
VERBOSE="${VERBOSE:-false}"

echo "Collecte TinyCTI one-shot"
echo "Configuration: $CONFIG_FILE"

# Options
OPTS=""
if [ "$VERBOSE" = "true" ]; then
    OPTS="$OPTS -v"
fi

# Lance la collecte
python3 tinycti.py -c "$CONFIG_FILE" $OPTS --once

echo "Collecte terminée"

# Export NGFW automatique
if [ "$AUTO_EXPORT_NGFW" = "true" ]; then
    echo "Export NGFW automatique..."
    python3 tinycti.py -c "$CONFIG_FILE" --export-ngfw
    echo "Export NGFW terminé"
fi
EOF

chmod +x tinycti-collect.sh

# ==========================================
# Script 5: tinycti-status.sh
# Affiche le statut du système
# ==========================================

cat > tinycti-status.sh << 'EOF'
#!/bin/bash
# Statut TinyCTI

CONFIG_FILE="${1:-config.yaml}"

echo "=== Statut TinyCTI ==="
echo

# Statut du daemon
PID_FILE="tinycti-daemon.pid"
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "✅ Daemon TinyCTI en cours (PID: $PID)"
    else
        echo "❌ Daemon TinyCTI arrêté (PID file obsolète)"
        rm -f "$PID_FILE"
    fi
else
    echo "❌ Daemon TinyCTI non démarré"
fi

# Statut du planificateur
echo
echo "=== Planificateur ==="
python3 tinycti.py -c "$CONFIG_FILE" --status 2>/dev/null || echo "Planificateur non disponible"

# Statistiques des IOCs
echo
echo "=== Statistiques IOCs ==="
if [ -d "iocs" ]; then
    for bucket in live chaud tiede froid; do
        if [ -d "iocs/$bucket" ]; then
            echo "Bucket $bucket:"
            for file in iocs/$bucket/*.txt; do
                if [ -f "$file" ]; then
                    count=$(grep -v '^#' "$file" 2>/dev/null | wc -l)
                    basename_file=$(basename "$file" .txt)
                    printf "  %-12s: %6d IOCs\n" "$basename_file" "$count"
                fi
            done
        fi
    done
else
    echo "Répertoire iocs/ non trouvé"
fi

# Statut de l'API
echo
echo "=== API Status ==="
API_URL="http://127.0.0.1:5000/api/status"
if curl -s "$API_URL" > /dev/null 2>&1; then
    echo "✅ API accessible sur $API_URL"
    curl -s "$API_URL" | python3 -m json.tool 2>/dev/null || echo "Réponse API non JSON"
else
    echo "❌ API non accessible sur $API_URL"
fi
EOF

chmod +x tinycti-status.sh

# ==========================================
# Script 6: install-tinycti.sh
# Installation complète
# ==========================================

cat > install-tinycti.sh << 'EOF'
#!/bin/bash
# Installation TinyCTI

set -e

echo "Installation TinyCTI"
echo "==================="

# Crée l'utilisateur tinycti si nécessaire
if ! id tinycti >/dev/null 2>&1; then
    echo "Création utilisateur tinycti..."
    sudo useradd -r -s /bin/bash -d /opt/tinycti tinycti
fi

# Crée les répertoires
echo "Création des répertoires..."
sudo mkdir -p /opt/tinycti/{logs,iocs,ngfw}
sudo chown -R tinycti:tinycti /opt/tinycti

# Installe les dépendances Python
echo "Installation des dépendances Python..."
sudo -u tinycti pip3 install --user \
    requests feedparser iocextract stix2 taxii2-client \
    pyyaml cerberus flask gunicorn

# Copie les fichiers
echo "Installation des fichiers..."
sudo cp tinycti.py wsgi.py gunicorn.conf.py /opt/tinycti/
sudo cp config.yaml /opt/tinycti/
sudo cp *.sh /opt/tinycti/
sudo chown tinycti:tinycti /opt/tinycti/*

# Configuration systemd
echo "Configuration systemd..."
sudo tee /etc/systemd/system/tinycti.service > /dev/null << 'SYSTEMD_EOF'
[Unit]
Description=TinyCTI Threat Intelligence Collector
After=network.target

[Service]
Type=simple
User=tinycti
Group=tinycti
WorkingDirectory=/opt/tinycti
ExecStart=/opt/tinycti/start-tinycti-daemon.sh
ExecStop=/opt/tinycti/stop-tinycti-daemon.sh
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

sudo systemctl daemon-reload

echo "Installation terminée !"
echo
echo "Commandes utiles:"
echo "  sudo systemctl start tinycti     # Démarre le service"
echo "  sudo systemctl enable tinycti    # Active au démarrage"
echo "  sudo systemctl status tinycti    # Statut du service"
echo "  sudo -u tinycti /opt/tinycti/tinycti-status.sh  # Statut détaillé"
echo
echo "Interface web: http://localhost:5000 (si API activée)"
EOF

chmod +x install-tinycti.sh

echo "Scripts de démarrage créés:"
echo "  start-tinycti-daemon.sh   - Démarre le daemon"
echo "  stop-tinycti-daemon.sh    - Arrête le daemon"
echo "  start-tinycti-api.sh      - API avec Gunicorn"
echo "  tinycti-collect.sh        - Collecte manuelle"
echo "  tinycti-status.sh         - Affiche le statut"
echo "  install-tinycti.sh        - Installation système"