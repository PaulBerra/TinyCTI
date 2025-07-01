# Guide d'Installation TinyCTI

## Prérequis système

### Système d'exploitation supportés
- Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+)
- macOS 11+
- Windows 10+ (avec WSL2 recommandé)

### Versions Python
- Python 3.9+ (recommandé: Python 3.11+)
- pip 21.0+

## Installation des dépendances système

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
sudo apt install -y sqlite3 curl wget
```

### CentOS/RHEL/Rocky Linux
```bash
sudo dnf install -y python3 python3-pip
sudo dnf install -y sqlite curl wget
```

### macOS
```bash
# Avec Homebrew
brew install python3 sqlite3
```

## Installation de TinyCTI

### Méthode 1: Installation directe
```bash
# Cloner le repository
git clone https://github.com/PaulBerra/TinyCTI.git
cd TinyCTI

# Installer les dépendances Python
pip3 install -r requirements.txt

# Ou installer manuellement les dépendances principales
pip3 install requests feedparser flask pyyaml bcrypt jwt stix2
```

### Méthode 2: Environnement virtuel (recommandé)
```bash
# Créer un environnement virtuel
python3 -m venv tinycti-env
source tinycti-env/bin/activate  # Linux/macOS
# ou tinycti-env\Scripts\activate  # Windows

# Installer les dépendances
pip install -r requirements.txt
```

### Méthode 3: Installation avec Docker
```bash
# Construire l'image Docker
docker build -t tinycti .

# Lancer le conteneur
docker run -d -p 5000:5000 -v ./config:/app/config -v ./data:/app/data tinycti
```

## Configuration initiale

### 1. Créer le fichier de configuration
```bash
cp config.yaml.example config.yaml
```

### 2. Configuration minimale
Éditer `config.yaml`:
```yaml
# Configuration minimale
output_dir: "./data"
max_file_size: 10485760  # 10MB

# Configuration de l'API
api:
  enabled: true
  host: "0.0.0.0"
  port: 5000
  auth:
    enabled: false  # Désactivé pour démarrage rapide

# Configuration des logs
logging:
  level: "INFO"
  file: "tinycti.log"

# Au moins un flux pour tester
feeds:
  - name: "test_feed"
    enabled: true
    type: "text"
    url: "https://example.com/iocs.txt"
    priority: 5
```

### 3. Créer les répertoires nécessaires
```bash
mkdir -p data/{live,chaud,tiede,froid}
mkdir -p logs
```

### 4. Initialiser la base de données
```bash
python3 tinycti.py --init-db
```

## Premier démarrage

### Mode simple (une fois)
```bash
python3 tinycti.py --config config.yaml
```

### Mode daemon
```bash
python3 tinycti.py --config config.yaml
```

### Vérification du fonctionnement
```bash
# Test de l'API
curl http://localhost:5000/api/status

# Vérification des fichiers générés
ls -la data/
```

## Configuration de production

### 1. Sécurité
```yaml
api:
  auth:
    enabled: true
    password: "votre_mot_de_passe_fort"
    rate_limit:
      enabled: true
      requests_per_minute: 60
```

### 2. Performance
```yaml
daemon:
  enabled: true
  max_concurrent_feeds: 5
  check_interval: "300s"  # 5 minutes

performance:
  memory_limit: "1GB"
  max_file_size: 52428800  # 50MB
```

### 3. Monitoring
```yaml
logging:
  level: "INFO"
  audit_enabled: true
  audit_file: "tinycti-audit.log"
  compression: true
```

## Configuration en tant que service systemd

### 1. Créer le fichier de service
```bash
sudo nano /etc/systemd/system/tinycti.service
```

```ini
[Unit]
Description=TinyCTI Threat Intelligence Platform
After=network.target

[Service]
Type=forking
User=tinycti
Group=tinycti
WorkingDirectory=/opt/tinycti
ExecStart=/opt/tinycti/tinycti-env/bin/python /opt/tinycti/tinycti.py --config /opt/tinycti/config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 2. Créer l'utilisateur dédié
```bash
sudo useradd -r -s /bin/false tinycti
sudo mkdir -p /opt/tinycti
sudo chown tinycti:tinycti /opt/tinycti
```

### 3. Activer le service
```bash
sudo systemctl daemon-reload
sudo systemctl enable tinycti
sudo systemctl start tinycti
sudo systemctl status tinycti
```

## Configuration avec reverse proxy (nginx)

### 1. Configuration nginx
```nginx
server {
    listen 80;
    server_name tinycti.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 2. SSL avec Let's Encrypt
```bash
sudo certbot --nginx -d tinycti.example.com
```

## Dépannage

### Problèmes courants

#### Erreur de permissions
```bash
# Donner les bonnes permissions
chmod +x tinycti.py
chmod -R 755 data/
```

#### Port déjà utilisé
```bash
# Changer le port dans config.yaml
api:
  port: 8080
```

#### Dépendances manquantes
```bash
# Installer toutes les dépendances optionnelles
pip3 install requests feedparser flask pyyaml bcrypt jwt stix2 cerberus
```

#### Base de données corrompue
```bash
# Réinitialiser la base de données
rm data/tinycti.db
python3 tinycti.py --init-db
```

### Logs de diagnostic
```bash
# Voir les logs en temps réel
tail -f tinycti.log

# Niveau debug
python3 tinycti.py --config config.yaml --debug
```

### Test de connectivité
```bash
# Test des endpoints API
curl -v http://localhost:5000/api/health
curl -v http://localhost:5000/api/status
```

## Mise à jour

### Version simple
```bash
git pull origin main
pip3 install -r requirements.txt --upgrade
```

### Avec sauvegarde
```bash
# Sauvegarder la configuration et les données
cp -r data/ data-backup-$(date +%Y%m%d)
cp config.yaml config.yaml.backup

# Mettre à jour
git pull origin main
pip3 install -r requirements.txt --upgrade

# Redémarrer le service
sudo systemctl restart tinycti
```

## Désinstallation

### Arrêter les services
```bash
sudo systemctl stop tinycti
sudo systemctl disable tinycti
sudo rm /etc/systemd/system/tinycti.service
```

### Supprimer les fichiers
```bash
sudo rm -rf /opt/tinycti
sudo userdel tinycti
```

### Nettoyer les dépendances (optionnel)
```bash
pip3 uninstall -r requirements.txt
```

## Support

### Fichiers de logs importants
- `tinycti.log` - Logs principaux
- `tinycti-audit.log` - Logs d'audit
- `data/tinycti.db` - Base de données SQLite

### Commandes de diagnostic
```bash
# Version et configuration
python3 tinycti.py --version
python3 tinycti.py --check-config

# Statistiques
curl http://localhost:5000/api/stats

# Santé du système
curl http://localhost:5000/api/health
```