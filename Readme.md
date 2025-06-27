# TinyCTI

A tiny and efficient CTI Framework


##  Monitoring et Logs

### Surveillance du Daemon

```bash
# Statut en temps réel
python tinycti.py --status

# Exemple de sortie:
# === Statut du Planificateur TinyCTI ===
# Tâches totales: 5
# Tâches en cours: 1
# Tâches prêtes: 2
# Prochaine exécution: 2025-06-27 22:15:30
# 
# Détail des tâches:
#   URLhaus_URLs:  EN ATTENTE
#     Priorité: 1
#     Prochaine exécution: dans 1205s
#   ThreatAPI:  EN COURS
#     Priorité: 4
```

### Analyse des logs du daemon

```bash
# Suivre les logs en temps réel
tail -f tinycti.log

# Statistiques du daemon
grep "Statistiques du daemon" tinycti.log | tail -1

# Erreurs de flux spécifiques  
grep "Erreur pour.*URLhaus" tinycti.log

# Taux de réussite global
grep "Taux de réussite" tinycti.log | tail -5
```

### Métriques importantes

Le daemon affiche périodiquement ses statistiques :

- **Uptime** : Temps de fonctionnement depuis le démarrage
- **Exécutions totales** : Nombre de collectes effectuées

# TinyCTI - Framework Modulaire Léger de Collecte d'IOCs

TinyCTI est un framework modulaire et léger pour collecter des indicateurs de compromission (IOCs) depuis différentes sources et les organiser par type et niveau de rétention. Conçu pour être simple d'utilisation tout en offrant une architecture robuste et extensible.

##  Installation Rapide

### Prérequis
- Python 3.7+
- pip

### Installation des dépendances

```bash
# Créer un environnement virtuel (recommandé)
python3 -m venv tinycti-env
source tinycti-env/bin/activate  # Linux/Mac
# ou
tinycti-env\Scripts\activate     # Windows

# Installer les dépendances
pip install requests feedparser iocextract stix2 taxii2-client pyyaml cerberus
```

### Installation TinyCTI

```bash
# Télécharger les fichiers
wget https://raw.githubusercontent.com/example/tinycti/main/tinycti.py
wget https://raw.githubusercontent.com/example/tinycti/main/config.yaml
chmod +x tinycti.py
```

##  Configuration

Le framework utilise un fichier YAML pour configurer les flux de données. Éditez `config.yaml` :

### Types de flux supportés

#### 1. **Flux Texte (`text`)**
Une IOC par ligne, commentaires supportés avec `#`.

```yaml
- name: "URLhaus_URLs"
  type: "text"
  url: "https://urlhaus.abuse.ch/downloads/text/"
  retention: "live"
  enabled: true
```

#### 2. **Flux CSV (`csv`)**
Fichiers CSV avec IOCs dans une colonne spécifique.

```yaml
- name: "MalwareHashes"
  type: "csv"
  url: "https://example.com/malware.csv"
  delimiter: ","
  column: "sha256"        # Nom de colonne
  has_header: true
  retention: "chaud"
```

#### 3. **APIs JSON (`json`)**
APIs REST retournant du JSON structuré.

```yaml
- name: "ThreatAPI"
  type: "json"
  url: "https://api.example.com/indicators"
  api_keys:
    - "primary-key"
    - "backup-key"        # Rotation automatique
  json_path: ["data", "indicators"]
  retention: "chaud"
```

#### 4. **STIX 2.x (`stix`)**
Bundles STIX 2.x avec indicateurs structurés.

```yaml
- name: "STIX_Feed"
  type: "stix"
  url: "https://example.com/stix-bundle.json"
  retention: "tiede"
```

#### 5. **TAXII 2.x (`taxii`)**
Serveurs TAXII pour threat intelligence.

```yaml
- name: "TAXII_Server"
  type: "taxii"
  url: "https://taxii.example.com/api/"
  collection_id: "indicators"
  api_keys: ["your-key"]
  limit: 1000
```

#### 6. **Flux RSS (`rss`)**
Flux RSS avec IOCs dans le contenu.

```yaml
- name: "Security_Blog"
  type: "rss"
  url: "https://blog.example.com/feed.xml"
  max_entries: 50
  retention: "froid"
```

### Flux CSV robustes

Les flux CSV peuvent être complexes. TinyCTI offre des outils pour les analyser :

```bash
# Analyse un flux CSV pour suggérer la meilleure configuration
python tinycti.py --analyze-csv URLhaus_CSV

# Sortie exemple:
# === Analyse de la Structure CSV ===
# Lignes analysées: 100
# Délimiteur: ','
# Colonnes: 3-8
# Structure cohérente: False
# 
# Analyse des colonnes:
#   Colonne 2 ('url'): 95% IOCs détectés
#   Colonne 3 ('status'): 0% IOCs détectés
# 
# === Recommandations ===
# • Colonne recommandée: 2 ('url') - 95.0% d'IOCs
# • Structure incohérente: considérez skip_malformed_lines: true
```

Configuration CSV avancée :

```yaml
- name: "Complex_CSV"
  type: "csv"
  url: "https://example.com/data.csv"
  column: "indicator"           # Par nom plutôt qu'index
  auto_detect_column: true      # Auto-détection si incertain
  skip_malformed_lines: true    # Ignore les lignes incomplètes
  min_columns: 3                # Minimum de colonnes requis
```

### Niveaux de rétention

- **`live`** : IOCs très récents (< 24h) - High priority
- **`chaud`** : IOCs récents (1-7 jours) - Medium priority  
- **`tiede`** : IOCs anciens (semaines) - Low priority
- **`froid`** : IOCs archivés (mois/années) - Historical

##  Utilisation

### Modes d'exécution

TinyCTI peut fonctionner de deux façons :

#### 1. **Mode One-Shot** (par défaut)
Exécute une collecte unique et se termine.

```bash
# Exécution standard
python tinycti.py

# Configuration personnalisée  
python tinycti.py -c my-config.yaml

# Mode verbeux
python tinycti.py -v

# Mode debug complet
python tinycti.py --debug

# Force le mode one-shot même si daemon configuré
python tinycti.py --once
```

#### 2. **Mode Daemon** (nouveau !)
Tourne en permanence avec planification automatique des flux.

```bash
# Mode daemon avec planification
python tinycti.py --daemon

# ou avec config spécifique
python tinycti.py -d -c production-config.yaml

# Vérifier le statut du planificateur
python tinycti.py --status
```

### Configuration du Mode Daemon

```yaml
# Activation du daemon dans config.yaml
daemon:
  enabled: true                     # Active le mode daemon par défaut
  default_schedule: "1h"            # Planification par défaut
  check_interval: "30s"             # Fréquence de vérification  
  max_concurrent_feeds: 3           # Max flux simultanés
```

### Planification par Flux

Chaque flux peut avoir sa propre planification :

```yaml
feeds:
  # Flux critique - très fréquent
  - name: "Critical_IPs"
    type: "text"
    url: "https://critical.source.com/ips.txt"
    schedule: "5m"                  # Toutes les 5 minutes
    priority: 1                     # Haute priorité
    rate_limit: 0                   # Pas de limitation
    
  # API externe - respecte les limites
  - name: "External_API"
    type: "json"
    url: "https://api.external.com/threats"
    schedule: "6h"                  # 4 fois par jour maximum
    priority: 5                     # Priorité moyenne
    rate_limit: 60                  # Attente 1min entre requêtes
    
  # Archive - peu fréquent
  - name: "Historical_Data"
    type: "csv"
    url: "https://archive.com/data.csv"
    schedule: "1d"                  # Une fois par jour
    priority: 9                     # Basse priorité
```

### Formats de Planification

- **Secondes** : `30s`, `120s`
- **Minutes** : `5m`, `30m`, `45m`  
- **Heures** : `1h`, `2h`, `6h`, `12h`
- **Jours** : `1d`, `7d`

### Gestion des Priorités

- **1-2** : Critique (sources internes, IOCs actifs)
- **3-5** : Normal (sources publiques fiables)
- **6-8** : Bas (RSS, données complémentaires)
- **9-10** : Archive (données historiques)

### Exécution automatisée

#### Service systemd (Linux)

```ini
# /etc/systemd/system/tinycti.service
[Unit]
Description=TinyCTI Threat Intelligence Collector
After=network.target

[Service]
Type=simple
User=tinycti
Group=tinycti
WorkingDirectory=/opt/tinycti
ExecStart=/opt/tinycti/venv/bin/python tinycti.py --daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Installation et démarrage
sudo systemctl enable tinycti
sudo systemctl start tinycti
sudo systemctl status tinycti

# Logs
journalctl -u tinycti -f
```

#### Docker (mode daemon)

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY tinycti.py config.yaml ./
RUN mkdir -p iocs

CMD ["python", "tinycti.py", "--daemon"]
```

```bash
# Build et run
docker build -t tinycti .
docker run -d --name tinycti-daemon \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -v $(pwd)/iocs:/app/iocs \
  tinycti
```

##  Structure des Fichiers de Sortie

```
iocs/
├── live/
│   ├── ipv4.txt          # IPs malveillantes récentes
│   ├── domain.txt        # Domaines malveillants
│   ├── url.txt           # URLs de phishing
│   ├── hash_sha256.txt   # Hashes de malwares
│   └── ...
├── chaud/
│   ├── ipv4.txt
│   └── ...
├── tiede/
└── froid/
```

### Types d'IOCs détectés

- **IPs** : IPv4, IPv6 (excluant les plages privées)
- **Domaines** : Noms de domaine valides
- **URLs** : URLs HTTP/HTTPS
- **Hashes** : MD5, SHA1, SHA256, SHA512
- **Emails** : Adresses email

##  Sécurité et Bonnes Pratiques

### Gestion des clés API

```yaml
# Rotation automatique des clés
api_keys:
  - "primary-key-with-high-quota"
  - "backup-key-for-failover"
  - "tertiary-key-if-needed"
```

### Protection des fichiers

```bash
# Permissions restrictives
chmod 600 config.yaml
chmod 700 tinycti.py
chmod -R 750 iocs/
```

### Variables d'environnement

```bash
# Pour protéger les clés sensibles
export TINYCTI_API_KEY="your-secret-key"
```

```yaml
# Dans config.yaml
api_keys:
  - "${TINYCTI_API_KEY}"
```

##  Configuration Avancée

### Traitement parallèle

```yaml
# Accélère la collecte pour de nombreux flux
parallel_feeds: true
max_workers: 4
```

### Limites de sécurité

```yaml
# Protection contre les données malveillantes
max_file_size: 52428800    # 50MB max
security:
  max_json_depth: 10
  validate_ssl: true
```

### Gestion des erreurs

```yaml
# Retry automatique avec backoff
feeds:
  - name: "unreliable-source"
    max_retries: 5
    timeout: 60
```

##  Monitoring et Logs

### Analyse des logs

```bash
# Suivre les logs en temps réel
tail -f tinycti.log

# Statistiques d'exécution
grep "Collecte terminée" tinycti.log | tail -5

# Erreurs récentes
grep "ERROR" tinycti.log | tail -10
```

### Métriques importantes

- **Taux de réussite** des flux
- **Nombre d'IOCs** collectés par exécution
- **Taux de déduplication**
- **Temps de traitement** par flux

##  Intégration avec d'autres outils

### Import dans MISP

```bash
# Script d'intégration MISP
cat iocs/live/ipv4.txt | while read ip; do
  curl -X POST "https://misp.example.com/attributes/add" \
    -H "Authorization: YOUR-MISP-KEY" \
    -d "{\"type\":\"ip-dst\",\"value\":\"$ip\"}"
done
```

### Alimentation de firewalls

```bash
# Génération de règles iptables
echo "# IOCs TinyCTI - $(date)" > ioc-rules.txt
cat iocs/live/ipv4.txt | while read ip; do
  echo "iptables -A INPUT -s $ip -j DROP" >> ioc-rules.txt
done
```

### Intégration SIEM

```python
# Script Python pour Splunk/ELK
import json
from pathlib import Path

def export_to_json():
    iocs = []
    for file_path in Path("iocs/live").glob("*.txt"):
        ioc_type = file_path.stem
        with open(file_path) as f:
            for line in f:
                if line.strip():
                    iocs.append({
                        "value": line.strip(),
                        "type": ioc_type,
                        "source": "tinycti",
                        "timestamp": "now"
                    })
    
    with open("iocs_export.json", "w") as f:
        json.dump(iocs, f, indent=2)

export_to_json()
```

##  Dépannage

### Problèmes courants

**Erreur "Configuration invalide"**
```bash
# Vérifier la syntaxe YAML
python -c "import yaml; yaml.safe_load(open('config.yaml'))"
```

**Timeout de requêtes**
```yaml
# Augmenter les timeouts
timeout: 120
max_retries: 5
```

**Trop de doublons**
```bash
# Vider le cache de déduplication
rm iocs/iocs.db
```

**Erreurs CSV "colonne inexistante"**
```bash
# Analyser la structure du CSV
python tinycti.py --analyze-csv MonFluxCSV

# Solutions:
# 1. Utiliser le nom de colonne au lieu de l'index
column: "url"  # au lieu de column: 2

# 2. Activer l'auto-détection
auto_detect_column: true

# 3. Ignorer les lignes malformées
skip_malformed_lines: true
min_columns: 3
```

**Permissions insuffisantes**
```bash
# Corriger les permissions
chown -R tinycti:tinycti /opt/tinycti/
chmod -R 755 /opt/tinycti/
```

##  Exemples de Configuration Complète

### Configuration Minimaliste

```yaml
feeds:
  - name: "URLhaus"
    type: "text"  
    url: "https://urlhaus.abuse.ch/downloads/text/"
    retention: "live"
    enabled: true
```

### Configuration d'Entreprise

```yaml
output_dir: "/var/lib/tinycti/iocs"
parallel_feeds: true
max_workers: 8

feeds:
  # Sources publiques
  - name: "URLhaus_URLs"
    type: "text"
    url: "https://urlhaus.abuse.ch/downloads/text/"
    retention: "live"
    
  - name: "Feodo_IPs"  
    type: "text"
    url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    retention: "live"
    
  # APIs commerciales
  - name: "ThreatIntel_API"
    type: "json"
    url: "https://api.threatintel.com/v1/indicators"
    api_keys:
      - "${THREAT_API_PRIMARY}"
      - "${THREAT_API_BACKUP}"
    json_path: ["data", "indicators"]
    retention: "chaud"
    
  # Serveur TAXII interne
  - name: "Internal_TAXII"
    type: "taxii"
    url: "https://taxii.internal.com/api/"
    collection_id: "company-indicators"
    username: "${TAXII_USER}"
    password: "${TAXII_PASS}"
    retention: "tiede"

retention_policy:
  live_to_chaud: "6h"      # Rotation rapide
  chaud_to_tiede: "24h"
  tiede_to_froid: "7d"
  froid_retention: "180d"
```

##  Roadmap

- [ ] Interface web de configuration
- [ ] Connecteurs pour bases de données
- [ ] Export vers formats multiples (STIX, MISP, CSV)
- [ ] Métriques Prometheus
- [ ] API REST pour consultation
- [ ] Clustering pour haute disponibilité

## 🤝 Contribution

TinyCTI est conçu pour être facilement extensible. Pour ajouter un nouveau type de flux :

1. Créer une classe héritant de `BasePlugin`
2. Implémenter `collect()` et `parse()`
3. Enregistrer le plugin dans `PluginManager`

##  Licence

MIT License - Voir le fichier LICENSE pour plus de détails.
