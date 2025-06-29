# Architecture Restructurée TinyCTI

## Vue d'Ensemble des 3 Systèmes

L'architecture TinyCTI a été restructurée pour séparer clairement les trois composants principaux :

### 1. 🌐 API Externe (ExternalAPIClient)
**Récupération d'IOCs depuis des APIs tierces**

- **Gestion SSL/TLS complète** : Vérification, certificats client, bundles CA personnalisés
- **Authentification avancée** : Basic, Bearer, API Key, OAuth2
- **Headers personnalisés** et User-Agent configurable
- **Retry automatique** avec backoff
- **Gestion des erreurs** spécialisée (SSL, timeout, rate limit)

#### Configuration SSL/TLS:
```yaml
feeds:
  - name: "secure_feed"
    url: "https://api.example.com/iocs"
    ssl:
      verify: true
      cert_file: "/path/to/client.crt"
      key_file: "/path/to/client.key"
      ca_bundle: "/path/to/ca-bundle.pem"
```

#### Authentification:
```yaml
    auth:
      type: "api_key"  # none, basic, bearer, api_key, oauth2
      key: "your-api-key"
      header: "X-API-Key"
    
    # OAuth2 example:
    auth:
      type: "oauth2"
      client_id: "your-client-id"
      client_secret: "your-secret"
      token_url: "https://api.example.com/oauth/token"
```

### 2. 📁 API Interne (InternalFileAPI)
**Exposition de fichiers .txt par bucket**

- **Endpoints RESTful** pour accéder aux buckets (live, chaud, tiede, froid)
- **Authentification par token** optionnelle
- **Rate limiting** configurable
- **Métadonnées de fichiers** (count, size, timestamps)
- **Format production** : un IOC par ligne, pas de test

#### Configuration:
```yaml
internal_api:
  enabled: true
  host: "127.0.0.1"
  port: 8080
  auth_token: "secure-token-here"  # Optionnel
  rate_limit: 100  # Requêtes par minute
```

#### Endpoints disponibles:
- `GET /buckets` - Liste les buckets disponibles
- `GET /bucket/{bucket}/{type}.txt` - Fichier IOCs (ex: `/bucket/live/ipv4.txt`)
- `GET /bucket/{bucket}/stats` - Statistiques du bucket

### 3. 🎛️ Interface Web de Gestion (WebManagementInterface)
**Gestion graphique du service**

- **Interface d'administration** complète
- **Gestion des feeds** : activation/désactivation, configuration
- **Monitoring en temps réel** : statistiques, logs, erreurs
- **Authentification sécurisée** : sessions, SAML, OpenID
- **Configuration production** : cookies sécurisés, CSRF protection

#### Configuration:
```yaml
api:
  enabled: true
  host: "127.0.0.1"
  port: 5000
  auth:
    enabled: true
    password: "admin-password"
```

## Flux de Données

```
[APIs Tierces] 
    ↓ (ExternalAPIClient - SSL/Auth)
[TinyCTI Core] 
    ↓ (Classification/Storage)
[Buckets: live/chaud/tiede/froid]
    ↓ (InternalFileAPI)
[Fichiers .txt exposés] → [Systèmes externes]

[WebManagementInterface] ←→ [TinyCTI Core] (Gestion/Monitoring)
```

## Intégration dans le Code

### HTTPPlugin amélioré:
```python
class HTTPPlugin(BasePlugin):
    def _make_request(self, url: str, **kwargs):
        # Utilise ExternalAPIClient pour SSL/auth robuste
        client = ExternalAPIClient(self.config)
        return client.fetch_data()
```

### Initialisation TinyCTI:
```python
# API de gestion web
if api_config.get("enabled", False):
    self.api_server = TinyCTIAPI(self, host, port)

# API interne d'exposition
self.internal_api = InternalFileAPI(self.storage, self.config)

# Démarrage en mode daemon
if self.internal_api.enabled:
    internal_api_thread = threading.Thread(target=self.internal_api.start, daemon=True)
    internal_api_thread.start()
```

## Avantages de cette Architecture

### 🔒 Sécurité Renforcée
- SSL/TLS de production avec certificats client
- Authentification OAuth2 et API keys
- Rate limiting et protection CSRF
- Isolation des composants

### 🚀 Performance Production
- Retry automatique avec backoff
- Connexions SSL optimisées
- Threading pour APIs parallèles
- Rate limiting intelligent

### 🔧 Maintenabilité
- Séparation claire des responsabilités
- Configuration centralisée
- Logs structurés par composant
- Tests unitaires par composant

### 🌐 Intégration Facilitée
- API REST standard pour fichiers
- Format .txt directement consommable
- Headers métadonnées riches
- Documentation OpenAPI générée

## Exemples d'Usage

### Récupération depuis API sécurisée:
```bash
# Configuration feed avec certificat client
feeds:
  - name: "enterprise_threat_feed"
    url: "https://threat-api.enterprise.com/iocs"
    ssl:
      verify: true
      cert_file: "/etc/tinycti/client.crt"
      key_file: "/etc/tinycti/client.key"
    auth:
      type: "api_key"
      key: "${API_KEY_ENV_VAR}"
      header: "X-Enterprise-Key"
```

### Consommation par système externe:
```bash
# Récupération directe des IOCs live
curl -H "Authorization: Bearer your-token" \
     http://localhost:8080/bucket/live/ipv4.txt

# Statistiques du bucket
curl http://localhost:8080/bucket/live/stats
```

### Gestion via interface web:
```bash
# Interface d'admin
http://localhost:5000/

# API de gestion
curl -X POST http://localhost:5000/api/feeds/toggle/feed_name
```

Cette architecture offre une séparation claire, une sécurité renforcée et une facilité d'intégration pour les environnements de production.