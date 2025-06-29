#!/usr/bin/env python3
"""
Script de test pour vérifier les améliorations TinyCTI
"""

import requests
import json
import time
import sys
from pathlib import Path

def test_api_endpoints():
    """Teste les nouveaux endpoints API"""
    base_url = "http://127.0.0.1:5000"
    
    print("=== Test des améliorations TinyCTI ===\n")
    
    # Test du health check (endpoint public)
    print("1. Test du health check...")
    try:
        response = requests.get(f"{base_url}/api/health", timeout=5)
        if response.status_code == 200:
            health = response.json()
            print(f"   ✅ Santé système: {health['status']}")
            print(f"   ⏱️  Uptime: {health['uptime_seconds']}s")
            print(f"   🔧 Composants: {list(health['components'].keys())}")
        else:
            print(f"   ❌ Erreur health check: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Impossible de tester le health check: {e}")
    
    print()
    
    # Test du statut général (endpoint public)
    print("2. Test du statut général...")
    try:
        response = requests.get(f"{base_url}/api/status", timeout=5)
        if response.status_code == 200:
            status = response.json()
            print(f"   ✅ Status: {status['status']}")
            print(f"   📊 Flux total: {status['feeds_total']}")
            print(f"   ✔️  Flux activés: {status['feeds_enabled']}")
        else:
            print(f"   ❌ Erreur status: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Impossible de tester le status: {e}")
    
    print()
    
    # Test d'authentification (doit échouer sans auth)
    print("3. Test de la protection par authentification...")
    try:
        response = requests.get(f"{base_url}/api/feeds", timeout=5)
        if response.status_code == 401:
            print("   ✅ Authentification requise correctement appliquée")
        else:
            print(f"   ⚠️  Réponse inattendue: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Erreur test auth: {e}")
    
    print()
    
    # Test des exports (doit échouer sans auth)
    print("4. Test des nouveaux endpoints d'export...")
    export_endpoints = [
        "/api/export/json/ipv4",
        "/api/export/csv/domain", 
        "/api/export/text/url"
    ]
    
    for endpoint in export_endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            if response.status_code == 401:
                print(f"   ✅ {endpoint}: Protection auth OK")
            else:
                print(f"   ⚠️  {endpoint}: Code {response.status_code}")
        except Exception as e:
            print(f"   ❌ {endpoint}: Erreur {e}")
    
    print()
    
    # Test des statistiques de rétention (doit échouer sans auth)
    print("5. Test des nouveaux endpoints de rétention...")
    retention_endpoints = [
        "/api/retention/stats",
        "/api/retention/audit"
    ]
    
    for endpoint in retention_endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            if response.status_code == 401:
                print(f"   ✅ {endpoint}: Protection auth OK")
            else:
                print(f"   ⚠️  {endpoint}: Code {response.status_code}")
        except Exception as e:
            print(f"   ❌ {endpoint}: Erreur {e}")

def test_file_structure():
    """Vérifie la structure des fichiers"""
    print("\n=== Test de la structure des fichiers ===\n")
    
    expected_files = [
        "config.yaml",
        "tinycti.py", 
        "wsgi.py",
        "requirements.txt",
        "generate_password_hash.py"
    ]
    
    base_path = Path(".")
    
    for file_name in expected_files:
        file_path = base_path / file_name
        if file_path.exists():
            print(f"   ✅ {file_name}: Présent")
        else:
            print(f"   ❌ {file_name}: Manquant")
    
    # Vérifie les répertoires IOCs
    ioc_dirs = ["live", "chaud", "tiede", "froid"]
    iocs_path = base_path / "iocs"
    
    if iocs_path.exists():
        print(f"   ✅ Répertoire iocs: Présent")
        for dir_name in ioc_dirs:
            dir_path = iocs_path / dir_name
            if dir_path.exists():
                print(f"   ✅ iocs/{dir_name}: Présent")
            else:
                print(f"   ⚠️  iocs/{dir_name}: Manquant")
    else:
        print(f"   ❌ Répertoire iocs: Manquant")

def test_config_validation():
    """Teste la configuration"""
    print("\n=== Test de la configuration ===\n")
    
    try:
        with open("config.yaml", "r") as f:
            import yaml
            config = yaml.safe_load(f)
            
        # Vérifie les nouvelles sections
        new_sections = [
            "api.auth",
            "api.export",
            "logging.compression",
            "logging.audit_enabled",
            "authentication.users",
            "retention_policy"
        ]
        
        for section in new_sections:
            keys = section.split(".")
            current = config
            found = True
            
            for key in keys:
                if key in current:
                    current = current[key]
                else:
                    found = False
                    break
            
            if found:
                print(f"   ✅ Configuration {section}: Présente")
            else:
                print(f"   ❌ Configuration {section}: Manquante")
                
    except Exception as e:
        print(f"   ❌ Erreur lecture config: {e}")

def main():
    """Fonction principale"""
    print("🔧 Script de test des améliorations TinyCTI")
    print("==========================================")
    
    # Test de la structure des fichiers
    test_file_structure()
    
    # Test de la configuration 
    test_config_validation()
    
    # Demande si on doit tester l'API (nécessite que TinyCTI soit en cours d'exécution)
    print("\n" + "="*50)
    response = input("Voulez-vous tester l'API? (TinyCTI doit être en cours d'exécution) [y/N]: ")
    
    if response.lower() in ['y', 'yes', 'oui']:
        test_api_endpoints()
    
    print("\n🎯 Test terminé!")
    print("\n💡 Pour utiliser les nouvelles fonctionnalités:")
    print("   1. Configurez l'authentification dans config.yaml")
    print("   2. Activez l'API avec 'api.enabled: true'") 
    print("   3. Lancez TinyCTI avec python tinycti.py --api")
    print("   4. Utilisez les nouveaux endpoints pour l'export et la gestion")

if __name__ == "__main__":
    main()