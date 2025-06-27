# Configuration Gunicorn pour TinyCTI
# Fichier: gunicorn.conf.py

import multiprocessing
import os

# Configuration réseau
bind = os.environ.get('TINYCTI_BIND', '127.0.0.1:5000')
backlog = 2048

# Workers
workers = int(os.environ.get('TINYCTI_WORKERS', min(4, multiprocessing.cpu_count())))
worker_class = 'sync'
worker_connections = 1000
timeout = 60
keepalive = 2
max_requests = 1000
max_requests_jitter = 100

# Paths
pythonpath = '.'
chdir = os.path.dirname(os.path.abspath(__file__))

# Daemon
daemon = False
pidfile = '/tmp/tinycti-api.pid'
user = None
group = None
tmp_upload_dir = None

# Logging
accesslog = '-'  # stdout
errorlog = '-'   # stderr
loglevel = os.environ.get('TINYCTI_LOG_LEVEL', 'info')
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'tinycti-api'

# Server hooks
def on_starting(server):
    """Hook appelé au démarrage du serveur"""
    server.log.info("TinyCTI API Server starting...")

def on_reload(server):
    """Hook appelé lors du rechargement"""
    server.log.info("TinyCTI API Server reloading...")

def worker_int(worker):
    """Hook appelé lors de l'interruption d'un worker"""
    worker.log.info("Worker interrupted")

def pre_fork(server, worker):
    """Hook appelé avant fork d'un worker"""
    server.log.info(f"Worker spawned (pid: {worker.pid})")

def post_fork(server, worker):
    """Hook appelé après fork d'un worker"""
    server.log.info(f"Worker spawned (pid: {worker.pid})")

def worker_abort(worker):
    """Hook appelé lors de l'abort d'un worker"""
    worker.log.info("Worker aborted")

# Configuration SSL (si nécessaire)
# keyfile = '/path/to/keyfile'
# certfile = '/path/to/certfile'
# ssl_version = ssl.PROTOCOL_TLS
# cert_reqs = ssl.CERT_NONE

# Variables d'environnement pour TinyCTI
raw_env = [
    'TINYCTI_CONFIG=' + os.environ.get('TINYCTI_CONFIG', 'config.yaml'),
    'TINYCTI_LOG_LEVEL=' + os.environ.get('TINYCTI_LOG_LEVEL', 'INFO'),
]

# Configuration pour développement vs production
if os.environ.get('TINYCTI_ENV') == 'development':
    # Configuration développement
    workers = 1
    reload = True
    timeout = 120
    loglevel = 'debug'
else:
    # Configuration production
    preload_app = True
    max_requests = 500
    max_requests_jitter = 50