# ============================================================
# config/phase2_settings.py
# Configuration centrale de la Phase 2 — MicroSecScore
# DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# ============================================================

# ─────────────────────────────────────────
# SECTION 1 — Kafka
# ─────────────────────────────────────────
KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"

KAFKA_TOPICS = {
    "logs":     "logs-applicatifs",
    "metrics":  "metriques-systeme",
    "alerts":   "alertes-securite"
}

KAFKA_PRODUCER_CONFIG = {
    "bootstrap_servers": KAFKA_BOOTSTRAP_SERVERS,
    "value_serializer":  None,   # JSON bytes — géré dans chaque collecteur
    "acks":              "all",  # Attendre confirmation du broker
    "retries":           3,
    "retry_backoff_ms":  500,
}

# ─────────────────────────────────────────
# SECTION 2 — Sources de collecte
# ─────────────────────────────────────────

# Docker Engine API
DOCKER_SOCKET = "unix://var/run/docker.sock"
DOCKER_LOG_TAIL = 100          # Nombre de lignes relues au démarrage
DOCKER_LOG_INTERVAL_S = 5      # Intervalle de collecte en secondes

# Prometheus + cAdvisor
CADVISOR_URL  = "http://localhost:8080"
PROMETHEUS_URL = "http://localhost:9090"
METRICS_INTERVAL_S = 15        # Intervalle de scraping en secondes

# CPU/RAM seuils d'alerte
CPU_ALERT_THRESHOLD_PCT  = 80.0
RAM_ALERT_THRESHOLD_PCT  = 85.0
NET_ALERT_THRESHOLD_MBPS = 100.0

# ─────────────────────────────────────────
# SECTION 3 — Générateur Falco
# ─────────────────────────────────────────
FALCO_GENERATOR_INTERVAL_S = 10   # Intervalle entre injections simulées
FALCO_RULES_FILE = "config/falco_rules.json"

# Fréquence d'injection des événements simulés (1 sur N cycles)
FALCO_SCAN_PROBABILITY    = 0.15  # 15% de chance : scan de reconnaissance
FALCO_BRUTE_PROBABILITY   = 0.10  # 10% de chance : tentative force brute
FALCO_LATERAL_PROBABILITY = 0.05  # 5%  de chance : mouvement latéral

# ─────────────────────────────────────────
# SECTION 4 — Normalisation des événements
# ─────────────────────────────────────────
EVENT_SCHEMA_VERSION = "1.0"

# Types d'événements valides dans le pipeline
VALID_EVENT_TYPES = {
    "LOG_HTTP",       # Requête HTTP reçue par un service
    "LOG_ERROR",      # Erreur applicative
    "LOG_AUTH",       # Tentative d'authentification
    "METRIC_CPU",     # Utilisation CPU
    "METRIC_RAM",     # Utilisation RAM
    "METRIC_NET",     # Trafic réseau
    "ALERT_SCAN",     # Scan de reconnaissance (Falco/simulé)
    "ALERT_BRUTE",    # Force brute (Falco/simulé)
    "ALERT_LATERAL",  # Mouvement latéral (Falco/simulé)
}

# ─────────────────────────────────────────
# SECTION 5 — Sorties
# ─────────────────────────────────────────
OUTPUT_DIR = "data/output"
EVENTS_LOG_FILE = "data/output/events_collected.jsonl"
PHASE2_REPORT_FILE = "data/output/phase2_rapport.json"
