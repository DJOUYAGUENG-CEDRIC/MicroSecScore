# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : config/settings.py
# Rôle    : Centralise tous les paramètres du projet
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================

import os

# =============================================================================
# SECTION 1 — CONNEXION NEO4J
# =============================================================================

NEO4J_URI      = "neo4j://127.0.0.1:7687"
NEO4J_USER     = "neo4j"
NEO4J_PASSWORD = "microsec123"

# =============================================================================
# SECTION 2 — COEFFICIENTS CVE
# Calibrés sur le standard CVSS v3.1 (Common Vulnerability Scoring System)
# Référence : https://www.first.org/cvss/v3.1/specification-document
# Formule   : Score_CVE = 100 - (CRITICAL×10 + HIGH×7 + MEDIUM×4 + LOW×1)
# =============================================================================

CVE_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH":      7,
    "MEDIUM":    4,
    "LOW":       1
}

# =============================================================================
# SECTION 3 — SEUILS DES NIVEAUX DE SÉCURITÉ
# Chaque tuple représente (borne_inférieure, borne_supérieure) incluses
# =============================================================================

SCORE_LEVELS = {
    "SAIN":     (90, 100),   # Système en bon état — surveillance normale
    "STABLE":   (70, 89),    # Faiblesses mineures — surveillance renforcée
    "DEGRADE":  (50, 69),    # Faiblesses significatives — alerte active
    "CRITIQUE": (0,  49)     # Système en danger — remédiation immédiate
}

# Couleurs associées à chaque niveau (utilisées par le visualiseur)
SCORE_COLORS = {
    "SAIN":     "green",
    "STABLE":   "yellow",
    "DEGRADE":  "orange",
    "CRITIQUE": "red"
}

# =============================================================================
# SECTION 4 — CHEMINS DES FICHIERS
# os.path.dirname(__file__) pointe vers le dossier config/
# On remonte d'un niveau pour atteindre phase1/, puis data/
# =============================================================================

BASE_DIR            = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INPUT_DIR           = os.path.join(BASE_DIR, "..", "data", "input")
OUTPUT_DIR          = os.path.join(BASE_DIR, "..", "data", "output")
LOG_DIR             = os.path.join(BASE_DIR, "..", "logs")

DOCKER_COMPOSE_PATH = os.path.join(INPUT_DIR, "docker-compose.yml")
K8S_DIR             = os.path.join(INPUT_DIR, "k8s")
GRAPH_OUTPUT_PATH   = os.path.join(OUTPUT_DIR, "graph_G0.json")
SCORES_OUTPUT_PATH  = os.path.join(OUTPUT_DIR, "security_scores.csv")
LOG_PATH            = os.path.join(LOG_DIR, "phase1.log")

# =============================================================================
# SECTION 5 — CONSTANTES D'ENVIRONNEMENT
# Utilisées par parsers/detector.py pour identifier l'environnement cible
# =============================================================================

ENV_DOCKER     = "docker"
ENV_KUBERNETES = "kubernetes"

# =============================================================================
# SECTION 6 — PARAMÈTRES DU GRAPHE G0
# Règles de calcul de la criticité des noeuds
# =============================================================================

# Seuils de connexions pour le calcul de criticité
CRITICITE_SEUILS = {
    5: 6,   # >= 6 connexions → criticité 5
    4: 4,   # >= 4 connexions → criticité 4
    3: 2,   # >= 2 connexions → criticité 3
    2: 1,   # >= 1 connexion  → criticité 2
    1: 0    # 0 connexion     → criticité 1
}

# Services qui reçoivent un bonus +1 de criticité (données sensibles)
SERVICES_SENSIBLES = [
    "payment", "orders-db", "user-db",
    "catalogue-db", "cart-db", "user"
]

# Nom du noeud représentant l'attaquant externe
OUTSIDE_NODE = "Outside"

# =============================================================================
# SECTION 7 — PARAMÈTRES API CVE
# =============================================================================

OSV_API_URL = "https://api.osv.dev/v1/query"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_TIMEOUT = 10    # secondes avant timeout
API_RETRIES = 3     # nombre de tentatives avant fallback

# =============================================================================
# SECTION 8 — PARAMÈTRES KUBERNETES WATCHER
# =============================================================================

K8S_NAMESPACE      = "default"
K8S_WATCH_TIMEOUT  = 300    # secondes entre deux reconnexions du watcher