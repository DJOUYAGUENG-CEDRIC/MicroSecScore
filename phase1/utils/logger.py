# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : utils/logger.py
# Rôle    : Logger centralisé — traçabilité complète de l'exécution
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================

import logging
import os
import sys
from config.settings import LOG_PATH

# =============================================================================
# FORMAT DES MESSAGES
# Exemple de sortie :
# [2025-10-14 08:32:11] [INFO]    [docker_parser] 13 services détectés
# [2025-10-14 08:32:12] [WARNING] [cve_client]    Timeout OSV.dev — bascule NVD
# [2025-10-14 08:32:15] [ERROR]   [neo4j]         Connexion refusée bolt://localhost:7687
# =============================================================================

LOG_FORMAT  = "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def get_logger(nom_module: str) -> logging.Logger:
    """
    Retourne un logger configuré pour le module demandé.

    Chaque module appelle get_logger(__name__) en haut de son fichier.
    Le logger écrit simultanément dans le terminal et dans phase1.log.

    Paramètre :
        nom_module (str) : nom du module appelant, ex. 'docker_parser'

    Retourne :
        logging.Logger : instance du logger prête à l'emploi
    """

    logger = logging.getLogger(nom_module)

    # Evite de dupliquer les handlers si le logger est appelé plusieurs fois
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # -------------------------------------------------------------------------
    # HANDLER 1 — Terminal (stdout)
    # Affiche INFO et au-dessus en temps réel pendant l'exécution
    # -------------------------------------------------------------------------
    handler_terminal = logging.StreamHandler(sys.stdout)
    handler_terminal.setLevel(logging.INFO)
    handler_terminal.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))

    # -------------------------------------------------------------------------
    # HANDLER 2 — Fichier phase1.log
    # Enregistre tout (DEBUG inclus) pour analyse post-exécution
    # Crée le dossier logs/ s'il n'existe pas encore
    # -------------------------------------------------------------------------
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    handler_fichier = logging.FileHandler(LOG_PATH, encoding="utf-8")
    handler_fichier.setLevel(logging.DEBUG)
    handler_fichier.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))

    # -------------------------------------------------------------------------
    # Ajout des deux handlers au logger
    # -------------------------------------------------------------------------
    logger.addHandler(handler_terminal)
    logger.addHandler(handler_fichier)

    return logger


# =============================================================================
# FONCTIONS UTILITAIRES DE MISE EN FORME
# Séparateurs visuels pour structurer la sortie terminal
# =============================================================================

def log_separateur(logger: logging.Logger, titre: str = "") -> None:
    """
    Affiche une ligne séparatrice dans les logs pour structurer la sortie.

    Exemple :
        ─────────────────────────────────────────
        PHASE 1 — CONSTRUCTION DU GRAPHE G0
        ─────────────────────────────────────────
    """
    ligne = "─" * 60
    logger.info(ligne)
    if titre:
        logger.info(f"  {titre.upper()}")
        logger.info(ligne)


def log_resultat(logger: logging.Logger, label: str, valeur) -> None:
    """
    Affiche un résultat clé sous forme formatée.

    Exemple :
        → Services parsés     : 13 noeuds, 11 arêtes
        → Score global        : 59.7/100 — État DÉGRADÉ
    """
    logger.info(f"→ {label:<25} : {valeur}")


def log_erreur_critique(logger: logging.Logger, message: str) -> None:
    """
    Enregistre une erreur critique et arrête proprement le programme.
    Utilisé quand une erreur rend impossible la suite de l'exécution
    (ex : fichier docker-compose.yml introuvable, Neo4j inaccessible).
    """
    logger.critical(f"ERREUR CRITIQUE — {message}")
    logger.critical("Arrêt du programme.")
    sys.exit(1)