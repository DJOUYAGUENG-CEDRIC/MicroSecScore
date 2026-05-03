# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : parsers/__init__.py
# Rôle    : Expose les fonctions publiques du module parsers
#           Import paresseux — on charge uniquement le parseur nécessaire
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================

from parsers.detector      import detecter_environnement
from parsers.docker_parser import parser_docker_compose
from config.settings       import ENV_DOCKER, ENV_KUBERNETES

__all__ = [
    "detecter_environnement",
    "parser_docker_compose",
    "parser_environnement",
    "ENV_DOCKER",
    "ENV_KUBERNETES"
]


def parser_environnement() -> dict:
    """
    Fonction unifiée appelée par phase1_topology.py.

    Utilise un import paresseux (lazy import) pour kubernetes_parser :
    le module kubernetes n'est importé QUE si l'environnement détecté
    est Kubernetes. Sur Docker, kubernetes n'est jamais importé
    — plus besoin que le module soit installé pour faire tourner
    le système en mode Docker.

    Retourne :
        dict : données parsées au format service_descriptor
    """
    from utils.logger import get_logger
    logger = get_logger(__name__)

    env = detecter_environnement()

    if env == ENV_DOCKER:
        logger.info("Parseur sélectionné : Docker Compose")
        return parser_docker_compose()

    elif env == ENV_KUBERNETES:
        logger.info("Parseur sélectionné : Kubernetes")
        # Import paresseux — uniquement si Kubernetes est détecté
        try:
            from parsers.kubernetes_parser import parser_kubernetes
            return parser_kubernetes()
        except ImportError:
            logger.error(
                "Module 'kubernetes' non installé. "
                "Installez-le avec : pip install kubernetes"
            )
            return None

    return None