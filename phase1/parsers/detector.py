# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : parsers/detector.py
# Rôle    : Détecte automatiquement l'environnement cible
#           ou utilise l'environnement forcé via --env
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================

import os
import subprocess

from config.settings import (
    DOCKER_COMPOSE_PATH,
    ENV_DOCKER,
    ENV_KUBERNETES
)
from utils.logger import get_logger, log_separateur, log_resultat, log_erreur_critique

logger = get_logger(__name__)

# Variable globale — environnement forcé manuellement via --env
_env_force = None


def forcer_environnement(env: str) -> None:
    """
    Force l'utilisation d'un environnement spécifique.
    Appelé par phase1_topology.py quand --env est passé en argument.

    Paramètre :
        env (str) : 'docker' ou 'kubernetes'
    """
    global _env_force
    if env in (ENV_DOCKER, ENV_KUBERNETES):
        _env_force = env
        logger.info(f"Environnement forcé manuellement : {env}")
    else:
        log_erreur_critique(
            logger,
            f"Environnement inconnu : '{env}'. Valeurs acceptées : 'docker', 'kubernetes'"
        )


def detecter_environnement(compose_path: str = None) -> str:
    """
    Retourne l'environnement cible.

    Paramètres :
        compose_path (str) : chemin vers un docker-compose.yml fourni
                             manuellement. Si fourni, force la détection Docker
                             sans vérifier kubectl.

    Si un environnement a été forcé via forcer_environnement(),
    on le retourne directement sans aucun test.

    Sinon, on détecte automatiquement par priorité décroissante :
        1. Docker Compose — fichier docker-compose.yml présent ?
        2. Kubernetes    — kubectl répond ?
        3. Erreur critique si rien trouvé

    Retourne :
        str : ENV_DOCKER ou ENV_KUBERNETES
    """
    global _env_force

    log_separateur(logger, "Détection de l'environnement")

    # -------------------------------------------------------------------------
    # Environnement forcé — pas de test, retour immédiat
    # -------------------------------------------------------------------------
    if _env_force is not None:
        log_resultat(logger, "Environnement forcé", _env_force.upper())
        return _env_force

    # -------------------------------------------------------------------------
    # Fichier fourni manuellement → Docker sans ambiguïté
    # -------------------------------------------------------------------------
    if compose_path is not None:
        if _detecter_docker(compose_path):
            log_resultat(logger, "Environnement détecté", "Docker Compose (fichier fourni)")
            return ENV_DOCKER
        log_erreur_critique(
            logger,
            f"Fichier fourni introuvable ou invalide : '{compose_path}'"
        )

    # -------------------------------------------------------------------------
    # Détection automatique — priorité décroissante
    # -------------------------------------------------------------------------
    if _detecter_docker():
        log_resultat(logger, "Environnement détecté", "Docker Compose")
        return ENV_DOCKER

    if _detecter_kubernetes():
        log_resultat(logger, "Environnement détecté", "Kubernetes")
        return ENV_KUBERNETES

    log_erreur_critique(
        logger,
        f"Aucun environnement détecté. "
        f"Vérifiez que '{DOCKER_COMPOSE_PATH}' existe "
        f"ou que kubectl est installé. "
        f"Vous pouvez aussi forcer l'environnement avec --env docker ou --env kubernetes"
    )


def _detecter_docker(compose_path: str = None) -> bool:
    chemin = compose_path or DOCKER_COMPOSE_PATH
    try:
        if not os.path.isfile(chemin):
            logger.debug(f"docker-compose.yml introuvable à : {chemin}")
            return False
        if os.path.getsize(chemin) == 0:
            logger.warning("docker-compose.yml trouvé mais vide — ignoré")
            return False
        logger.debug("docker-compose.yml trouvé et non vide")
        return True
    except OSError as e:
        logger.error(f"Erreur lecture docker-compose.yml : {e}")
        return False


def _detecter_kubernetes() -> bool:
    try:
        resultat = subprocess.run(
            ["kubectl", "cluster-info"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if resultat.returncode == 0:
            logger.debug("kubectl cluster-info — réponse positive")
            logger.info("kubectl opérationnel — cluster Kubernetes accessible")
            return True
        else:
            logger.debug(f"kubectl disponible mais cluster inaccessible (code : {resultat.returncode})")
            return False
    except FileNotFoundError:
        logger.debug("kubectl non installé")
        return False
    except subprocess.TimeoutExpired:
        logger.warning("kubectl timeout 5s")
        return False
    except Exception as e:
        logger.error(f"Erreur détection Kubernetes : {e}")
        return False


if __name__ == "__main__":
    env = detecter_environnement()
    print(f"\nRésultat : {env}")