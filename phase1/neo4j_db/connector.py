# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : neo4j_db/connector.py
# Rôle    : Gère la connexion à la base de données Neo4j
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError

from config.settings import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
from utils.logger    import get_logger, log_separateur, log_resultat

logger = get_logger(__name__)

_driver = None


def creer_connexion():
    global _driver
    if _driver is not None:
        return _driver

    log_separateur(logger, "Connexion Neo4j")
    logger.info(f"URI         : {NEO4J_URI}")
    logger.info(f"Utilisateur : {NEO4J_USER}")

    try:
        _driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USER, NEO4J_PASSWORD)
        )
        _driver.verify_connectivity()
        log_resultat(logger, "Statut connexion", "CONNECTÉ")
        return _driver

    except AuthError:
        logger.error(
            "Authentification refusée — "
            "vérifiez le mot de passe dans config/settings.py"
        )
        _driver = None
        return None

    except ServiceUnavailable:
        logger.error(
            f"Neo4j inaccessible sur {NEO4J_URI} — "
            "vérifiez que le service Neo4j est démarré"
        )
        _driver = None
        return None

    except Exception as e:
        logger.error(f"Erreur inattendue lors de la connexion Neo4j : {e}")
        _driver = None
        return None


def tester_connexion() -> bool:
    driver = creer_connexion()
    if driver is None:
        return False
    try:
        with driver.session() as session:
            result = session.run("RETURN 1 AS test")
            valeur = result.single()["test"]
            if valeur == 1:
                logger.debug("Test de connexion Neo4j : OK")
                return True
    except Exception as e:
        logger.error(f"Test de connexion Neo4j échoué : {e}")
    return False


def fermer_connexion() -> None:
    global _driver
    if _driver is not None:
        try:
            _driver.close()
            logger.info("Connexion Neo4j fermée proprement")
        except Exception as e:
            logger.warning(f"Erreur lors de la fermeture Neo4j : {e}")
        finally:
            _driver = None


if __name__ == "__main__":
    print("Test de connexion Neo4j...")
    ok = tester_connexion()
    print("Connexion réussie !" if ok else "Connexion échouée")
    fermer_connexion()