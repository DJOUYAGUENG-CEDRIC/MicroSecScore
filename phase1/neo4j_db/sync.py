# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : neo4j_db/sync.py
# Rôle    : Synchronise le graphe G0 (NetworkX) vers Neo4j
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================

import networkx as nx

from neo4j_db.connector import creer_connexion
from config.settings    import OUTSIDE_NODE
from utils.logger       import get_logger, log_separateur, log_resultat

logger = get_logger(__name__)


def synchroniser_G0(G0: nx.DiGraph) -> bool:
    log_separateur(logger, "Synchronisation G0 → Neo4j")

    driver = creer_connexion()
    if driver is None:
        logger.error("Synchronisation annulée — Neo4j inaccessible")
        return False

    try:
        with driver.session() as session:
            session.run("MATCH (s:Service) DETACH DELETE s")

            nb_noeuds  = 0
            nb_depends = 0
            nb_attaque = 0

            for noeud, attributs in G0.nodes(data=True):
                _creer_noeud(session, noeud, attributs)
                nb_noeuds += 1

            for source, cible, data in G0.edges(data=True):
                type_arete = data.get("type_arete", "DEPENDS_ON")
                if type_arete == "DEPENDS_ON":
                    _creer_relation_depends_on(session, source, cible)
                    nb_depends += 1
                elif type_arete == "PEUT_ATTAQUER":
                    _creer_relation_peut_attaquer(session, source, cible)
                    nb_attaque += 1

        log_resultat(logger, "Noeuds synchronisés",    nb_noeuds)
        log_resultat(logger, "Relations DEPENDS_ON",    nb_depends)
        log_resultat(logger, "Relations PEUT_ATTAQUER", nb_attaque)
        log_resultat(logger, "Statut",                  "SUCCÈS")
        return True

    except Exception as e:
        logger.error(f"Erreur lors de la synchronisation Neo4j : {e}")
        return False


def _creer_noeud(session, nom: str, attributs: dict) -> None:
    props = {
        "nom"          : nom,
        "image"        : attributs.get("image", "unknown"),
        "score_cve"    : attributs.get("score_cve")  if attributs.get("score_cve")  is not None else -1,
        "criticite"    : attributs.get("criticite")  if attributs.get("criticite")  is not None else -1,
        "niveau"       : attributs.get("niveau")     or "N/A",
        "ports_exposes": str(attributs.get("ports_exposes", [])),
        "privileged"   : attributs.get("privileged", False),
        "docker_sock"  : attributs.get("docker_sock", False),
        "type_noeud"   : attributs.get("type_noeud", "service")
    }
    cypher = """
        MERGE (s:Service {nom: $nom})
        ON CREATE SET s += $props
        ON MATCH  SET s += $props
    """
    session.run(cypher, nom=nom, props=props)


def _creer_relation_depends_on(session, source: str, cible: str) -> None:
    cypher = """
        MATCH (a:Service {nom: $source})
        MATCH (b:Service {nom: $cible})
        MERGE (a)-[:DEPENDS_ON {autorise: true}]->(b)
    """
    session.run(cypher, source=source, cible=cible)


def _creer_relation_peut_attaquer(session, source: str, cible: str) -> None:
    cypher = """
        MATCH (a:Service {nom: $source})
        MATCH (b:Service {nom: $cible})
        MERGE (a)-[:PEUT_ATTAQUER {autorise: false}]->(b)
    """
    session.run(cypher, source=source, cible=cible)


def vider_base() -> bool:
    driver = creer_connexion()
    if driver is None:
        return False
    try:
        with driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
            logger.warning("Base Neo4j entièrement vidée")
            return True
    except Exception as e:
        logger.error(f"Erreur lors du vidage de la base : {e}")
        return False


def verifier_synchronisation(G0: nx.DiGraph) -> bool:
    driver = creer_connexion()
    if driver is None:
        return False
    try:
        with driver.session() as session:
            nb_neo4j_noeuds = session.run(
                "MATCH (s:Service) RETURN count(s) AS n"
            ).single()["n"]
            nb_neo4j_aretes = session.run(
                "MATCH (:Service)-[r]->(:Service) RETURN count(r) AS n"
            ).single()["n"]

        coherent = (
            nb_neo4j_noeuds == G0.number_of_nodes() and
            nb_neo4j_aretes == G0.number_of_edges()
        )
        log_resultat(logger, "Noeuds NetworkX / Neo4j",
                     f"{G0.number_of_nodes()} / {nb_neo4j_noeuds}")
        log_resultat(logger, "Arêtes NetworkX / Neo4j",
                     f"{G0.number_of_edges()} / {nb_neo4j_aretes}")
        log_resultat(logger, "Cohérence", "OK" if coherent else "DIVERGENCE")
        return coherent
    except Exception as e:
        logger.error(f"Erreur vérification : {e}")
        return False