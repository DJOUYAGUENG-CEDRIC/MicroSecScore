# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : phase1_topology.py  (version finale)
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================
#
# USAGE :
#   Détection automatique :
#     python phase1_topology.py
#
#   Forcer Docker Compose (même si K8s disponible) :
#     python phase1_topology.py --env docker
#
#   Forcer Kubernetes (même si docker-compose.yml présent) :
#     python phase1_topology.py --env kubernetes
#
#   Autres options :
#     --simulation  : scores CVE simulés (sans appel API)
#     --no-neo4j    : sans synchronisation Neo4j
#     --no-viz      : sans visualisation
#
#   Exemples combinés :
#     python phase1_topology.py --env docker --no-viz
#     python phase1_topology.py --env kubernetes --simulation --no-neo4j
# =============================================================================

import sys
import argparse
import time

from config.settings    import ENV_KUBERNETES
from utils.logger       import get_logger, log_separateur, log_resultat
from parsers.detector   import detecter_environnement, forcer_environnement
from parsers.docker_parser     import parser_docker_compose
from graph.builder      import construire_G0
from graph.scorer       import calculer_criticites, calculer_score_global
from graph.exporter     import exporter_graphe, exporter_scores_csv
from cve.cve_scorer     import enrichir_G0_avec_scores_cve, simuler_scores_cve
from neo4j_db.connector import creer_connexion, fermer_connexion, tester_connexion
from neo4j_db.sync      import synchroniser_G0, verifier_synchronisation
from visualizer         import visualiser_G0

logger = get_logger(__name__)


def main(simulation  : bool = False,
         avec_neo4j  : bool = True,
         avec_viz    : bool = True,
         env_force   : str  = None,
         file_path   : str  = None,
         k8s_dir     : str  = None) -> dict:

    debut_total = time.time()

    log_separateur(logger, "MicroSecScore — Phase 1 : Topologie & Graphe G0")
    logger.info(f"Mode simulation   : {'OUI' if simulation else 'NON'}")
    logger.info(f"Sync Neo4j        : {'OUI' if avec_neo4j else 'NON'}")
    logger.info(f"Visualisation     : {'OUI' if avec_viz else 'NON'}")
    if file_path:
        logger.info(f"Fichier Docker    : {file_path}")
    if k8s_dir:
        logger.info(f"Dossier K8s       : {k8s_dir}")
    if env_force:
        logger.info(f"Environnement     : FORCÉ → {env_force.upper()}")

    # =========================================================================
    # ÉTAPE 1 — DÉTECTION ET PARSING
    # =========================================================================
    log_separateur(logger, "Étape 1 — Parsing de l'architecture")
    debut = time.time()

    # Si un dossier K8s est fourni, forcer l'environnement Kubernetes
    if k8s_dir and not env_force:
        env_force = ENV_KUBERNETES

    # Appliquer l'environnement forcé si spécifié
    if env_force:
        forcer_environnement(env_force)

    env_detecte = detecter_environnement(compose_path=file_path)

    # Sélection du parseur selon l'environnement
    if env_detecte == ENV_KUBERNETES:
        if k8s_dir:
            logger.info(f"Parseur sélectionné : Kubernetes (fichiers YAML depuis {k8s_dir})")
            try:
                from parsers.kubernetes_parser import parser_kubernetes_fichiers
                donnees_parsees = parser_kubernetes_fichiers(k8s_dir)
            except ImportError:
                logger.error("Module kubernetes non disponible")
                donnees_parsees = None
        else:
            logger.info("Parseur sélectionné : Kubernetes (API live)")
            try:
                from parsers.kubernetes_parser import parser_kubernetes
                donnees_parsees = parser_kubernetes()
            except ImportError:
                logger.error("Module kubernetes non disponible")
                donnees_parsees = None
    else:
        logger.info("Parseur sélectionné : Docker Compose")
        donnees_parsees = parser_docker_compose(file_path)

    if donnees_parsees is None:
        logger.critical(
            "Parsing échoué. "
            "Conseil : utilisez --env docker ou --env kubernetes "
            "pour forcer l'environnement."
        )
        sys.exit(1)

    log_resultat(logger, "Environnement",
                 "Docker Compose" if env_detecte != ENV_KUBERNETES else "Kubernetes")
    log_resultat(logger, "Services parsés",  f"{len(donnees_parsees['services'])}")
    log_resultat(logger, "Services exposés", f"{donnees_parsees['services_exposes']}")
    log_resultat(logger, "Durée",            f"{time.time() - debut:.2f}s")

    # =========================================================================
    # ÉTAPE 2 — CONSTRUCTION G0
    # =========================================================================
    log_separateur(logger, "Étape 2 — Construction du Graphe G0")
    debut = time.time()

    G0 = construire_G0(donnees_parsees)
    if G0 is None:
        logger.critical("Construction de G0 échouée")
        sys.exit(1)

    log_resultat(logger, "Noeuds",  f"{G0.number_of_nodes()} (dont Outside)")
    log_resultat(logger, "Arêtes",  f"{G0.number_of_edges()}")
    log_resultat(logger, "Durée",   f"{time.time() - debut:.2f}s")

    # =========================================================================
    # ÉTAPE 3 — CRITICITÉS
    # =========================================================================
    log_separateur(logger, "Étape 3 — Calcul des criticités")
    debut = time.time()

    G0 = calculer_criticites(G0)
    log_resultat(logger, "Criticités", f"{G0.number_of_nodes()} noeuds")
    log_resultat(logger, "Durée",      f"{time.time() - debut:.2f}s")

    # =========================================================================
    # ÉTAPE 4 — SCORES CVE
    # =========================================================================
    log_separateur(logger, "Étape 4 — Calcul des scores CVE")
    debut = time.time()

    if simulation:
        logger.warning("MODE SIMULATION — scores CVE Sock Shop injectés")
        G0 = simuler_scores_cve(G0)
    else:
        logger.info("Interrogation APIs CVE (OSV.dev → NVD NIST)...")
        logger.info("Patience — 3 à 10 minutes selon la connexion internet")
        G0 = enrichir_G0_avec_scores_cve(G0)

    log_resultat(logger, "Durée", f"{time.time() - debut:.2f}s")

    # =========================================================================
    # ÉTAPE 5 — SCORE GLOBAL
    # =========================================================================
    log_separateur(logger, "Étape 5 — Calcul du score global")
    debut = time.time()

    resultat_score = calculer_score_global(G0)
    if resultat_score is None:
        resultat_score = {"score_global": 0, "niveau": "CRITIQUE", "details": []}

    score_global = resultat_score["score_global"]
    niveau       = resultat_score["niveau"]

    log_resultat(logger, "Score global",    f"{score_global}/100")
    log_resultat(logger, "Niveau sécurité", niveau)
    log_resultat(logger, "Durée",           f"{time.time() - debut:.2f}s")

    # =========================================================================
    # ÉTAPE 6 — NEO4J
    # =========================================================================
    if avec_neo4j:
        log_separateur(logger, "Étape 6 — Synchronisation Neo4j")
        debut = time.time()
        if tester_connexion():
            succes = synchroniser_G0(G0)
            if succes:
                verifier_synchronisation(G0)
        else:
            logger.warning("Neo4j inaccessible — synchronisation ignorée")
        log_resultat(logger, "Durée", f"{time.time() - debut:.2f}s")

    # =========================================================================
    # ÉTAPE 7 — EXPORT
    # =========================================================================
    log_separateur(logger, "Étape 7 — Export des fichiers")
    debut = time.time()

    chemin_json = exporter_graphe(G0)
    chemin_csv  = exporter_scores_csv(G0)

    if chemin_json: log_resultat(logger, "G0 exporté",      chemin_json)
    if chemin_csv:  log_resultat(logger, "Scores exportés", chemin_csv)
    log_resultat(logger, "Durée", f"{time.time() - debut:.2f}s")

    # =========================================================================
    # ÉTAPE 8 — VISUALISATION
    # =========================================================================
    if avec_viz:
        log_separateur(logger, "Étape 8 — Visualisation de G0")
        debut = time.time()
        fichiers_viz = visualiser_G0(G0, mode="les_deux")
        for fmt, chemin in fichiers_viz.items():
            log_resultat(logger, f"Viz {fmt.upper()}", chemin)
        log_resultat(logger, "Durée", f"{time.time() - debut:.2f}s")

    # =========================================================================
    # WATCHER KUBERNETES
    # =========================================================================
    if env_detecte == ENV_KUBERNETES:
        log_separateur(logger, "Watcher Kubernetes")
        from watcher import demarrer_watcher
        demarrer_watcher(G0)
        logger.info("Watcher actif — G0 mis à jour automatiquement")

    # =========================================================================
    # RÉSUMÉ FINAL
    # =========================================================================
    duree_totale = time.time() - debut_total
    symboles = {"SAIN":"✓", "STABLE":"~", "DEGRADE":"!", "CRITIQUE":"✗"}
    ligne = "=" * 60

    logger.info(ligne)
    logger.info("  RÉSUMÉ — PHASE 1 : TOPOLOGIE & GRAPHE G0")
    logger.info(ligne)
    logger.info(f"  → Environnement   : {'Docker Compose' if env_detecte != ENV_KUBERNETES else 'Kubernetes'}")
    logger.info(f"  → Services parsés : {len(donnees_parsees['services'])} services")
    logger.info(f"  → Noeuds dans G0  : {G0.number_of_nodes()} (dont Outside)")
    logger.info(f"  → Arêtes dans G0  : {G0.number_of_edges()}")
    logger.info(f"  → Services exposés: {donnees_parsees['services_exposes']}")
    logger.info("")
    logger.info(f"  → G0 sauvegardé   : {chemin_json}")
    logger.info(f"  → Scores CVE      : {chemin_csv}")
    logger.info("")
    logger.info(f"  → Score global    : {score_global}/100 → {niveau} {symboles.get(niveau,'?')}")
    logger.info("")

    details = resultat_score.get("details", [])
    if details:
        logger.info("  Services les plus vulnérables :")
        for d in details[:3]:
            logger.info(
                f"    {d['service']:<20} "
                f"score={d['score_cve']}/100  "
                f"criticité={d['criticite']}"
            )

    logger.info("")
    logger.info(f"  → Durée totale    : {duree_totale:.1f}s")
    logger.info(ligne)

    if avec_neo4j:
        fermer_connexion()

    return {
        "G0"          : G0,
        "score_global": score_global,
        "niveau"      : niveau,
        "details"     : resultat_score.get("details", []),
        "graph_json"  : chemin_json,
        "scores_csv"  : chemin_csv
    }


def _parser_arguments():
    parser = argparse.ArgumentParser(
        description="MicroSecScore — Phase 1 : Topologie & Graphe G0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python phase1_topology.py                        # Détection automatique
  python phase1_topology.py --env docker           # Forcer Docker Compose
  python phase1_topology.py --env kubernetes       # Forcer Kubernetes
  python phase1_topology.py --env docker --no-viz  # Docker sans visualisation
  python phase1_topology.py --simulation           # Mode simulation (sans API)
  python phase1_topology.py --no-neo4j             # Sans Neo4j
        """
    )
    parser.add_argument(
        "--env",
        choices=["docker", "kubernetes"],
        default=None,
        help="Forcer l'environnement (docker ou kubernetes). Sans cette option : détection automatique."
    )
    parser.add_argument(
        "--file",
        metavar="CHEMIN",
        default=None,
        help="Chemin vers un fichier docker-compose.yml à analyser (remplace le fichier par défaut)."
    )
    parser.add_argument(
        "--k8s-dir",
        metavar="DOSSIER",
        default=None,
        help="Dossier contenant les manifestes Kubernetes (deployments.yaml, services.yaml, networkpolicies.yaml)."
    )
    parser.add_argument(
        "--simulation",
        action="store_true",
        default=False,
        help="Utilise les scores CVE simulés (pas d'appel API réseau)"
    )
    parser.add_argument(
        "--no-neo4j",
        action="store_true",
        default=False,
        help="Ignore la synchronisation avec Neo4j"
    )
    parser.add_argument(
        "--no-viz",
        action="store_true",
        default=False,
        help="Ignore la génération des visualisations"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parser_arguments()
    resultat = main(
        simulation = args.simulation,
        avec_neo4j = not args.no_neo4j,
        avec_viz   = not args.no_viz,
        env_force  = args.env,
        file_path  = args.file,
        k8s_dir    = args.k8s_dir,
    )
    codes = {"SAIN":0, "STABLE":0, "DEGRADE":1, "CRITIQUE":2}
    sys.exit(codes.get(resultat["niveau"], 1))