# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : graph/builder.py
# Rôle    : Construit le graphe G0 = (N, E, A) avec NetworkX
#           G0 est la source de vérité de tout le système MicroSecScore
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================

import networkx as nx

from config.settings import OUTSIDE_NODE, SERVICES_SENSIBLES
from utils.logger import get_logger, log_separateur, log_resultat

logger = get_logger(__name__)


# =============================================================================
# FONCTION PRINCIPALE — CONSTRUCTION DE G0
# =============================================================================

def construire_G0(donnees_parsees: dict) -> nx.DiGraph:
    """
    Construit le graphe de connaissances G0 à partir des données parsées.

    Définition formelle :
        G0 = (N, E, A) où :
        N = ensemble des noeuds (microservices + noeud Outside)
        E = ensemble des arêtes orientées (communications autorisées)
        A = fonction d'attribution des attributs à chaque noeud

    Algorithme — construction incrémentale en 4 étapes :
        1. Initialisation du DiGraph (graphe orienté)
        2. Ajout des noeuds (un par microservice + Outside)
        3. Ajout des arêtes DEPENDS_ON (communications autorisées)
        4. Ajout des arêtes PEUT_ATTAQUER (depuis Outside)

    L'ordre est impératif : les noeuds doivent exister
    avant qu'on puisse créer des arêtes entre eux.

    Paramètre :
        donnees_parsees (dict) : sortie de docker_parser ou kubernetes_parser

    Retourne :
        nx.DiGraph : le graphe G0 enrichi
    """

    log_separateur(logger, "Construction du Graphe G0")

    if not donnees_parsees:
        logger.error("Données parsées vides — impossible de construire G0")
        return None

    services = donnees_parsees.get("services", {})
    services_exposes = donnees_parsees.get("services_exposes", [])

    # -------------------------------------------------------------------------
    # ÉTAPE 1 — Initialisation du DiGraph
    # DiGraph = Directed Graph = Graphe Orienté
    # L'orientation est essentielle : front-end → catalogue ≠ catalogue → front-end
    # -------------------------------------------------------------------------
    G0 = nx.DiGraph()
    G0.graph["nom"]     = "G0"
    G0.graph["version"] = "1.0"
    logger.debug("DiGraph initialisé")

    # -------------------------------------------------------------------------
    # ÉTAPE 2 — Ajout des noeuds microservices
    # Chaque noeud reçoit ses attributs de sécurité initiaux
    # score_cve et criticite sont None — ils seront calculés par scorer.py
    # -------------------------------------------------------------------------
    logger.debug(f"Ajout de {len(services)} noeuds microservices")

    for nom, service in services.items():
        G0.add_node(
            nom,
            image        = service.get("image", "unknown"),
            ports_exposes= service.get("ports_exposes", []),
            privileged   = service.get("privileged", False),
            docker_sock  = service.get("docker_sock", False),
            score_cve    = None,
            criticite    = None,
            niveau       = None,
            type_noeud   = "service"
        )
        logger.debug(f"  Noeud ajouté : {nom}")

    # -------------------------------------------------------------------------
    # ÉTAPE 3 — Ajout du noeud spécial Outside
    # Outside représente un attaquant externe — abstraction de toute
    # menace provenant d'internet
    # -------------------------------------------------------------------------
    G0.add_node(
        OUTSIDE_NODE,
        type_noeud   = "attaquant_externe",
        score_cve    = None,
        criticite    = 0,
        niveau       = "EXTERNE"
    )
    logger.debug(f"Noeud spécial ajouté : {OUTSIDE_NODE}")

    # -------------------------------------------------------------------------
    # ÉTAPE 4 — Ajout des arêtes DEPENDS_ON
    # Chaque dépendance devient une arête orientée dans G0
    # front-end depends_on catalogue → arête front-end → catalogue
    # -------------------------------------------------------------------------
    logger.debug("Ajout des arêtes DEPENDS_ON")
    nb_aretes_depends = 0

    for nom_service, service in services.items():
        for dependance in service.get("depends_on", []):

            # Vérifie que le service cible existe dans le graphe
            if dependance not in G0.nodes:
                logger.warning(
                    f"Dépendance ignorée : {nom_service} → {dependance} "
                    f"(service '{dependance}' non trouvé dans G0)"
                )
                continue

            G0.add_edge(
                nom_service,
                dependance,
                type_arete = "DEPENDS_ON",
                autorise   = True
            )
            nb_aretes_depends += 1
            logger.debug(f"  Arête DEPENDS_ON : {nom_service} → {dependance}")

    # -------------------------------------------------------------------------
    # ÉTAPE 5 — Ajout des arêtes PEUT_ATTAQUER depuis Outside
    # Seuls les services exposant des ports sont atteignables depuis internet
    # -------------------------------------------------------------------------
    logger.debug("Ajout des arêtes PEUT_ATTAQUER")
    nb_aretes_attaque = 0

    for nom_service in services_exposes:
        if nom_service not in G0.nodes:
            continue

        G0.add_edge(
            OUTSIDE_NODE,
            nom_service,
            type_arete = "PEUT_ATTAQUER",
            autorise   = False
        )
        nb_aretes_attaque += 1
        logger.debug(f"  Arête PEUT_ATTAQUER : {OUTSIDE_NODE} → {nom_service}")

    # -------------------------------------------------------------------------
    # RÉSUMÉ DE LA CONSTRUCTION
    # -------------------------------------------------------------------------
    log_resultat(logger, "Noeuds dans G0",        G0.number_of_nodes())
    log_resultat(logger, "Arêtes DEPENDS_ON",     nb_aretes_depends)
    log_resultat(logger, "Arêtes PEUT_ATTAQUER",  nb_aretes_attaque)
    log_resultat(logger, "Total arêtes",          G0.number_of_edges())

    logger.info("Graphe G0 construit avec succès")
    return G0


# =============================================================================
# FONCTIONS UTILITAIRES DE CONSULTATION DE G0
# Utilisées par les phases 3 et 4 pour vérifier les communications
# =============================================================================

def get_chemins_autorises(G0: nx.DiGraph) -> list:
    """
    Retourne toutes les paires (source, destination) dont la communication
    est autorisée dans G0 (arêtes de type DEPENDS_ON).

    Utilisé par la règle CEP P3 (mouvement latéral) :
    si une communication observée n'est pas dans cette liste,
    c'est un mouvement latéral suspect.

    Retourne :
        list : liste de tuples (service_src, service_dst)
    """
    return [
        (src, dst)
        for src, dst, data in G0.edges(data=True)
        if data.get("type_arete") == "DEPENDS_ON"
    ]


def get_chemins_attaque(G0: nx.DiGraph, source: str = None) -> list:
    """
    Retourne tous les chemins d'attaque possibles depuis Outside
    ou depuis un noeud source donné.

    Utilisé par la Phase 4 pour prédire la prochaine cible
    d'un attaquant localisé sur un noeud du graphe.

    Paramètre :
        source (str) : noeud de départ (défaut : Outside)

    Retourne :
        list : liste de chemins (chaque chemin est une liste de noeuds)
    """
    if source is None:
        source = OUTSIDE_NODE

    if source not in G0.nodes:
        logger.warning(f"Noeud source '{source}' absent de G0")
        return []

    chemins = []
    for cible in G0.nodes:
        if cible == source:
            continue
        try:
            for chemin in nx.all_simple_paths(G0, source=source, target=cible):
                chemins.append(chemin)
        except nx.NetworkXNoPath:
            continue

    return chemins


def get_voisins_sortants(G0: nx.DiGraph, noeud: str) -> list:
    """
    Retourne les voisins directs sortants d'un noeud.

    Utilisé par la Phase 4 pour prédire la prochaine cible :
    si l'attaquant est sur 'orders', ses prochaines cibles
    probables sont les voisins sortants de 'orders' dans G0.

    Retourne :
        list : noms des noeuds voisins sortants
    """
    if noeud not in G0.nodes:
        return []
    return list(G0.successors(noeud))


# =============================================================================
# TEST RAPIDE — Exécution directe du fichier
# python graph/builder.py
# =============================================================================

if __name__ == "__main__":
    # Données de test minimales simulant la sortie de docker_parser.py
    donnees_test = {
        "services": {
            "front-end": {
                "image"        : "weaveworksdemos/front-end:0.3.12",
                "ports_exposes": [80],
                "depends_on"   : ["catalogue", "orders", "cart", "user"],
                "privileged"   : False,
                "docker_sock"  : False
            },
            "catalogue": {
                "image"        : "weaveworksdemos/catalogue:0.3.5",
                "ports_exposes": [],
                "depends_on"   : ["catalogue-db"],
                "privileged"   : False,
                "docker_sock"  : False
            },
            "catalogue-db": {
                "image"        : "weaveworksdemos/catalogue-db:0.3.0",
                "ports_exposes": [],
                "depends_on"   : [],
                "privileged"   : False,
                "docker_sock"  : False
            },
            "orders": {
                "image"        : "weaveworksdemos/orders:0.4.7",
                "ports_exposes": [],
                "depends_on"   : ["orders-db"],
                "privileged"   : False,
                "docker_sock"  : False
            },
            "orders-db": {
                "image"        : "mongo:3.4",
                "ports_exposes": [],
                "depends_on"   : [],
                "privileged"   : False,
                "docker_sock"  : False
            }
        },
        "services_exposes": ["front-end"]
    }

    G0 = construire_G0(donnees_test)
    if G0:
        print(f"\nNoeuds  : {list(G0.nodes())}")
        print(f"Arêtes  : {list(G0.edges())}")
        print(f"\nChemins autorisés :")
        for chemin in get_chemins_autorises(G0):
            print(f"  {chemin[0]} → {chemin[1]}")
        print(f"\nChemins d'attaque depuis Outside :")
        for chemin in get_chemins_attaque(G0):
            print(f"  {' → '.join(chemin)}")