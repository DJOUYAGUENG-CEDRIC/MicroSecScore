# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : graph/scorer.py
# Rôle    : Calcule la criticité de chaque noeud et le score global du système
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================

import networkx as nx

from config.settings import (
    CRITICITE_SEUILS,
    SERVICES_SENSIBLES,
    SCORE_LEVELS,
    OUTSIDE_NODE
)
from utils.logger import get_logger, log_separateur, log_resultat

logger = get_logger(__name__)


# =============================================================================
# FONCTION 1 — CALCUL DES CRITICITÉS
# Algorithme : centralité de degré (degree centrality)
# =============================================================================

def calculer_criticites(G0: nx.DiGraph) -> nx.DiGraph:
    """
    Calcule et attribue la criticité à chaque noeud de G0.

    Algorithme — centralité de degré :
        Pour chaque noeud s :
        1. Compter les connexions entrantes (in_degree)
           = nombre de services qui appellent s
        2. Compter les connexions sortantes (out_degree)
           = nombre de services que s appelle
        3. Total = in_degree + out_degree
        4. Convertir en criticité selon les seuils définis
        5. Appliquer le bonus +1 pour les services sensibles

    La criticité mesure l'importance d'un noeud dans le graphe.
    Un noeud très connecté a une criticité élevée — sa compromission
    affecterait davantage l'ensemble du système.

    Paramètre :
        G0 (nx.DiGraph) : graphe construit par builder.py

    Retourne :
        nx.DiGraph : G0 enrichi avec l'attribut 'criticite' sur chaque noeud
    """

    log_separateur(logger, "Calcul des criticités")

    for noeud in G0.nodes:

        # Outside n'a pas de criticité métier
        if noeud == OUTSIDE_NODE:
            G0.nodes[noeud]["criticite"] = 0
            continue

        # ---------------------------------------------------------------------
        # ÉTAPE 1 — Calcul du degré total
        # On exclut les arêtes PEUT_ATTAQUER du calcul :
        # elles représentent une menace externe, pas une dépendance interne
        # ---------------------------------------------------------------------
        in_degree  = sum(
            1 for _, _, data in G0.in_edges(noeud, data=True)
            if data.get("type_arete") == "DEPENDS_ON"
        )
        out_degree = sum(
            1 for _, _, data in G0.out_edges(noeud, data=True)
            if data.get("type_arete") == "DEPENDS_ON"
        )
        total_connexions = in_degree + out_degree

        # ---------------------------------------------------------------------
        # ÉTAPE 2 — Conversion en criticité selon les seuils
        # Les seuils sont définis dans config/settings.py (CRITICITE_SEUILS)
        # On parcourt les seuils du plus élevé au plus bas (ordre décroissant)
        # ---------------------------------------------------------------------
        criticite = 1  # valeur par défaut (0 connexion)

        for valeur_criticite, seuil_connexions in sorted(
            CRITICITE_SEUILS.items(), reverse=True
        ):
            if total_connexions >= seuil_connexions:
                criticite = valeur_criticite
                break

        # ---------------------------------------------------------------------
        # ÉTAPE 3 — Bonus +1 pour les services sensibles
        # Les bases de données et le service de paiement sont plus critiques
        # car ils contiennent des données sensibles
        # Le plafond est 5 (criticité maximale)
        # ---------------------------------------------------------------------
        if noeud in SERVICES_SENSIBLES:
            criticite = min(criticite + 1, 5)
            logger.debug(f"  Bonus sensible appliqué à '{noeud}'")

        # ---------------------------------------------------------------------
        # ÉTAPE 4 — Attribution au noeud
        # ---------------------------------------------------------------------
        G0.nodes[noeud]["criticite"] = criticite

        logger.debug(
            f"  {noeud:<20} "
            f"in={in_degree} out={out_degree} "
            f"total={total_connexions} → criticité={criticite}"
        )

    log_resultat(logger, "Criticités calculées", f"{G0.number_of_nodes()} noeuds")
    return G0


# =============================================================================
# FONCTION 2 — CALCUL DU SCORE GLOBAL
# Algorithme : moyenne pondérée par la criticité
# =============================================================================

def calculer_score_global(G0: nx.DiGraph) -> dict:
    """
    Calcule le score global de sécurité du système.

    Algorithme — moyenne pondérée :
        Score_Global = Σ(criticité(s) × score_cve(s)) / Σ(criticité(s))

    On utilise une moyenne pondérée et non une moyenne arithmétique
    car un service critique vulnérable est plus dangereux qu'un service
    périphérique vulnérable. La criticité joue le rôle de pondération.

    Précondition :
        Tous les noeuds de G0 doivent avoir leur score_cve calculé
        par cve/cve_scorer.py avant d'appeler cette fonction.

    Paramètre :
        G0 (nx.DiGraph) : graphe avec score_cve et criticite renseignés

    Retourne :
        dict : {
            'score_global' : float (0-100),
            'niveau'       : str ('SAIN', 'STABLE', 'DEGRADE', 'CRITIQUE'),
            'details'      : liste des scores par service
        }
    """

    log_separateur(logger, "Calcul du Score Global")

    somme_ponderee = 0.0
    somme_poids    = 0
    details        = []
    services_sans_score = []

    for noeud, attributs in G0.nodes(data=True):

        # On exclut Outside du calcul du score global
        if noeud == OUTSIDE_NODE:
            continue

        score_cve  = attributs.get("score_cve")
        criticite  = attributs.get("criticite", 1)

        # Signale les services dont le score CVE n'a pas encore été calculé
        if score_cve is None:
            services_sans_score.append(noeud)
            logger.warning(
                f"Score CVE absent pour '{noeud}' — "
                f"ce service sera ignoré du calcul global"
            )
            continue

        contribution    = criticite * score_cve
        somme_ponderee += contribution
        somme_poids    += criticite

        details.append({
            "service"     : noeud,
            "score_cve"   : round(score_cve, 2),
            "criticite"   : criticite,
            "contribution": round(contribution, 2)
        })

        logger.debug(
            f"  {noeud:<20} "
            f"score_cve={score_cve:.1f} "
            f"criticite={criticite} "
            f"contribution={contribution:.1f}"
        )

    if services_sans_score:
        logger.warning(
            f"{len(services_sans_score)} services ignorés "
            f"(score CVE absent) : {services_sans_score}"
        )

    # -------------------------------------------------------------------------
    # Calcul de la moyenne pondérée
    # -------------------------------------------------------------------------
    if somme_poids == 0:
        logger.error("Impossible de calculer le score global — aucun service valide")
        return None

    score_global = round(somme_ponderee / somme_poids, 1)

    # -------------------------------------------------------------------------
    # Détermination du niveau de sécurité
    # -------------------------------------------------------------------------
    niveau = _determiner_niveau(score_global)

    # -------------------------------------------------------------------------
    # Attribution du niveau à chaque noeud dans G0
    # -------------------------------------------------------------------------
    for noeud, attributs in G0.nodes(data=True):
        if noeud == OUTSIDE_NODE:
            continue
        score = attributs.get("score_cve")
        if score is not None:
            G0.nodes[noeud]["niveau"] = _determiner_niveau(score)

    # -------------------------------------------------------------------------
    # Résumé
    # -------------------------------------------------------------------------
    log_resultat(logger, "Score global",    f"{score_global}/100")
    log_resultat(logger, "Niveau sécurité", niveau)
    log_resultat(logger, "Services évalués", len(details))

    return {
        "score_global": score_global,
        "niveau"      : niveau,
        "details"     : sorted(details, key=lambda x: x["score_cve"])
    }


# =============================================================================
# FONCTION UTILITAIRE — DÉTERMINATION DU NIVEAU
# =============================================================================

def _determiner_niveau(score: float) -> str:
    """
    Détermine le niveau de sécurité correspondant à un score.

    Niveaux (définis dans config/settings.py) :
        90-100 → SAIN
        70-89  → STABLE
        50-69  → DÉGRADÉ
        0-49   → CRITIQUE

    Retourne :
        str : niveau de sécurité
    """
    for niveau, (borne_inf, borne_sup) in SCORE_LEVELS.items():
        if borne_inf <= score <= borne_sup:
            return niveau
    return "CRITIQUE"


# =============================================================================
# TEST RAPIDE — Exécution directe du fichier
# python graph/scorer.py
# =============================================================================

if __name__ == "__main__":
    import sys
    sys.path.insert(0, "..")

    # Graphe de test minimal
    G0 = nx.DiGraph()
    G0.add_node("front-end",   score_cve=48, criticite=None, niveau=None, type_noeud="service")
    G0.add_node("catalogue",   score_cve=68, criticite=None, niveau=None, type_noeud="service")
    G0.add_node("orders",      score_cve=76, criticite=None, niveau=None, type_noeud="service")
    G0.add_node("orders-db",   score_cve=24, criticite=None, niveau=None, type_noeud="service")
    G0.add_node("payment",     score_cve=0,  criticite=None, niveau=None, type_noeud="service")
    G0.add_node(OUTSIDE_NODE,  score_cve=None, criticite=0,  niveau="EXTERNE", type_noeud="attaquant_externe")

    G0.add_edge("front-end",  "catalogue",  type_arete="DEPENDS_ON")
    G0.add_edge("front-end",  "orders",     type_arete="DEPENDS_ON")
    G0.add_edge("orders",     "orders-db",  type_arete="DEPENDS_ON")
    G0.add_edge(OUTSIDE_NODE, "front-end",  type_arete="PEUT_ATTAQUER")

    G0 = calculer_criticites(G0)
    resultat = calculer_score_global(G0)

    print(f"\n{'='*50}")
    print(f"Score global : {resultat['score_global']}/100 → {resultat['niveau']}")
    print(f"\nDétail par service :")
    for d in resultat["details"]:
        print(f"  {d['service']:<20} score={d['score_cve']} criticite={d['criticite']}")