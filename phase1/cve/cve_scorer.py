# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : cve/cve_scorer.py
# Rôle    : Calcule le Score_CVE pour chaque service et enrichit G0
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================

import networkx as nx

from config.settings import CVE_WEIGHTS, OUTSIDE_NODE
from cve.cve_client  import interroger_cve_par_image
from utils.logger    import get_logger, log_separateur, log_resultat

logger = get_logger(__name__)


# =============================================================================
# FONCTION PRINCIPALE — ENRICHISSEMENT DE G0 AVEC LES SCORES CVE
# =============================================================================

def enrichir_G0_avec_scores_cve(G0: nx.DiGraph) -> nx.DiGraph:
    """
    Interroge l'API CVE pour chaque service de G0 et calcule son Score_CVE.

    Cette fonction fait le lien entre le module cve/ et le graphe G0.
    Elle enrichit chaque noeud de G0 avec son score_cve calculé,
    rendant G0 prêt pour le calcul du score global dans graph/scorer.py.

    Paramètre :
        G0 (nx.DiGraph) : graphe construit par builder.py

    Retourne :
        nx.DiGraph : G0 avec l'attribut score_cve renseigné sur chaque noeud
    """

    log_separateur(logger, "Calcul des scores CVE")

    nb_services  = 0
    nb_erreurs   = 0

    for noeud, attributs in G0.nodes(data=True):

        # Outside n'a pas d'image Docker — on l'ignore
        if noeud == OUTSIDE_NODE:
            continue

        image = attributs.get("image", "unknown")

        if image == "unknown":
            logger.warning(f"Image inconnue pour '{noeud}' — score CVE = 50 (valeur neutre)")
            G0.nodes[noeud]["score_cve"] = 50.0
            nb_services += 1
            continue

        # -------------------------------------------------------------------------
        # Interrogation de l'API CVE pour cette image
        # -------------------------------------------------------------------------
        logger.debug(f"Scan CVE : {noeud} ({image})")
        resultats_cve = interroger_cve_par_image(image)

        if resultats_cve.get("erreur"):
            logger.warning(
                f"Impossible de récupérer les CVE pour '{noeud}' "
                f"— score CVE = 100 (hypothèse conservative : aucune faille)"
            )
            G0.nodes[noeud]["score_cve"] = 100.0
            nb_erreurs  += 1
            nb_services += 1
            continue

        # -------------------------------------------------------------------------
        # Calcul du Score_CVE
        # -------------------------------------------------------------------------
        score = calculer_score_cve(
            critical = resultats_cve.get("CRITICAL", 0),
            high     = resultats_cve.get("HIGH",     0),
            medium   = resultats_cve.get("MEDIUM",   0),
            low      = resultats_cve.get("LOW",      0)
        )

        G0.nodes[noeud]["score_cve"] = score
        nb_services += 1

        logger.info(
            f"  {noeud:<20} "
            f"C={resultats_cve['CRITICAL']} "
            f"H={resultats_cve['HIGH']} "
            f"M={resultats_cve['MEDIUM']} "
            f"L={resultats_cve['LOW']} "
            f"→ score={score}/100 "
            f"[source:{resultats_cve['source']}]"
        )

    log_resultat(logger, "Services scannés", nb_services)
    log_resultat(logger, "Erreurs API",      nb_erreurs)

    return G0


# =============================================================================
# FONCTION PRINCIPALE — CALCUL DU SCORE CVE
# Algorithme : pénalité pondérée par sévérité CVSS
# =============================================================================

def calculer_score_cve(critical: int = 0,
                        high    : int = 0,
                        medium  : int = 0,
                        low     : int = 0) -> float:
    """
    Calcule le Score_CVE d'un service à partir de ses compteurs de CVE.

    Algorithme — pénalité pondérée par sévérité CVSS v3.1 :

        Pénalité = CRITICAL × 10 + HIGH × 7 + MEDIUM × 4 + LOW × 1
        Score    = max(0, 100 - Pénalité)

    Les coefficients (10, 7, 4, 1) reflètent la hiérarchie officielle
    du standard CVSS v3.1 :
        CRITICAL : exploitation triviale, impact maximal (RCE possible)
        HIGH     : exploitation facile, impact élevé (privilege escalation)
        MEDIUM   : exploitation conditionnelle, impact modéré
        LOW      : exploitation difficile, impact limité

    Le plafonnement à 0 via max(0, ...) évite les scores négatifs
    qui n'ont pas de sens sur une échelle de 0 à 100.

    Paramètres :
        critical (int) : nombre de CVE CRITICAL
        high     (int) : nombre de CVE HIGH
        medium   (int) : nombre de CVE MEDIUM
        low      (int) : nombre de CVE LOW

    Retourne :
        float : score entre 0 et 100 (0 = très vulnérable, 100 = sain)
    """

    penalite = (
        critical * CVE_WEIGHTS["CRITICAL"] +
        high     * CVE_WEIGHTS["HIGH"]     +
        medium   * CVE_WEIGHTS["MEDIUM"]   +
        low      * CVE_WEIGHTS["LOW"]
    )

    score = max(0.0, 100.0 - penalite)

    logger.debug(
        f"Calcul Score_CVE : "
        f"C={critical}×{CVE_WEIGHTS['CRITICAL']} + "
        f"H={high}×{CVE_WEIGHTS['HIGH']} + "
        f"M={medium}×{CVE_WEIGHTS['MEDIUM']} + "
        f"L={low}×{CVE_WEIGHTS['LOW']} "
        f"= pénalité {penalite} → score {score}/100"
    )

    return round(score, 1)


# =============================================================================
# FONCTION UTILITAIRE — SIMULATION POUR TESTS SANS API
# Permet de tester tout le pipeline sans connexion internet
# =============================================================================

def simuler_scores_cve(G0: nx.DiGraph) -> nx.DiGraph:
    """
    Injecte des scores CVE simulés dans G0 pour les tests hors-ligne.

    Ces valeurs correspondent aux résultats réels de Sock Shop
    documentés dans le cours Phase 1. Elles permettent de tester
    les phases 3 et 4 sans dépendre des APIs OSV/NVD.

    ATTENTION : à utiliser uniquement en environnement de test.

    Retourne :
        nx.DiGraph : G0 enrichi avec des scores simulés
    """

    scores_simules = {
        "front-end"   : 48.0,
        "catalogue"   : 68.0,
        "catalogue-db": 50.0,
        "orders"      : 76.0,
        "orders-db"   : 24.0,
        "cart"        : 86.0,
        "cart-db"     : 92.0,
        "user"        : 62.0,
        "user-db"     : 42.0,
        "payment"     : 14.0,
        "shipping"    : 78.0,
        "queue-master": 70.0,
        "rabbitmq"    : 60.0,
        "edge-router" : 76.0
    }

    logger.warning("MODE SIMULATION — scores CVE simulés (Sock Shop réels)")

    for noeud in G0.nodes:
        if noeud == OUTSIDE_NODE:
            continue
        score = scores_simules.get(noeud, 70.0)
        G0.nodes[noeud]["score_cve"] = score
        logger.debug(f"  Simulation : {noeud} → {score}/100")

    return G0


# =============================================================================
# TEST RAPIDE — Exécution directe du fichier
# python cve/cve_scorer.py
# =============================================================================

if __name__ == "__main__":

    print("=== Test de la formule calculer_score_cve ===\n")

    cas_tests = [
        {"nom": "payment",    "C": 5, "H": 7, "M": 9,  "L": 0},
        {"nom": "orders-db",  "C": 4, "H": 6, "M": 10, "L": 0},
        {"nom": "cart-db",    "C": 0, "H": 1, "M": 2,  "L": 0},
        {"nom": "cart",       "C": 0, "H": 2, "M": 3,  "L": 0},
        {"nom": "front-end",  "C": 2, "H": 5, "M": 8,  "L": 3},
    ]

    print(f"{'Service':<15} {'C':>3} {'H':>3} {'M':>3} {'L':>3} {'Pénalité':>10} {'Score':>8}")
    print("-" * 55)

    for cas in cas_tests:
        penalite = (
            cas["C"] * 10 +
            cas["H"] *  7 +
            cas["M"] *  4 +
            cas["L"] *  1
        )
        score = max(0, 100 - penalite)
        print(
            f"{cas['nom']:<15} "
            f"{cas['C']:>3} {cas['H']:>3} {cas['M']:>3} {cas['L']:>3} "
            f"{penalite:>10} "
            f"{score:>7}/100"
        )