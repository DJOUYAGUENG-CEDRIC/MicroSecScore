# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : graph/exporter.py
# Rôle    : Exporte G0 en graph_G0.json et les scores en security_scores.csv
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================

import json
import os
from datetime import datetime

import networkx as nx
import pandas as pd
from networkx.readwrite import json_graph

from config.settings import (
    GRAPH_OUTPUT_PATH,
    SCORES_OUTPUT_PATH,
    OUTPUT_DIR,
    OUTSIDE_NODE
)
from utils.logger import get_logger, log_separateur, log_resultat

logger = get_logger(__name__)


# =============================================================================
# FONCTION 1 — EXPORT DU GRAPHE EN JSON
# Algorithme : sérialisation node-link format (standard NetworkX)
# =============================================================================

def exporter_graphe(G0: nx.DiGraph, horodatage: bool = True) -> str:
    """
    Exporte le graphe G0 au format JSON (node-link format).

    Algorithme — sérialisation node-link format :
        Le node-link format est le format standard NetworkX pour
        représenter un graphe en JSON. Il contient :
        - 'directed'  : True (graphe orienté)
        - 'graph'     : métadonnées du graphe
        - 'nodes'     : liste des noeuds avec leurs attributs
        - 'links'     : liste des arêtes avec leur type et direction

        Ce format est lisible par les phases 3 et 4
        et peut être rechargé en mémoire sans perte d'information.

    Paramètres :
        G0           (nx.DiGraph) : graphe à exporter
        horodatage   (bool)       : ajoute l'heure de génération aux métadonnées

    Retourne :
        str : chemin du fichier JSON généré
    """

    log_separateur(logger, "Export du Graphe G0")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # -------------------------------------------------------------------------
    # Enrichissement des métadonnées du graphe
    # -------------------------------------------------------------------------
    if horodatage:
        G0.graph["horodatage"]     = datetime.now().isoformat()
    G0.graph["nb_noeuds"]          = G0.number_of_nodes()
    G0.graph["nb_aretes"]          = G0.number_of_edges()
    G0.graph["noeuds_exposes"]     = [
        n for n, d in G0.nodes(data=True)
        if d.get("ports_exposes")
    ]

    # -------------------------------------------------------------------------
    # Sérialisation en node-link format
    # -------------------------------------------------------------------------
    donnees_json = json_graph.node_link_data(G0)

    # -------------------------------------------------------------------------
    # Écriture du fichier JSON (indenté pour lisibilité)
    # -------------------------------------------------------------------------
    try:
        with open(GRAPH_OUTPUT_PATH, "w", encoding="utf-8") as f:
            json.dump(donnees_json, f, indent=2, ensure_ascii=False)

        taille_ko = os.path.getsize(GRAPH_OUTPUT_PATH) / 1024
        log_resultat(logger, "G0 exporté",   GRAPH_OUTPUT_PATH)
        log_resultat(logger, "Taille",        f"{taille_ko:.1f} Ko")
        log_resultat(logger, "Noeuds",        G0.number_of_nodes())
        log_resultat(logger, "Arêtes",        G0.number_of_edges())

        return GRAPH_OUTPUT_PATH

    except IOError as e:
        logger.error(f"Impossible d'écrire {GRAPH_OUTPUT_PATH} : {e}")
        return None


# =============================================================================
# FONCTION 2 — EXPORT DES SCORES EN CSV
# =============================================================================

def exporter_scores_csv(G0: nx.DiGraph) -> str:
    """
    Génère le fichier security_scores.csv avec les scores de chaque service.

    Le fichier CSV contient pour chaque service :
        - service    : nom du microservice
        - image      : image Docker utilisée
        - score_cve  : score de vulnérabilité (0-100)
        - criticite  : importance dans le graphe (1-5)
        - niveau     : SAIN / STABLE / DÉGRADÉ / CRITIQUE
        - ports      : ports exposés vers l'extérieur
        - privileged : mode privilégié activé

    Ce fichier est la sortie principale lisible par un humain.

    Retourne :
        str : chemin du fichier CSV généré
    """

    log_separateur(logger, "Export des scores CSV")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # -------------------------------------------------------------------------
    # Construction de la liste de dictionnaires pour pandas
    # -------------------------------------------------------------------------
    lignes = []

    for noeud, attributs in G0.nodes(data=True):

        # On exclut Outside du CSV
        if noeud == OUTSIDE_NODE:
            continue

        score_cve = attributs.get("score_cve")
        criticite = attributs.get("criticite")
        niveau    = attributs.get("niveau", "N/A")

        lignes.append({
            "service"   : noeud,
            "image"     : attributs.get("image", "unknown"),
            "score_cve" : round(score_cve, 1) if score_cve is not None else "N/A",
            "criticite" : criticite if criticite is not None else "N/A",
            "niveau"    : niveau,
            "ports"     : str(attributs.get("ports_exposes", [])),
            "privileged": attributs.get("privileged", False)
        })

    if not lignes:
        logger.warning("Aucun service à exporter dans le CSV")
        return None

    # -------------------------------------------------------------------------
    # Tri par score_cve croissant (les plus vulnérables en premier)
    # -------------------------------------------------------------------------
    df = pd.DataFrame(lignes)

    df["_score_num"] = pd.to_numeric(df["score_cve"], errors="coerce")
    df = df.sort_values("_score_num", ascending=True)
    df = df.drop(columns=["_score_num"])

    # -------------------------------------------------------------------------
    # Écriture du CSV
    # -------------------------------------------------------------------------
    try:
        df.to_csv(SCORES_OUTPUT_PATH, index=False, encoding="utf-8")

        log_resultat(logger, "CSV exporté",    SCORES_OUTPUT_PATH)
        log_resultat(logger, "Services évalués", len(lignes))

        return SCORES_OUTPUT_PATH

    except IOError as e:
        logger.error(f"Impossible d'écrire {SCORES_OUTPUT_PATH} : {e}")
        return None


# =============================================================================
# FONCTION 3 — RECHARGEMENT DU GRAPHE DEPUIS JSON
# Permet aux phases 3 et 4 de recharger G0 sans le reconstruire
# =============================================================================

def charger_graphe(chemin: str = None) -> nx.DiGraph:
    """
    Recharge G0 depuis un fichier graph_G0.json.

    Utilisé par les phases 3 et 4 pour accéder à G0
    sans relancer toute la Phase 1.

    Paramètre :
        chemin (str) : chemin du fichier JSON (défaut : GRAPH_OUTPUT_PATH)

    Retourne :
        nx.DiGraph : le graphe G0 rechargé
    """
    if chemin is None:
        chemin = GRAPH_OUTPUT_PATH

    try:
        with open(chemin, "r", encoding="utf-8") as f:
            donnees = json.load(f)

        G0 = json_graph.node_link_graph(donnees, directed=True)
        logger.info(f"G0 rechargé depuis {chemin}")
        logger.info(f"  {G0.number_of_nodes()} noeuds, {G0.number_of_edges()} arêtes")
        return G0

    except FileNotFoundError:
        logger.error(f"Fichier introuvable : {chemin}")
        return None
    except Exception as e:
        logger.error(f"Erreur lors du rechargement de G0 : {e}")
        return None


# =============================================================================
# TEST RAPIDE — Exécution directe du fichier
# python graph/exporter.py
# =============================================================================

if __name__ == "__main__":
    import sys
    sys.path.insert(0, "..")

    # Graphe de test minimal
    G0 = nx.DiGraph()
    G0.graph["nom"] = "G0_test"

    G0.add_node("front-end",
                image="weaveworksdemos/front-end:0.3.12",
                score_cve=48, criticite=4,
                niveau="DEGRADE", ports_exposes=[80], privileged=False)
    G0.add_node("orders",
                image="weaveworksdemos/orders:0.4.7",
                score_cve=76, criticite=3,
                niveau="STABLE", ports_exposes=[], privileged=False)
    G0.add_node(OUTSIDE_NODE,
                type_noeud="attaquant_externe",
                score_cve=None, criticite=0, niveau="EXTERNE")

    G0.add_edge("front-end",  "orders",     type_arete="DEPENDS_ON")
    G0.add_edge(OUTSIDE_NODE, "front-end",  type_arete="PEUT_ATTAQUER")

    chemin_json = exporter_graphe(G0)
    chemin_csv  = exporter_scores_csv(G0)

    print(f"\nJSON : {chemin_json}")
    print(f"CSV  : {chemin_csv}")

    # Test de rechargement
    G0_recharge = charger_graphe(chemin_json)
    if G0_recharge:
        print(f"\nG0 rechargé : {G0_recharge.number_of_nodes()} noeuds")