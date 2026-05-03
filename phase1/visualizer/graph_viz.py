# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : visualizer/graph_viz.py
# Rôle    : Génère la représentation visuelle de G0
#           Mode statique (matplotlib/PNG) ou interactif (pyvis/HTML)
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================

import os
import networkx as nx
import matplotlib
matplotlib.use("Agg")   # Mode sans interface graphique (serveur)
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from config.settings import OUTPUT_DIR, OUTSIDE_NODE, SCORE_COLORS
from utils.logger    import get_logger, log_separateur, log_resultat

logger = get_logger(__name__)

# =============================================================================
# CODES COULEUR PAR NIVEAU DE SÉCURITÉ
# =============================================================================

COULEURS_NIVEAUX = {
    "SAIN"    : "#2E7D32",   # vert foncé
    "STABLE"  : "#F9A825",   # jaune
    "DEGRADE" : "#E65100",   # orange foncé
    "CRITIQUE": "#B71C1C",   # rouge foncé
    "EXTERNE" : "#424242",   # gris foncé (Outside)
    "N/A"     : "#78909C"    # gris bleu (score non calculé)
}

COULEURS_ARETES = {
    "DEPENDS_ON"    : "#1565C0",   # bleu — communication autorisée
    "PEUT_ATTAQUER" : "#C62828"    # rouge — vecteur d'attaque
}


# =============================================================================
# FONCTION UNIFIÉE — POINT D'ENTRÉE PRINCIPAL
# =============================================================================

def visualiser_G0(G0: nx.DiGraph,
                  mode: str = "les_deux") -> dict:
    """
    Génère la visualisation de G0 dans le mode demandé.

    Paramètres :
        G0   (nx.DiGraph) : graphe à visualiser
        mode (str)        : 'matplotlib', 'pyvis', ou 'les_deux'

    Retourne :
        dict : { 'png': chemin_fichier, 'html': chemin_fichier }
    """
    log_separateur(logger, "Visualisation de G0")
    resultats = {}

    if mode in ("matplotlib", "les_deux"):
        chemin_png = visualiser_matplotlib(G0)
        if chemin_png:
            resultats["png"] = chemin_png

    if mode in ("pyvis", "les_deux"):
        chemin_html = visualiser_pyvis(G0)
        if chemin_html:
            resultats["html"] = chemin_html

    return resultats


# =============================================================================
# RENDU STATIQUE — MATPLOTLIB
# =============================================================================

def visualiser_matplotlib(G0: nx.DiGraph) -> str:
    """
    Génère une image PNG statique de G0 avec matplotlib.

    Algorithme — layout Fruchterman-Reingold :
        Traite le graphe comme un système physique :
        - Les noeuds se repoussent (forces électrostatiques)
        - Les arêtes les attirent (forces de ressort)
        L'état d'équilibre produit une disposition lisible
        où les noeuds proches sont naturellement regroupés.

    Code couleur des noeuds :
        Vert    → SAIN     (score 90-100)
        Jaune   → STABLE   (score 70-89)
        Orange  → DÉGRADÉ  (score 50-69)
        Rouge   → CRITIQUE (score 0-49)
        Gris    → Outside  (attaquant externe)

    Code couleur des arêtes :
        Bleu    → DEPENDS_ON    (communication autorisée)
        Rouge   → PEUT_ATTAQUER (vecteur d'attaque)

    Retourne :
        str : chemin du fichier PNG généré
    """

    logger.debug("Génération du rendu matplotlib")

    try:
        fig, ax = plt.subplots(figsize=(16, 10))
        ax.set_facecolor("#F8F9FA")
        fig.patch.set_facecolor("#F8F9FA")

        # ---------------------------------------------------------------------
        # LAYOUT — Fruchterman-Reingold
        # seed=42 garantit un positionnement reproductible
        # k contrôle l'espacement entre noeuds
        # ---------------------------------------------------------------------
        pos = nx.spring_layout(G0, seed=42, k=2.5)

        # ---------------------------------------------------------------------
        # COULEURS DES NOEUDS selon le niveau de sécurité
        # ---------------------------------------------------------------------
        couleurs_noeuds = []
        tailles_noeuds  = []

        for noeud, attributs in G0.nodes(data=True):
            niveau   = attributs.get("niveau", "N/A")
            couleur  = COULEURS_NIVEAUX.get(niveau, COULEURS_NIVEAUX["N/A"])
            couleurs_noeuds.append(couleur)

            # Outside est plus petit — c'est un noeud externe
            if noeud == OUTSIDE_NODE:
                tailles_noeuds.append(1500)
            else:
                # Taille proportionnelle à la criticité
                criticite = attributs.get("criticite", 1) or 1
                tailles_noeuds.append(800 + criticite * 300)

        # ---------------------------------------------------------------------
        # COULEURS DES ARÊTES selon le type
        # ---------------------------------------------------------------------
        couleurs_aretes = []
        styles_aretes   = []

        for _, _, data in G0.edges(data=True):
            type_arete = data.get("type_arete", "DEPENDS_ON")
            couleurs_aretes.append(
                COULEURS_ARETES.get(type_arete, "#1565C0")
            )
            # Arêtes PEUT_ATTAQUER en pointillés pour les distinguer
            styles_aretes.append(
                "dashed" if type_arete == "PEUT_ATTAQUER" else "solid"
            )

        # ---------------------------------------------------------------------
        # DESSIN DES ARÊTES
        # On dessine séparément les deux types d'arêtes
        # pour appliquer des styles différents
        # ---------------------------------------------------------------------
        aretes_depends  = [
            (s, t) for s, t, d in G0.edges(data=True)
            if d.get("type_arete") == "DEPENDS_ON"
        ]
        aretes_attaque  = [
            (s, t) for s, t, d in G0.edges(data=True)
            if d.get("type_arete") == "PEUT_ATTAQUER"
        ]

        nx.draw_networkx_edges(
            G0, pos,
            edgelist    = aretes_depends,
            edge_color  = COULEURS_ARETES["DEPENDS_ON"],
            arrows      = True,
            arrowsize   = 20,
            width       = 1.5,
            alpha       = 0.7,
            ax          = ax
        )
        nx.draw_networkx_edges(
            G0, pos,
            edgelist    = aretes_attaque,
            edge_color  = COULEURS_ARETES["PEUT_ATTAQUER"],
            arrows      = True,
            arrowsize   = 25,
            width       = 2.5,
            style       = "dashed",
            alpha       = 0.9,
            ax          = ax
        )

        # ---------------------------------------------------------------------
        # DESSIN DES NOEUDS
        # ---------------------------------------------------------------------
        nx.draw_networkx_nodes(
            G0, pos,
            node_color  = couleurs_noeuds,
            node_size   = tailles_noeuds,
            alpha       = 0.9,
            ax          = ax
        )

        # ---------------------------------------------------------------------
        # LABELS DES NOEUDS
        # Affiche le nom + score CVE sur deux lignes
        # ---------------------------------------------------------------------
        labels = {}
        for noeud, attributs in G0.nodes(data=True):
            score = attributs.get("score_cve")
            if score is not None and noeud != OUTSIDE_NODE:
                labels[noeud] = f"{noeud}\n{score}/100"
            else:
                labels[noeud] = noeud

        nx.draw_networkx_labels(
            G0, pos,
            labels      = labels,
            font_size   = 7,
            font_color  = "white",
            font_weight = "bold",
            ax          = ax
        )

        # ---------------------------------------------------------------------
        # LÉGENDE
        # ---------------------------------------------------------------------
        legendes = [
            mpatches.Patch(color=COULEURS_NIVEAUX["SAIN"],     label="SAIN (90-100)"),
            mpatches.Patch(color=COULEURS_NIVEAUX["STABLE"],   label="STABLE (70-89)"),
            mpatches.Patch(color=COULEURS_NIVEAUX["DEGRADE"],  label="DÉGRADÉ (50-69)"),
            mpatches.Patch(color=COULEURS_NIVEAUX["CRITIQUE"], label="CRITIQUE (0-49)"),
            mpatches.Patch(color=COULEURS_NIVEAUX["EXTERNE"],  label="Attaquant externe"),
        ]
        ax.legend(
            handles     = legendes,
            loc         = "upper left",
            fontsize    = 9,
            framealpha  = 0.9
        )

        ax.set_title(
            "MicroSecScore — Graphe G0 des communications autorisées",
            fontsize=14, fontweight="bold", pad=20
        )
        ax.axis("off")
        plt.tight_layout()

        # ---------------------------------------------------------------------
        # SAUVEGARDE
        # ---------------------------------------------------------------------
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        chemin_png = os.path.join(OUTPUT_DIR, "graph_G0.png")
        plt.savefig(chemin_png, dpi=150, bbox_inches="tight")
        plt.close()

        log_resultat(logger, "Rendu PNG généré", chemin_png)
        return chemin_png

    except Exception as e:
        logger.error(f"Erreur lors du rendu matplotlib : {e}")
        return None


# =============================================================================
# RENDU INTERACTIF — PYVIS
# =============================================================================

def visualiser_pyvis(G0: nx.DiGraph) -> str:
    """
    Génère un fichier HTML interactif de G0 avec pyvis.

    Le rendu pyvis permet :
        - Zoomer et déplacer les noeuds à la souris
        - Survoler un noeud pour voir ses attributs
        - Cliquer sur un noeud pour le sélectionner
        - Filtrer les arêtes par type

    Ce format est idéal pour la démonstration en soutenance :
    il s'ouvre dans n'importe quel navigateur web, sans installation.

    Retourne :
        str : chemin du fichier HTML généré
    """

    try:
        from pyvis.network import Network
    except ImportError:
        logger.warning(
            "pyvis non installé — rendu interactif ignoré. "
            "Installez avec : pip install pyvis"
        )
        return None

    logger.debug("Génération du rendu pyvis interactif")

    try:
        net = Network(
            height          = "750px",
            width           = "100%",
            bgcolor         = "#F8F9FA",
            font_color      = "#212121",
            directed        = True,
            notebook        = False
        )

        # Options de physique — Fruchterman-Reingold adapté pour pyvis
        net.set_options("""
        var options = {
          "physics": {
            "forceAtlas2Based": {
              "gravitationalConstant": -50,
              "centralGravity": 0.01,
              "springLength": 150,
              "springConstant": 0.08
            },
            "solver": "forceAtlas2Based",
            "stabilization": { "iterations": 150 }
          },
          "edges": {
            "arrows": { "to": { "enabled": true, "scaleFactor": 1.2 } },
            "smooth": { "type": "dynamic" }
          },
          "interaction": {
            "hover": true,
            "tooltipDelay": 200,
            "zoomView": true
          }
        }
        """)

        # ---------------------------------------------------------------------
        # AJOUT DES NOEUDS
        # ---------------------------------------------------------------------
        for noeud, attributs in G0.nodes(data=True):
            niveau    = attributs.get("niveau", "N/A")
            score_cve = attributs.get("score_cve")
            criticite = attributs.get("criticite", 1) or 1
            couleur   = COULEURS_NIVEAUX.get(niveau, COULEURS_NIVEAUX["N/A"])

            # Taille du noeud proportionnelle à la criticité
            taille = 15 + criticite * 5 if noeud != OUTSIDE_NODE else 20

            # Infobulle affichée au survol
            titre = _construire_infobulle(noeud, attributs)

            net.add_node(
                noeud,
                label   = f"{noeud}\n{score_cve}/100" if score_cve is not None else noeud,
                color   = couleur,
                size    = taille,
                title   = titre,
                font    = {"size": 12, "color": "white", "bold": True}
            )

        # ---------------------------------------------------------------------
        # AJOUT DES ARÊTES
        # ---------------------------------------------------------------------
        for source, cible, data in G0.edges(data=True):
            type_arete = data.get("type_arete", "DEPENDS_ON")
            couleur    = COULEURS_ARETES.get(type_arete, "#1565C0")
            pointille  = type_arete == "PEUT_ATTAQUER"
            largeur    = 3 if type_arete == "PEUT_ATTAQUER" else 1.5

            net.add_edge(
                source, cible,
                color   = couleur,
                dashes  = pointille,
                width   = largeur,
                title   = type_arete,
                label   = type_arete if type_arete == "PEUT_ATTAQUER" else ""
            )

        # ---------------------------------------------------------------------
        # SAUVEGARDE HTML
        # ---------------------------------------------------------------------
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        chemin_html = os.path.join(OUTPUT_DIR, "graph_G0.html")
        net.save_graph(chemin_html)

        log_resultat(logger, "Rendu HTML interactif généré", chemin_html)
        logger.info(
            f"Ouvrez {chemin_html} dans votre navigateur "
            f"pour explorer G0 de façon interactive"
        )
        return chemin_html

    except Exception as e:
        logger.error(f"Erreur lors du rendu pyvis : {e}")
        return None


# =============================================================================
# FONCTION UTILITAIRE — INFOBULLE DE NOEUD
# =============================================================================

def _construire_infobulle(nom: str, attributs: dict) -> str:
    """
    Construit le texte de l'infobulle affichée au survol dans pyvis.

    Retourne :
        str : texte HTML de l'infobulle
    """
    score     = attributs.get("score_cve",     "N/A")
    criticite = attributs.get("criticite",     "N/A")
    niveau    = attributs.get("niveau",        "N/A")
    image     = attributs.get("image",         "N/A")
    ports     = attributs.get("ports_exposes", [])
    priv      = attributs.get("privileged",    False)

    lignes = [
        f"<b>{nom}</b>",
        f"Image     : {image}",
        f"Score CVE : {score}/100",
        f"Criticité : {criticite}",
        f"Niveau    : {niveau}",
    ]

    if ports:
        lignes.append(f"Ports exposés : {ports}")
    if priv:
        lignes.append("<b style='color:red'>⚠ Mode privilégié activé</b>")

    return "<br>".join(lignes)


# =============================================================================
# TEST RAPIDE — Exécution directe du fichier
# python visualizer/graph_viz.py
# =============================================================================

if __name__ == "__main__":
    import sys
    sys.path.insert(0, "..")

    # Graphe de test Sock Shop minimal
    G0 = nx.DiGraph()

    services_test = {
        "front-end"  : {"score_cve": 48.0,  "criticite": 4, "niveau": "DEGRADE",  "image": "weaveworksdemos/front-end:0.3.12",  "ports_exposes": [80]},
        "catalogue"  : {"score_cve": 68.0,  "criticite": 3, "niveau": "DEGRADE",  "image": "weaveworksdemos/catalogue:0.3.5",   "ports_exposes": []},
        "orders"     : {"score_cve": 76.0,  "criticite": 3, "niveau": "STABLE",   "image": "weaveworksdemos/orders:0.4.7",      "ports_exposes": []},
        "orders-db"  : {"score_cve": 24.0,  "criticite": 4, "niveau": "CRITIQUE", "image": "mongo:3.4",                         "ports_exposes": []},
        "payment"    : {"score_cve": 0.0,   "criticite": 2, "niveau": "CRITIQUE", "image": "weaveworksdemos/payment:0.4.3",     "ports_exposes": []},
        "cart"       : {"score_cve": 86.0,  "criticite": 3, "niveau": "SAIN",     "image": "weaveworksdemos/cart:0.4.8",        "ports_exposes": []},
        "cart-db"    : {"score_cve": 92.0,  "criticite": 4, "niveau": "SAIN",     "image": "redis:alpine",                      "ports_exposes": []},
    }

    for nom, attrs in services_test.items():
        G0.add_node(nom, **attrs, privileged=False, docker_sock=False, type_noeud="service")

    G0.add_node(OUTSIDE_NODE, score_cve=None, criticite=0,
                niveau="EXTERNE", type_noeud="attaquant_externe",
                image="N/A", ports_exposes=[], privileged=False, docker_sock=False)

    G0.add_edge("front-end",  "catalogue",  type_arete="DEPENDS_ON")
    G0.add_edge("front-end",  "orders",     type_arete="DEPENDS_ON")
    G0.add_edge("front-end",  "cart",       type_arete="DEPENDS_ON")
    G0.add_edge("orders",     "orders-db",  type_arete="DEPENDS_ON")
    G0.add_edge("orders",     "payment",    type_arete="DEPENDS_ON")
    G0.add_edge("cart",       "cart-db",    type_arete="DEPENDS_ON")
    G0.add_edge(OUTSIDE_NODE, "front-end",  type_arete="PEUT_ATTAQUER")

    resultats = visualiser_G0(G0, mode="les_deux")
    print("\nFichiers générés :")
    for format_viz, chemin in resultats.items():
        print(f"  {format_viz.upper()} : {chemin}")