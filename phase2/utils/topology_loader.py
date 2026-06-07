"""
utils/topology_loader.py
====================================
Charge la topologie G0 produite par Phase 1 pour enrichir
la collecte Phase 2.

DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
"""

import json
import logging
import os

from config.phase2_settings import GRAPH_G0_PATH

logger = logging.getLogger("phase2.topology_loader")


def charger_topologie_phase1() -> dict:
    """
    Lit graph_G0.json et retourne un dict :
      { "service_name": {"score_cve": float, "criticite": int, "image": str} }

    Retourne {} si le fichier est absent (comportement dégradé silencieux).
    """
    path = os.path.abspath(GRAPH_G0_PATH)
    if not os.path.isfile(path):
        logger.warning(f"graph_G0.json introuvable ({path}) — collecte sur tous les conteneurs")
        return {}

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.error(f"Erreur lecture graph_G0.json : {exc}")
        return {}

    services = {}
    for node in data.get("nodes", []):
        nom = node.get("id")
        if nom and nom != "Outside":
            services[nom] = {
                "score_cve": float(node.get("score_cve", 50.0)),
                "criticite": int(node.get("criticite", 1)),
                "image":     str(node.get("image", "unknown")),
            }

    logger.info(f"Topologie Phase 1 chargée : {len(services)} services → {list(services.keys())}")
    return services
