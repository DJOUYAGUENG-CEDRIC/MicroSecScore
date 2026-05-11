# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : cve/cve_client.py
# Rôle    : Scanner CVE basé sur Trivy CLI
#           Remplace les appels OSV.dev / NVD NIST (lents, dépendants du réseau)
#           Trivy : plus rapide (5-30s/image), plus précis, fonctionne hors-ligne
#           après le premier téléchargement de la base de vulnérabilités.
#
# Prérequis :
#   Trivy installé et dans le PATH.
#   Windows : choco install trivy
#             ou télécharger le .exe sur https://github.com/aquasecurity/trivy/releases
#   Linux   : apt install trivy  /  brew install trivy
#
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================

import json
import shutil
import subprocess

from config.settings import TRIVY_TIMEOUT
from utils.logger    import get_logger

logger = get_logger(__name__)


# =============================================================================
# STRUCTURES DE RETOUR
# Interface identique à l'ancien cve_client.py (OSV/NVD)
# =============================================================================

def _resultat_vide(source: str = "trivy") -> dict:
    return {
        "CRITICAL": 0,
        "HIGH"    : 0,
        "MEDIUM"  : 0,
        "LOW"     : 0,
        "source"  : source,
        "erreur"  : False
    }

def _resultat_erreur(source: str = "trivy_erreur") -> dict:
    r = _resultat_vide(source)
    r["erreur"] = True
    return r


# =============================================================================
# FONCTION PRINCIPALE — SCAN D'UNE IMAGE AVEC TRIVY
# =============================================================================

def interroger_cve_par_image(image: str) -> dict:
    """
    Lance Trivy pour scanner une image Docker et retourne les compteurs CVE.

    Algorithme :
        1. Vérifie que trivy est dans le PATH
        2. Exécute : trivy image --format json --quiet <image>
        3. Parse le JSON → compte CRITICAL / HIGH / MEDIUM / LOW
        4. En cas d'erreur → retourne un résultat avec erreur=True
           (cve_scorer.py lui attribue alors le score 100 par défaut)

    Paramètre :
        image (str) : nom complet de l'image Docker
                      ex: "nginx:1.21", "weaveworksdemos/front-end:0.3.12"

    Retourne :
        dict : {
            "CRITICAL" : int,
            "HIGH"     : int,
            "MEDIUM"   : int,
            "LOW"      : int,
            "source"   : str,   # "trivy" ou code d'erreur
            "erreur"   : bool
        }
    """

    # -------------------------------------------------------------------------
    # Étape 1 — Vérification de l'installation Trivy
    # -------------------------------------------------------------------------
    if not shutil.which("trivy"):
        logger.warning(
            "Trivy introuvable dans le PATH — score CVE = 100 (défaut conservateur). "
            "Installez Trivy : https://github.com/aquasecurity/trivy/releases"
        )
        return _resultat_erreur("trivy_absent")

    # -------------------------------------------------------------------------
    # Étape 2 — Lancement du scan Trivy
    # Flags utilisés :
    #   --format json   : sortie JSON structurée sur stdout
    #   --quiet         : supprime les logs de progression (hors JSON)
    #   --timeout       : timeout par image (configurable dans settings.py)
    # -------------------------------------------------------------------------
    logger.debug(f"Trivy scan : {image}")

    cmd = [
        "trivy", "image",
        "--format",  "json",
        "--quiet",
        "--timeout", f"{TRIVY_TIMEOUT}s",
        image,
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=TRIVY_TIMEOUT + 15,
        )
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")

    except subprocess.TimeoutExpired:
        logger.warning(f"Trivy timeout ({TRIVY_TIMEOUT}s) pour '{image}'")
        return _resultat_erreur("trivy_timeout")

    except FileNotFoundError:
        logger.error("Commande 'trivy' introuvable — vérifiez l'installation")
        return _resultat_erreur("trivy_absent")

    except Exception as e:
        logger.error(f"Erreur inattendue lors du scan Trivy de '{image}' : {e}")
        return _resultat_erreur("trivy_erreur")

    # -------------------------------------------------------------------------
    # Étape 3 — Vérification du code de retour
    # Trivy retourne 0 (aucune vuln) ou 1 (vulnérabilités trouvées)
    # Un code > 1 indique une erreur réelle (image inexistante, etc.)
    # -------------------------------------------------------------------------
    if proc.returncode > 1:
        logger.warning(
            f"Trivy erreur (code {proc.returncode}) pour '{image}' "
            f"— {stderr.strip()[:300]}"
        )
        return _resultat_erreur("trivy_echec")

    # -------------------------------------------------------------------------
    # Étape 4 — Parse du JSON et comptage par sévérité
    # -------------------------------------------------------------------------
    return _parser_sortie_trivy(stdout, image)


# =============================================================================
# PARSEUR DE LA SORTIE JSON TRIVY
# =============================================================================

def _parser_sortie_trivy(stdout: str, image: str) -> dict:
    """
    Parse le JSON produit par 'trivy image --format json'.

    Structure JSON Trivy :
    {
      "Results": [
        {
          "Target": "nginx:1.21 (debian 11.6)",
          "Vulnerabilities": [
            { "Severity": "HIGH", "VulnerabilityID": "CVE-2021-XXXXX", ... },
            ...
          ]
        },
        ...
      ]
    }

    Retourne :
        dict : compteurs par sévérité avec source="trivy" et erreur=False
    """
    if not stdout.strip():
        logger.warning(f"Trivy: sortie vide pour '{image}' (image non trouvée localement?)")
        return _resultat_erreur("trivy_vide")

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as e:
        logger.warning(f"Trivy: JSON invalide pour '{image}' : {e}")
        return _resultat_erreur("trivy_json_invalide")

    compteurs = _resultat_vide("trivy")

    for resultat in data.get("Results", []):
        vulns = resultat.get("Vulnerabilities") or []
        for vuln in vulns:
            severite = vuln.get("Severity", "").upper()
            if severite in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                compteurs[severite] += 1

    total = sum(compteurs[k] for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
    logger.info(
        f"  {image:<40} "
        f"CRITICAL={compteurs['CRITICAL']:>3}  "
        f"HIGH={compteurs['HIGH']:>3}  "
        f"MEDIUM={compteurs['MEDIUM']:>3}  "
        f"LOW={compteurs['LOW']:>3}  "
        f"(total: {total})  [source: Trivy]"
    )

    return compteurs


# =============================================================================
# TEST RAPIDE — Exécution directe du fichier
# python cve/cve_client.py
# =============================================================================

if __name__ == "__main__":
    images_test = [
        "nginx:1.21",
        "mongo:3.4",
        "redis:alpine",
        "node:14.17.0-alpine",
    ]

    print("=== Test Trivy CVE Scanner ===\n")

    for image in images_test:
        print(f"Image : {image}")
        r = interroger_cve_par_image(image)
        if r["erreur"]:
            print(f"  ⚠ Erreur : {r['source']}")
        else:
            print(f"  CRITICAL : {r['CRITICAL']}")
            print(f"  HIGH     : {r['HIGH']}")
            print(f"  MEDIUM   : {r['MEDIUM']}")
            print(f"  LOW      : {r['LOW']}")
            print(f"  Source   : {r['source']}")
        print()
