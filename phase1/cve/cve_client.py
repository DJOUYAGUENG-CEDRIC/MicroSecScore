# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : cve/cve_client.py
# Rôle    : Interroge l'API OSV.dev pour récupérer les CVE par image Docker
#           En cas d'échec ou image propriétaire, bascule sur NVD NIST
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================

import time
import requests

from config.settings import (
    OSV_API_URL,
    NVD_API_URL,
    API_TIMEOUT,
    API_RETRIES
)
from utils.logger import get_logger

# Initialisation du logger — OBLIGATOIRE
logger = get_logger(__name__)


# =============================================================================
# STRUCTURE D'UN RÉSULTAT CVE VIDE
# =============================================================================

def _resultat_vide() -> dict:
    return {
        "CRITICAL": 0,
        "HIGH"    : 0,
        "MEDIUM"  : 0,
        "LOW"     : 0,
        "source"  : "aucune",
        "erreur"  : False
    }

def _resultat_erreur() -> dict:
    r = _resultat_vide()
    r["erreur"] = True
    r["source"] = "erreur"
    return r


# =============================================================================
# FONCTION PRINCIPALE
# Circuit Breaker : OSV.dev → NVD NIST → résultat vide
# =============================================================================

def interroger_cve_par_image(image: str) -> dict:
    """
    Récupère les CVE associées à une image Docker.

    Algorithme — Circuit Breaker avec fallback étendu :
        1. OSV.dev  → si package connu : retourner résultat
                    → si non trouvé (propriétaire) : aller sur NVD
                    → si erreur réseau : aller sur NVD
        2. NVD NIST → si réponse OK : retourner résultat
        3. Échec total → score 100 avec flag erreur
    """
    logger.debug(f"Interrogation CVE pour : {image}")
    nom_package, version = _parser_image(image)

    # Tentative 1 — OSV.dev
    resultat_osv, trouve_dans_osv = _interroger_osv_v2(nom_package, version)

    if resultat_osv is not None and trouve_dans_osv:
        resultat_osv["source"] = "osv"
        resultat_osv["erreur"] = False
        logger.debug(
            f"  OSV.dev → "
            f"C={resultat_osv['CRITICAL']} H={resultat_osv['HIGH']} "
            f"M={resultat_osv['MEDIUM']} L={resultat_osv['LOW']}"
        )
        return resultat_osv

    if not trouve_dans_osv:
        logger.info(
            f"'{image}' non indexé dans OSV.dev "
            f"(image propriétaire) — consultation NVD NIST"
        )
    else:
        logger.warning(f"OSV.dev indisponible pour '{image}' — bascule NVD NIST")

    # Tentative 2 — NVD NIST
    resultat_nvd = _interroger_nvd(nom_package, version)

    if resultat_nvd is not None:
        resultat_nvd["source"] = "nvd"
        resultat_nvd["erreur"] = False
        logger.debug(
            f"  NVD NIST → "
            f"C={resultat_nvd['CRITICAL']} H={resultat_nvd['HIGH']} "
            f"M={resultat_nvd['MEDIUM']} L={resultat_nvd['LOW']}"
        )
        return resultat_nvd

    # Échec total
    logger.error(
        f"OSV.dev et NVD NIST inaccessibles pour '{image}' — "
        f"score CVE = 100 (hypothèse conservative)"
    )
    return _resultat_erreur()


# =============================================================================
# INTERROGATION OSV.DEV
# =============================================================================

def _interroger_osv_v2(nom_package: str, version: str) -> tuple:
    """
    Interroge OSV.dev.

    Retourne :
        (dict_résultat, True)  → package connu avec ses CVE
        (None, False)          → package non trouvé ou erreur réseau
    """
    payload = {
        "package": {
            "name"     : nom_package,
            "ecosystem": "npm"
        },
        "version": version
    }

    for tentative in range(1, API_RETRIES + 1):
        try:
            response = requests.post(
                OSV_API_URL,
                json=payload,
                timeout=API_TIMEOUT
            )

            if response.status_code == 200:
                data  = response.json()
                vulns = data.get("vulns", [])

                if len(vulns) == 0 and "vulns" not in data:
                    logger.debug(
                        f"Package '{nom_package}' absent de OSV.dev "
                        f"(probablement propriétaire)"
                    )
                    return (None, False)

                compteurs = _parser_reponse_osv(data)
                return (compteurs, True)

            elif response.status_code == 404:
                logger.debug(f"Package '{nom_package}' non trouvé dans OSV.dev (404)")
                return (None, False)

            else:
                logger.debug(
                    f"OSV.dev tentative {tentative}/{API_RETRIES} "
                    f"→ HTTP {response.status_code}"
                )

        except requests.Timeout:
            logger.debug(f"OSV.dev timeout (tentative {tentative}/{API_RETRIES})")
            if tentative < API_RETRIES:
                time.sleep(2 ** tentative)

        except requests.ConnectionError:
            logger.debug(f"OSV.dev connexion refusée (tentative {tentative}/{API_RETRIES})")
            if tentative < API_RETRIES:
                time.sleep(2 ** tentative)

        except Exception as e:
            logger.debug(f"OSV.dev erreur inattendue : {e}")
            break

    return (None, False)


def _parser_reponse_osv(data: dict) -> dict:
    """Parse la réponse JSON d'OSV.dev et compte les CVE par sévérité."""
    compteurs = _resultat_vide()
    vulns     = data.get("vulns", [])

    for vuln in vulns:
        severite = _extraire_severite_osv(vuln)
        if severite in compteurs:
            compteurs[severite] += 1

    return compteurs


def _extraire_severite_osv(vuln: dict) -> str:
    """Extrait le niveau de sévérité d'une vulnérabilité OSV."""
    for sev in vuln.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            score = float(sev.get("score", 0))
            return _cvss_score_vers_niveau(score)

    sev_texte = vuln.get("database_specific", {}).get("severity", "")
    if sev_texte.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return sev_texte.upper()

    return "LOW"


# =============================================================================
# INTERROGATION NVD NIST (FALLBACK)
# =============================================================================

def _interroger_nvd(nom_package: str, version: str) -> dict:
    """
    Interroge l'API NVD NIST comme source de secours.
    Couvre les logiciels open source ET propriétaires.
    Limite de débit : 5 requêtes / 30 secondes.
    """
    compteurs = _resultat_vide()

    for niveau in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        for tentative in range(1, API_RETRIES + 1):
            try:
                params = {
                    "keywordSearch" : nom_package,
                    "cvssV3Severity": niveau
                }
                response = requests.get(
                    NVD_API_URL,
                    params=params,
                    timeout=API_TIMEOUT
                )

                if response.status_code == 200:
                    data = response.json()
                    compteurs[niveau] = data.get("totalResults", 0)
                    time.sleep(0.6)  # Respecter la limite de débit NVD
                    break

                elif response.status_code == 429:
                    logger.debug("NVD rate limit — pause 30s")
                    time.sleep(30)

                else:
                    logger.debug(
                        f"NVD tentative {tentative}/{API_RETRIES} "
                        f"→ HTTP {response.status_code}"
                    )

            except requests.Timeout:
                logger.debug(f"NVD timeout niveau {niveau} (tentative {tentative})")
                if tentative < API_RETRIES:
                    time.sleep(2 ** tentative)

            except requests.ConnectionError:
                logger.debug("NVD connexion refusée")
                return None

            except Exception as e:
                logger.debug(f"NVD erreur inattendue : {e}")
                return None

    return compteurs


# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

def _parser_image(image: str) -> tuple:
    """
    Décompose une image Docker en nom de package et version.

    Exemples :
        "weaveworksdemos/front-end:0.3.12" → ("front-end", "0.3.12")
        "mongo:3.4"                         → ("mongo", "3.4")
        "nginx"                             → ("nginx", "latest")
    """
    if "/" in image:
        parties = image.split("/")
        image   = parties[-1]

    if ":" in image:
        nom, version = image.split(":", 1)
    else:
        nom     = image
        version = "latest"

    return nom, version


def _cvss_score_vers_niveau(score: float) -> str:
    """Convertit un score CVSS numérique en niveau textuel (standard CVSS v3.1)."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "LOW"


# =============================================================================
# TEST RAPIDE
# python cve/cve_client.py
# =============================================================================

if __name__ == "__main__":
    images_test = [
        "weaveworksdemos/front-end:0.3.12",
        "mongo:3.4",
        "redis:alpine"
    ]

    for image in images_test:
        print(f"\nImage : {image}")
        resultat = interroger_cve_par_image(image)
        print(f"  Source   : {resultat['source']}")
        print(f"  CRITICAL : {resultat['CRITICAL']}")
        print(f"  HIGH     : {resultat['HIGH']}")
        print(f"  MEDIUM   : {resultat['MEDIUM']}")
        print(f"  LOW      : {resultat['LOW']}")