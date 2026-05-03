# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : parsers/docker_parser.py
# Rôle    : Lit docker-compose.yml et extrait les informations sécuritaires
#           de chaque service pour construire G0
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================

import yaml

from config.settings import DOCKER_COMPOSE_PATH, OUTSIDE_NODE
from utils.logger import get_logger, log_separateur, log_resultat

logger = get_logger(__name__)


# =============================================================================
# FONCTION PRINCIPALE — PARSING DU DOCKER-COMPOSE.YML
# =============================================================================

def parser_docker_compose() -> dict:
    """
    Lit le fichier docker-compose.yml et extrait les informations
    sécuritaires de chaque service.

    Algorithme — parseur à extraction sélective :
        1. Charger le fichier YAML en mémoire (PyYAML)
        2. Pour chaque service, extraire les attributs sécuritaires
        3. Normaliser chaque service en un dictionnaire standard
        4. Identifier les services exposés vers l'extérieur
        5. Retourner la structure complète

    Retourne :
        dict : {
            'services'         : { nom_service : service_descriptor },
            'services_exposes' : [ liste des services avec ports ouverts ],
            'total_noeuds'     : int,
            'total_aretes'     : int
        }
    """

    log_separateur(logger, "Parsing Docker Compose")
    logger.info(f"Lecture de : {DOCKER_COMPOSE_PATH}")

    # -------------------------------------------------------------------------
    # ÉTAPE 1 — Chargement du fichier YAML
    # yaml.safe_load() est utilisé (pas yaml.load()) pour des raisons
    # de sécurité : safe_load interdit l'exécution de code Python embarqué
    # -------------------------------------------------------------------------
    contenu_yaml = _charger_yaml(DOCKER_COMPOSE_PATH)
    if contenu_yaml is None:
        return None

    # Vérifie que la clé 'services' existe dans le fichier
    if "services" not in contenu_yaml:
        logger.error("Clé 'services' absente du fichier docker-compose.yml")
        return None

    services_bruts = contenu_yaml["services"]
    logger.debug(f"{len(services_bruts)} services bruts trouvés dans le YAML")

    # -------------------------------------------------------------------------
    # ÉTAPE 2 — Extraction sélective des attributs sécuritaires
    # Pour chaque service, on construit un service_descriptor normalisé
    # -------------------------------------------------------------------------
    services          = {}
    services_exposes  = []
    total_aretes      = 0

    for nom_service, config in services_bruts.items():

        if config is None:
            config = {}

        descriptor = _extraire_attributs(nom_service, config)
        services[nom_service] = descriptor

        # Compte les arêtes DEPENDS_ON pour les statistiques
        total_aretes += len(descriptor["depends_on"])

        # Identifie les services exposés vers l'extérieur (ports ouverts)
        if descriptor["ports_exposes"]:
            services_exposes.append(nom_service)
            logger.debug(
                f"Service exposé détecté : {nom_service} "
                f"→ ports {descriptor['ports_exposes']}"
            )

    # -------------------------------------------------------------------------
    # ÉTAPE 3 — Ajout des arêtes PEUT_ATTAQUER depuis Outside
    # Un service exposé = Outside peut l'attaquer directement
    # -------------------------------------------------------------------------
    total_aretes += len(services_exposes)

    # -------------------------------------------------------------------------
    # ÉTAPE 4 — Résumé de l'extraction
    # -------------------------------------------------------------------------
    total_noeuds = len(services) + 1  # +1 pour le noeud Outside

    log_resultat(logger, "Services détectés", len(services))
    log_resultat(logger, "Services exposés", f"{services_exposes}")
    log_resultat(logger, "Noeuds dans G0", f"{total_noeuds} (dont Outside)")
    log_resultat(logger, "Arêtes détectées", total_aretes)

    return {
        "services"        : services,
        "services_exposes": services_exposes,
        "total_noeuds"    : total_noeuds,
        "total_aretes"    : total_aretes
    }


# =============================================================================
# EXTRACTION DES ATTRIBUTS SÉCURITAIRES D'UN SERVICE
# =============================================================================

def _extraire_attributs(nom: str, config: dict) -> dict:
    """
    Construit le service_descriptor normalisé pour un service donné.

    Un service_descriptor est un dictionnaire standardisé contenant
    tous les attributs sécuritaires extraits du fichier YAML.
    Ce format est indépendant de la complexité du YAML source.

    Paramètres :
        nom    (str)  : nom du service (ex: 'front-end')
        config (dict) : section du service dans le YAML

    Retourne :
        dict : service_descriptor avec les champs suivants :
            - nom           : nom du service
            - image         : image Docker utilisée
            - ports_exposes : liste des ports exposés vers l'extérieur
            - depends_on    : liste des services dont ce service dépend
            - networks      : liste des réseaux Docker auxquels il appartient
            - privileged    : True si le service tourne en mode privilégié
            - docker_sock   : True si le socket Docker est monté (risque élevé)
            - score_cve     : None (sera rempli par cve/cve_scorer.py)
            - criticite     : None (sera rempli par graph/scorer.py)
    """

    # Extraction de l'image Docker
    image = config.get("image", "unknown")

    # Extraction des ports exposés
    # Format YAML possible : "80:8079" ou "8080:8080/tcp"
    # On extrait uniquement le port hôte (partie gauche du ':')
    ports_bruts  = config.get("ports", [])
    ports_exposes = _extraire_ports(ports_bruts)

    # Extraction des dépendances (depends_on)
    # Format possible : liste simple ou dictionnaire avec conditions
    depends_on_brut = config.get("depends_on", [])
    depends_on      = _normaliser_depends_on(depends_on_brut)

    # Extraction des réseaux
    networks_brut = config.get("networks", {})
    if isinstance(networks_brut, list):
        networks = networks_brut
    elif isinstance(networks_brut, dict):
        networks = list(networks_brut.keys())
    else:
        networks = []

    # Détection du mode privilégié (risque critique)
    # Un conteneur privilégié a accès complet à l'hôte Docker
    privileged = config.get("privileged", False)
    if privileged:
        logger.warning(
            f"[RISQUE] Service '{nom}' tourne en mode privilégié "
            f"— accès complet à l'hôte Docker"
        )

    # Détection du montage du socket Docker (risque critique)
    # Donne accès à tous les conteneurs depuis ce service
    docker_sock = _detecter_docker_sock(config.get("volumes", []))
    if docker_sock:
        logger.warning(
            f"[RISQUE] Service '{nom}' monte /var/run/docker.sock "
            f"— contrôle total du daemon Docker"
        )

    return {
        "nom"          : nom,
        "image"        : image,
        "ports_exposes": ports_exposes,
        "depends_on"   : depends_on,
        "networks"     : networks,
        "privileged"   : privileged,
        "docker_sock"  : docker_sock,
        "score_cve"    : None,   # rempli par cve/cve_scorer.py
        "criticite"    : None    # rempli par graph/scorer.py
    }


# =============================================================================
# FONCTIONS UTILITAIRES PRIVÉES
# =============================================================================

def _charger_yaml(chemin: str) -> dict:
    """
    Charge et parse le fichier YAML de façon sécurisée.

    Utilise yaml.safe_load() et non yaml.load() pour interdire
    l'exécution de code Python potentiellement malveillant
    embarqué dans le fichier YAML.

    Retourne :
        dict : contenu parsé, ou None en cas d'erreur
    """
    try:
        with open(chemin, "r", encoding="utf-8") as f:
            contenu = yaml.safe_load(f)
            logger.debug("Fichier YAML chargé avec succès")
            return contenu
    except FileNotFoundError:
        logger.error(f"Fichier introuvable : {chemin}")
        return None
    except yaml.YAMLError as e:
        logger.error(f"Erreur de syntaxe YAML dans {chemin} : {e}")
        return None
    except Exception as e:
        logger.error(f"Erreur inattendue lors du chargement YAML : {e}")
        return None


def _extraire_ports(ports_bruts: list) -> list:
    """
    Extrait les numéros de ports exposés vers l'hôte.

    Formats acceptés :
        "80:8079"         → port hôte = 80
        "8080:8080/tcp"   → port hôte = 8080
        80                → port hôte = 80

    Retourne :
        list : liste des ports hôtes sous forme d'entiers
    """
    ports = []
    for p in ports_bruts:
        try:
            port_str = str(p).split(":")[0].split("/")[0].strip()
            ports.append(int(port_str))
        except (ValueError, IndexError):
            logger.debug(f"Port ignoré (format non reconnu) : {p}")
    return ports


def _normaliser_depends_on(depends_on_brut) -> list:
    """
    Normalise le champ depends_on qui peut avoir deux formats YAML :

    Format liste simple :
        depends_on:
            - catalogue
            - orders

    Format dictionnaire avec conditions :
        depends_on:
            catalogue:
                condition: service_healthy

    Retourne :
        list : liste des noms de services dépendants
    """
    if isinstance(depends_on_brut, list):
        return depends_on_brut
    elif isinstance(depends_on_brut, dict):
        return list(depends_on_brut.keys())
    else:
        return []


def _detecter_docker_sock(volumes: list) -> bool:
    """
    Détecte si le socket Docker est monté dans le conteneur.

    Le montage de /var/run/docker.sock donne au conteneur
    un accès complet au daemon Docker de l'hôte — risque critique.

    Retourne :
        bool : True si docker.sock est monté, False sinon
    """
    for volume in volumes:
        if "docker.sock" in str(volume):
            return True
    return False


# =============================================================================
# TEST RAPIDE — Exécution directe du fichier
# Permet de tester docker_parser.py seul : python parsers/docker_parser.py
# =============================================================================

if __name__ == "__main__":
    resultat = parser_docker_compose()
    if resultat:
        print(f"\n{'='*50}")
        print(f"Services trouvés : {list(resultat['services'].keys())}")
        print(f"Services exposés : {resultat['services_exposes']}")
        print(f"Total noeuds     : {resultat['total_noeuds']}")
        print(f"Total arêtes     : {resultat['total_aretes']}")
        print(f"{'='*50}")
        print("\nDétail du premier service :")
        premier = list(resultat['services'].values())[0]
        for cle, valeur in premier.items():
            print(f"  {cle:<15} : {valeur}")