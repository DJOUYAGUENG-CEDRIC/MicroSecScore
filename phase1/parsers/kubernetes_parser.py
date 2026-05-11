# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : parsers/kubernetes_parser.py
# Rôle    : Interroge l'API Kubernetes pour extraire les informations
#           sécuritaires de chaque service et construire G0
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================

import os
import yaml
from kubernetes import client, config as k8s_config

from config.settings import K8S_NAMESPACE, K8S_DIR
from utils.logger import get_logger, log_separateur, log_resultat

logger = get_logger(__name__)


# =============================================================================
# FONCTION PRINCIPALE — PARSING DE L'ENVIRONNEMENT KUBERNETES
# =============================================================================

def parser_kubernetes() -> dict:
    """
    Interroge l'API Kubernetes et extrait les informations sécuritaires
    de chaque service déployé dans le namespace cible.

    Algorithme — extraction multi-ressources par agrégation :
        1. Connexion à l'API Kubernetes (kubeconfig local)
        2. Extraction des Deployments → liste des services actifs
        3. Extraction des Services K8s → ports exposés vers l'extérieur
        4. Extraction des NetworkPolicies → communications autorisées
        5. Agrégation en service_descriptors normalisés (même format
           que docker_parser.py)

    Retourne :
        dict : {
            'services'         : { nom_service : service_descriptor },
            'services_exposes' : [ liste des services avec ports ouverts ],
            'total_noeuds'     : int,
            'total_aretes'     : int
        }
    """

    log_separateur(logger, "Parsing Kubernetes")
    logger.info(f"Namespace cible : {K8S_NAMESPACE}")

    # -------------------------------------------------------------------------
    # ÉTAPE 1 — Connexion à l'API Kubernetes
    # Charge la configuration depuis ~/.kube/config (kubeconfig local)
    # -------------------------------------------------------------------------
    try:
        k8s_config.load_kube_config()
        logger.debug("Kubeconfig chargé avec succès")
    except Exception as e:
        logger.error(f"Impossible de charger le kubeconfig : {e}")
        return None

    v1      = client.CoreV1Api()
    apps_v1 = client.AppsV1Api()
    net_v1  = client.NetworkingV1Api()

    # -------------------------------------------------------------------------
    # ÉTAPE 2 — Extraction des Deployments
    # Un Deployment = un microservice qui tourne dans le cluster
    # -------------------------------------------------------------------------
    deployments = _extraire_deployments(apps_v1)
    if deployments is None:
        return None

    # -------------------------------------------------------------------------
    # ÉTAPE 3 — Extraction des Services Kubernetes
    # Un Service K8s expose un pod sur un port réseau
    # Types pertinents : NodePort et LoadBalancer = exposés vers l'extérieur
    # -------------------------------------------------------------------------
    services_k8s = _extraire_services_k8s(v1)

    # -------------------------------------------------------------------------
    # ÉTAPE 4 — Extraction des NetworkPolicies
    # Une NetworkPolicy définit les communications autorisées entre pods
    # Elle sera traduite en arêtes DEPENDS_ON dans G0
    # -------------------------------------------------------------------------
    network_policies = _extraire_network_policies(net_v1)

    # -------------------------------------------------------------------------
    # ÉTAPE 5 — Agrégation en service_descriptors normalisés
    # On fusionne les trois sources en un format identique à docker_parser.py
    # -------------------------------------------------------------------------
    services         = {}
    services_exposes = []
    total_aretes     = 0

    for nom_deploy, config_deploy in deployments.items():

        # Cherche le Service K8s correspondant à ce Deployment
        service_k8s   = services_k8s.get(nom_deploy, {})

        # Cherche les NetworkPolicies qui s'appliquent à ce pod
        depends_on    = _extraire_depends_on_depuis_policies(
                            nom_deploy, network_policies
                        )

        # Extrait les ports exposés depuis le Service K8s
        ports_exposes = service_k8s.get("ports_exposes", [])

        descriptor = {
            "nom"          : nom_deploy,
            "image"        : config_deploy.get("image", "unknown"),
            "ports_exposes": ports_exposes,
            "depends_on"   : depends_on,
            "networks"     : [K8S_NAMESPACE],
            "privileged"   : config_deploy.get("privileged", False),
            "docker_sock"  : config_deploy.get("docker_sock", False),
            "score_cve"    : None,
            "criticite"    : None
        }

        services[nom_deploy] = descriptor
        total_aretes        += len(depends_on)

        if ports_exposes:
            services_exposes.append(nom_deploy)
            logger.debug(
                f"Service exposé : {nom_deploy} "
                f"→ ports {ports_exposes}"
            )

    # Ajout des arêtes PEUT_ATTAQUER depuis Outside
    total_aretes += len(services_exposes)
    total_noeuds  = len(services) + 1   # +1 pour Outside

    log_resultat(logger, "Deployments détectés", len(services))
    log_resultat(logger, "Services exposés",     f"{services_exposes}")
    log_resultat(logger, "Noeuds dans G0",       f"{total_noeuds} (dont Outside)")
    log_resultat(logger, "Arêtes détectées",     total_aretes)

    return {
        "services"        : services,
        "services_exposes": services_exposes,
        "total_noeuds"    : total_noeuds,
        "total_aretes"    : total_aretes
    }


# =============================================================================
# FONCTIONS PRIVÉES — Extraction par type de ressource
# =============================================================================

def _extraire_deployments(apps_v1) -> dict:
    """
    Extrait tous les Deployments du namespace cible.

    Pour chaque Deployment, on extrait :
    - L'image Docker du premier conteneur
    - Le mode privilégié (securityContext)
    - Le montage éventuel de docker.sock

    Retourne :
        dict : { nom_deployment : { image, privileged, docker_sock } }
    """
    try:
        deployments_k8s = apps_v1.list_namespaced_deployment(
            namespace=K8S_NAMESPACE
        )
        logger.debug(
            f"{len(deployments_k8s.items)} deployments trouvés "
            f"dans le namespace '{K8S_NAMESPACE}'"
        )

        deployments = {}
        for deploy in deployments_k8s.items:
            nom       = deploy.metadata.name
            conteneurs = deploy.spec.template.spec.containers

            if not conteneurs:
                continue

            # On prend le premier conteneur comme représentant du service
            conteneur  = conteneurs[0]
            image      = conteneur.image or "unknown"

            # Détection du mode privilégié
            privileged = False
            if conteneur.security_context:
                privileged = conteneur.security_context.privileged or False

            # Détection du montage docker.sock
            docker_sock = False
            volumes     = deploy.spec.template.spec.volumes or []
            for vol in volumes:
                if vol.host_path and "docker.sock" in (vol.host_path.path or ""):
                    docker_sock = True
                    logger.warning(
                        f"[RISQUE] Deployment '{nom}' monte docker.sock"
                    )

            deployments[nom] = {
                "image"      : image,
                "privileged" : privileged,
                "docker_sock": docker_sock
            }

        return deployments

    except Exception as e:
        logger.error(f"Erreur extraction Deployments : {e}")
        return None


def _extraire_services_k8s(v1) -> dict:
    """
    Extrait les Services Kubernetes et identifie les ports exposés.

    Types de Service pertinents pour la sécurité :
    - NodePort      : expose le service sur un port de chaque noeud
    - LoadBalancer  : expose le service via un load balancer externe
    - ClusterIP     : interne au cluster — pas exposé vers l'extérieur

    Retourne :
        dict : { nom_service : { ports_exposes : [...] } }
    """
    try:
        services_k8s = v1.list_namespaced_service(namespace=K8S_NAMESPACE)
        services     = {}

        for svc in services_k8s.items:
            nom           = svc.metadata.name
            type_service  = svc.spec.type or "ClusterIP"
            ports_exposes = []

            # Seuls NodePort et LoadBalancer sont exposés vers l'extérieur
            if type_service in ("NodePort", "LoadBalancer"):
                for port in (svc.spec.ports or []):
                    if port.node_port:
                        ports_exposes.append(port.node_port)
                    elif port.port:
                        ports_exposes.append(port.port)

            services[nom] = {"ports_exposes": ports_exposes}

        logger.debug(f"{len(services)} services Kubernetes extraits")
        return services

    except Exception as e:
        logger.error(f"Erreur extraction Services Kubernetes : {e}")
        return {}


def _extraire_network_policies(net_v1) -> list:
    """
    Extrait les NetworkPolicies du namespace cible.

    Une NetworkPolicy définit :
    - podSelector : le pod auquel la règle s'applique
    - ingress     : les pods autorisés à communiquer VERS ce pod
    - egress      : les pods vers lesquels ce pod peut communiquer

    Ces règles seront traduites en arêtes DEPENDS_ON dans G0.

    Retourne :
        list : liste des NetworkPolicy objects
    """
    try:
        policies = net_v1.list_namespaced_network_policy(
            namespace=K8S_NAMESPACE
        )
        logger.debug(f"{len(policies.items)} NetworkPolicies trouvées")
        return policies.items

    except Exception as e:
        logger.warning(f"NetworkPolicies inaccessibles : {e}")
        return []


def _extraire_depends_on_depuis_policies(nom_service: str,
                                          policies: list) -> list:
    """
    Déduit les dépendances d'un service à partir des NetworkPolicies.

    Pour chaque NetworkPolicy dont le podSelector correspond
    au service, on extrait les pods autorisés en ingress
    (= les services qui peuvent envoyer des requêtes vers lui).

    Paramètres :
        nom_service (str)  : nom du service analysé
        policies    (list) : liste des NetworkPolicy objects

    Retourne :
        list : noms des services qui peuvent communiquer avec nom_service
    """
    depends_on = []

    for policy in policies:
        # Vérifie si cette policy s'applique à notre service
        selector = policy.spec.pod_selector
        if not selector or not selector.match_labels:
            continue

        labels = selector.match_labels
        if labels.get("app") != nom_service:
            continue

        # Extrait les sources ingress autorisées
        for ingress_rule in (policy.spec.ingress or []):
            for source in (ingress_rule._from or []):
                if source.pod_selector and source.pod_selector.match_labels:
                    source_app = source.pod_selector.match_labels.get("app")
                    if source_app and source_app not in depends_on:
                        depends_on.append(source_app)

    return depends_on


# =============================================================================
# PARSEUR BASÉ FICHIERS — Lecture de manifestes YAML locaux
# Alternative à parser_kubernetes() qui nécessite un cluster actif.
# Lit deployments.yaml, services.yaml et networkpolicies.yaml depuis un dossier.
# =============================================================================

def parser_kubernetes_fichiers(k8s_dir: str = None) -> dict:
    """
    Analyse des manifestes Kubernetes YAML locaux sans connexion au cluster.

    Paramètres :
        k8s_dir (str) : dossier contenant deployments.yaml, services.yaml
                        et optionnellement networkpolicies.yaml.
                        Si None, utilise K8S_DIR (data/input/k8s/).

    Retourne :
        dict : même format que parser_kubernetes()
    """
    dossier = k8s_dir or K8S_DIR

    log_separateur(logger, "Parsing Kubernetes (fichiers YAML)")
    logger.info(f"Dossier source : {dossier}")

    deployments      = _lire_deployments_yaml(dossier)
    if deployments is None:
        return None

    services_k8s     = _lire_services_yaml(dossier)
    network_policies = _lire_networkpolicies_yaml(dossier)

    services         = {}
    services_exposes = []
    total_aretes     = 0

    for nom, config_deploy in deployments.items():
        service_k8s   = services_k8s.get(nom, {})
        depends_on    = _extraire_depends_on_depuis_policies_yaml(nom, network_policies)
        ports_exposes = service_k8s.get("ports_exposes", [])

        descriptor = {
            "nom"          : nom,
            "image"        : config_deploy.get("image", "unknown"),
            "ports_exposes": ports_exposes,
            "depends_on"   : depends_on,
            "networks"     : [K8S_NAMESPACE],
            "privileged"   : config_deploy.get("privileged", False),
            "docker_sock"  : config_deploy.get("docker_sock", False),
            "score_cve"    : None,
            "criticite"    : None
        }

        services[nom]  = descriptor
        total_aretes  += len(depends_on)

        if ports_exposes:
            services_exposes.append(nom)
            logger.debug(f"Service exposé : {nom} → ports {ports_exposes}")

    total_aretes += len(services_exposes)
    total_noeuds  = len(services) + 1

    log_resultat(logger, "Deployments détectés", len(services))
    log_resultat(logger, "Services exposés",     f"{services_exposes}")
    log_resultat(logger, "Noeuds dans G0",       f"{total_noeuds} (dont Outside)")
    log_resultat(logger, "Arêtes détectées",     total_aretes)

    return {
        "services"        : services,
        "services_exposes": services_exposes,
        "total_noeuds"    : total_noeuds,
        "total_aretes"    : total_aretes
    }


def _extraire_depends_on_depuis_policies_yaml(nom_service: str, policies: list) -> list:
    """
    Variante de _extraire_depends_on_depuis_policies pour des dicts YAML bruts
    (issus de yaml.safe_load_all) plutôt que des objets K8s API.
    """
    depends_on = []
    for policy in policies:
        spec     = policy.get("spec", {})
        selector = spec.get("podSelector", {}).get("matchLabels", {})
        if selector.get("app") != nom_service:
            continue
        for ingress_rule in spec.get("ingress", []):
            for source in ingress_rule.get("from", []):
                source_app = source.get("podSelector", {}).get("matchLabels", {}).get("app")
                if source_app and source_app not in depends_on:
                    depends_on.append(source_app)
    return depends_on


def _lire_deployments_yaml(dossier: str) -> dict:
    chemin = os.path.join(dossier, "deployments.yaml")
    try:
        with open(chemin, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
    except FileNotFoundError:
        logger.error(f"deployments.yaml introuvable : {chemin}")
        return None
    except yaml.YAMLError as e:
        logger.error(f"Erreur YAML dans deployments.yaml : {e}")
        return None

    deployments = {}
    for doc in docs:
        if not doc or doc.get("kind") != "Deployment":
            continue
        nom      = doc["metadata"]["name"]
        conteneurs = doc.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        if not conteneurs:
            continue
        conteneur  = conteneurs[0]
        image      = conteneur.get("image", "unknown")

        privileged  = False
        sec_ctx     = conteneur.get("securityContext", {})
        if sec_ctx:
            privileged = sec_ctx.get("privileged", False)

        docker_sock = False
        for vol in doc.get("spec", {}).get("template", {}).get("spec", {}).get("volumes", []):
            host_path = vol.get("hostPath", {}).get("path", "")
            if "docker.sock" in host_path:
                docker_sock = True
                logger.warning(f"[RISQUE] Deployment '{nom}' monte docker.sock")

        deployments[nom] = {"image": image, "privileged": privileged, "docker_sock": docker_sock}

    logger.debug(f"{len(deployments)} deployments trouvés dans {chemin}")
    return deployments


def _lire_services_yaml(dossier: str) -> dict:
    chemin = os.path.join(dossier, "services.yaml")
    services = {}
    try:
        with open(chemin, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
    except FileNotFoundError:
        logger.warning(f"services.yaml introuvable : {chemin} — aucun port exposé")
        return services
    except yaml.YAMLError as e:
        logger.error(f"Erreur YAML dans services.yaml : {e}")
        return services

    for doc in docs:
        if not doc or doc.get("kind") != "Service":
            continue
        nom          = doc["metadata"]["name"]
        type_service = doc.get("spec", {}).get("type", "ClusterIP")
        ports_exposes = []
        if type_service in ("NodePort", "LoadBalancer"):
            for port in doc.get("spec", {}).get("ports", []):
                node_port = port.get("nodePort") or port.get("port")
                if node_port:
                    ports_exposes.append(node_port)
        services[nom] = {"ports_exposes": ports_exposes}

    logger.debug(f"{len(services)} services trouvés dans {chemin}")
    return services


def _lire_networkpolicies_yaml(dossier: str) -> list:
    chemin = os.path.join(dossier, "networkpolicies.yaml")
    policies = []
    try:
        with open(chemin, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
    except FileNotFoundError:
        logger.warning(f"networkpolicies.yaml introuvable : {chemin} — dépendances ignorées")
        return policies
    except yaml.YAMLError as e:
        logger.error(f"Erreur YAML dans networkpolicies.yaml : {e}")
        return policies

    for doc in docs:
        if doc and doc.get("kind") == "NetworkPolicy":
            policies.append(doc)

    logger.debug(f"{len(policies)} NetworkPolicies trouvées dans {chemin}")
    return policies


# =============================================================================
# TEST RAPIDE — Exécution directe du fichier
# Permet de tester kubernetes_parser.py seul :
# python parsers/kubernetes_parser.py
# =============================================================================

if __name__ == "__main__":
    resultat = parser_kubernetes()
    if resultat:
        print(f"\n{'='*50}")
        print(f"Services trouvés : {list(resultat['services'].keys())}")
        print(f"Services exposés : {resultat['services_exposes']}")
        print(f"Total noeuds     : {resultat['total_noeuds']}")
        print(f"Total arêtes     : {resultat['total_aretes']}")
        print(f"{'='*50}")