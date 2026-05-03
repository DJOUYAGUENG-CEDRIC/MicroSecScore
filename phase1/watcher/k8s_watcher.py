# =============================================================================
# MicroSecScore — Phase 1 : Topologie & Graphe G0
# Fichier : watcher/k8s_watcher.py
# Rôle    : Surveille les événements Kubernetes en temps réel
#           et met à jour G0 dynamiquement à chaque changement
# Auteur  : DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
# =============================================================================

import threading
import time
import json
import os
from datetime import datetime

import networkx as nx
from networkx.readwrite import json_graph
from kubernetes import client, config as k8s_config, watch

from config.settings import (
    K8S_NAMESPACE,
    K8S_WATCH_TIMEOUT,
    GRAPH_OUTPUT_PATH,
    OUTSIDE_NODE
)
from utils.logger import get_logger, log_separateur, log_resultat

logger = get_logger(__name__)

# =============================================================================
# ÉTAT GLOBAL DU WATCHER
# =============================================================================

# Instance unique du graphe G0 dynamique (partagée entre threads)
_G0_dynamique   = None

# Verrou pour accès concurrent au graphe (thread-safety)
_verrou_G0      = threading.Lock()

# Signal d'arrêt du watcher
_watcher_actif  = False

# Thread du watcher
_thread_watcher = None


# =============================================================================
# FONCTION PRINCIPALE — DÉMARRER LE WATCHER
# =============================================================================

def demarrer_watcher(G0_initial: nx.DiGraph) -> None:
    """
    Démarre la surveillance temps réel de Kubernetes dans un thread séparé.

    Le watcher s'exécute en arrière-plan sans bloquer le programme principal.
    Il reçoit un G0 initial (construit par la Phase 1) et le maintient
    à jour en permanence en écoutant les événements Kubernetes.

    Algorithme — pattern Observer sur flux d'événements :
        1. Initialiser G0 dynamique avec le graphe statique initial
        2. Lancer un thread de surveillance en arrière-plan
        3. Le thread écoute le Watch API Kubernetes (flux continu)
        4. À chaque événement Pod/Service → mettre à jour G0
        5. Sauvegarder graph_G0.json horodaté après chaque modification

    Paramètre :
        G0_initial (nx.DiGraph) : graphe G0 construit par builder.py
    """

    global _G0_dynamique, _watcher_actif, _thread_watcher

    log_separateur(logger, "Démarrage du Watcher Kubernetes")

    # Initialiser G0 dynamique avec une copie du graphe statique
    with _verrou_G0:
        _G0_dynamique = G0_initial.copy()

    _watcher_actif = True

    # Lancer le thread de surveillance en arrière-plan
    # daemon=True : le thread s'arrête automatiquement si le programme principal s'arrête
    _thread_watcher = threading.Thread(
        target  = _boucle_surveillance,
        name    = "KubernetesWatcher",
        daemon  = True
    )
    _thread_watcher.start()

    log_resultat(logger, "Watcher Kubernetes",  "ACTIF")
    log_resultat(logger, "Thread",              _thread_watcher.name)
    log_resultat(logger, "Namespace surveillé", K8S_NAMESPACE)
    logger.info("G0 sera mis à jour automatiquement à chaque changement Kubernetes")


# =============================================================================
# BOUCLE DE SURVEILLANCE — TOURNE EN ARRIÈRE-PLAN
# =============================================================================

def _boucle_surveillance() -> None:
    """
    Boucle principale du thread de surveillance.

    Écoute le Watch API Kubernetes et traite chaque événement.
    En cas de déconnexion, se reconnecte automatiquement après
    K8S_WATCH_TIMEOUT secondes.

    Les types d'événements traités :
        ADDED    → nouveau pod déployé   → ajouter le noeud dans G0
        DELETED  → pod supprimé         → retirer le noeud de G0
        MODIFIED → pod modifié (image)  → mettre à jour les attributs
    """

    logger.debug("Boucle de surveillance Kubernetes démarrée")

    while _watcher_actif:
        try:
            # Charger la configuration Kubernetes
            k8s_config.load_kube_config()
            v1 = client.CoreV1Api()
            w  = watch.Watch()

            logger.debug(
                f"Connexion au Watch API Kubernetes — "
                f"namespace : {K8S_NAMESPACE}"
            )

            # -------------------------------------------------------------------
            # ÉCOUTE DU FLUX D'ÉVÉNEMENTS
            # w.stream() est un générateur qui produit un événement
            # à chaque changement dans le cluster Kubernetes
            # timeout_seconds : reconnexion automatique après ce délai
            # -------------------------------------------------------------------
            for evenement in w.stream(
                v1.list_namespaced_pod,
                namespace       = K8S_NAMESPACE,
                timeout_seconds = K8S_WATCH_TIMEOUT
            ):
                if not _watcher_actif:
                    w.stop()
                    break

                _traiter_evenement_pod(evenement)

        except k8s_config.ConfigException:
            logger.error(
                "Configuration Kubernetes introuvable — "
                "watcher désactivé"
            )
            break

        except Exception as e:
            if _watcher_actif:
                logger.warning(
                    f"Déconnexion du Watch API : {e} — "
                    f"reconnexion dans {K8S_WATCH_TIMEOUT}s"
                )
                time.sleep(K8S_WATCH_TIMEOUT)

    logger.debug("Boucle de surveillance Kubernetes arrêtée")


# =============================================================================
# TRAITEMENT D'UN ÉVÉNEMENT POD
# =============================================================================

def _traiter_evenement_pod(evenement: dict) -> None:
    """
    Traite un événement Kubernetes et met à jour G0 en conséquence.

    Les trois types d'événements possibles :
        ADDED    → un nouveau pod a démarré
        DELETED  → un pod a été supprimé
        MODIFIED → un pod existant a été modifié

    Paramètre :
        evenement (dict) : événement Kubernetes brut du Watch API
                          Contient 'type' et 'object' (le pod)
    """

    type_evenement = evenement.get("type", "")
    pod            = evenement.get("object")

    if pod is None:
        return

    nom_pod   = pod.metadata.name
    namespace = pod.metadata.namespace

    # On ignore les namespaces autres que notre cible
    if namespace != K8S_NAMESPACE:
        return

    # Extrait le nom du service depuis le label 'app'
    labels      = pod.metadata.labels or {}
    nom_service = labels.get("app", nom_pod)

    logger.info(
        f"Événement Kubernetes : [{type_evenement}] "
        f"pod={nom_pod} service={nom_service}"
    )

    # -------------------------------------------------------------------------
    # ADDED — Nouveau pod démarré → ajouter le noeud dans G0
    # -------------------------------------------------------------------------
    if type_evenement == "ADDED":
        _ajouter_service(nom_service, pod)

    # -------------------------------------------------------------------------
    # DELETED — Pod supprimé → retirer le noeud de G0
    # -------------------------------------------------------------------------
    elif type_evenement == "DELETED":
        _retirer_service(nom_service)

    # -------------------------------------------------------------------------
    # MODIFIED — Pod modifié → mettre à jour les attributs du noeud
    # -------------------------------------------------------------------------
    elif type_evenement == "MODIFIED":
        _mettre_a_jour_service(nom_service, pod)


# =============================================================================
# OPÉRATIONS SUR G0
# =============================================================================

def _ajouter_service(nom_service: str, pod) -> None:
    """
    Ajoute un nouveau noeud dans G0 dynamique.

    Extrait les attributs du pod et crée le noeud avec
    les mêmes propriétés que lors de la construction initiale.
    """
    global _G0_dynamique

    with _verrou_G0:
        if _G0_dynamique is None:
            return

        if nom_service in _G0_dynamique.nodes:
            logger.debug(f"Service '{nom_service}' déjà dans G0 — ignoré")
            return

        # Extraire l'image depuis le premier conteneur du pod
        conteneurs = pod.spec.containers if pod.spec else []
        image      = conteneurs[0].image if conteneurs else "unknown"

        # Détection du mode privilégié
        privileged = False
        if conteneurs and conteneurs[0].security_context:
            privileged = conteneurs[0].security_context.privileged or False

        _G0_dynamique.add_node(
            nom_service,
            image        = image,
            ports_exposes= [],
            privileged   = privileged,
            docker_sock  = False,
            score_cve    = None,
            criticite    = None,
            niveau       = None,
            type_noeud   = "service",
            source       = "kubernetes_runtime"
        )

        logger.info(f"G0 mis à jour — noeud AJOUTÉ : {nom_service} ({image})")

    # Sauvegarder G0 après modification
    _sauvegarder_G0(evenement="ADDED", service=nom_service)


def _retirer_service(nom_service: str) -> None:
    """
    Retire un noeud de G0 dynamique quand un pod est supprimé.

    Retire également toutes les arêtes connectées à ce noeud
    (NetworkX le fait automatiquement avec remove_node).
    """
    global _G0_dynamique

    with _verrou_G0:
        if _G0_dynamique is None:
            return

        if nom_service not in _G0_dynamique.nodes:
            logger.debug(f"Service '{nom_service}' absent de G0 — ignoré")
            return

        # remove_node supprime le noeud ET toutes ses arêtes
        _G0_dynamique.remove_node(nom_service)
        logger.info(f"G0 mis à jour — noeud RETIRÉ : {nom_service}")

    # Sauvegarder G0 après modification
    _sauvegarder_G0(evenement="DELETED", service=nom_service)


def _mettre_a_jour_service(nom_service: str, pod) -> None:
    """
    Met à jour les attributs d'un noeud existant dans G0.

    Utilisé quand un pod est redémarré avec une nouvelle image
    (mise à jour de l'application).
    """
    global _G0_dynamique

    with _verrou_G0:
        if _G0_dynamique is None:
            return

        if nom_service not in _G0_dynamique.nodes:
            # Si le noeud n'existe pas, on l'ajoute
            _ajouter_service(nom_service, pod)
            return

        # Mettre à jour l'image si elle a changé
        conteneurs = pod.spec.containers if pod.spec else []
        if conteneurs:
            nouvelle_image = conteneurs[0].image
            ancienne_image = _G0_dynamique.nodes[nom_service].get("image")

            if nouvelle_image != ancienne_image:
                _G0_dynamique.nodes[nom_service]["image"]     = nouvelle_image
                # Réinitialiser le score CVE — il faudra le recalculer
                _G0_dynamique.nodes[nom_service]["score_cve"] = None
                _G0_dynamique.nodes[nom_service]["niveau"]    = None

                logger.info(
                    f"G0 mis à jour — noeud MODIFIÉ : {nom_service} "
                    f"({ancienne_image} → {nouvelle_image})"
                )
                logger.warning(
                    f"Score CVE de '{nom_service}' réinitialisé — "
                    f"image modifiée, nouveau scan CVE requis"
                )

    # Sauvegarder G0 après modification
    _sauvegarder_G0(evenement="MODIFIED", service=nom_service)


# =============================================================================
# SAUVEGARDE HORODATÉE DE G0
# =============================================================================

def _sauvegarder_G0(evenement: str = "", service: str = "") -> None:
    """
    Sauvegarde graph_G0.json avec horodatage après chaque modification.

    Le fichier est écrit de façon atomique : on écrit dans un fichier
    temporaire puis on le renomme, évitant ainsi une corruption du fichier
    si le programme s'arrête pendant l'écriture.

    L'horodatage permet de tracer l'historique des modifications de G0
    — utile pour l'analyse forensique post-incident.
    """
    global _G0_dynamique

    with _verrou_G0:
        if _G0_dynamique is None:
            return

        try:
            # Enrichir les métadonnées avant la sauvegarde
            _G0_dynamique.graph["derniere_maj"]    = datetime.now().isoformat()
            _G0_dynamique.graph["evenement"]       = evenement
            _G0_dynamique.graph["service_modifie"] = service
            _G0_dynamique.graph["nb_noeuds"]       = _G0_dynamique.number_of_nodes()
            _G0_dynamique.graph["nb_aretes"]       = _G0_dynamique.number_of_edges()

            donnees_json = json_graph.node_link_data(_G0_dynamique)

            # Écriture atomique : fichier temporaire → renommage
            chemin_tmp = GRAPH_OUTPUT_PATH + ".tmp"

            with open(chemin_tmp, "w", encoding="utf-8") as f:
                json.dump(donnees_json, f, indent=2, ensure_ascii=False)

            os.replace(chemin_tmp, GRAPH_OUTPUT_PATH)

            logger.debug(
                f"G0 sauvegardé après événement [{evenement}] "
                f"sur {service} — "
                f"{_G0_dynamique.number_of_nodes()} noeuds, "
                f"{_G0_dynamique.number_of_edges()} arêtes"
            )

        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde de G0 : {e}")


# =============================================================================
# FONCTIONS PUBLIQUES — ACCÈS ET CONTRÔLE
# =============================================================================

def get_G0_dynamique() -> nx.DiGraph:
    """
    Retourne une copie thread-safe du G0 dynamique courant.

    Utilisé par les phases 3 et 4 pour obtenir l'état
    le plus récent du graphe sans risque de corruption.

    Retourne :
        nx.DiGraph : copie du graphe G0 à l'instant t
    """
    with _verrou_G0:
        if _G0_dynamique is None:
            return None
        return _G0_dynamique.copy()


def arreter_watcher() -> None:
    """
    Arrête proprement le thread de surveillance Kubernetes.

    Doit être appelé en fin d'exécution de phase1_topology.py.
    """
    global _watcher_actif

    _watcher_actif = False

    if _thread_watcher and _thread_watcher.is_alive():
        _thread_watcher.join(timeout=5)
        logger.info("Watcher Kubernetes arrêté proprement")


# =============================================================================
# TEST RAPIDE — Exécution directe du fichier
# python watcher/k8s_watcher.py
# (nécessite un cluster Kubernetes accessible)
# =============================================================================

if __name__ == "__main__":
    import sys
    sys.path.insert(0, "..")

    G0_test = nx.DiGraph()
    G0_test.add_node("front-end",
                     image="weaveworksdemos/front-end:0.3.12",
                     score_cve=48.0, criticite=4,
                     niveau="DEGRADE", ports_exposes=[80],
                     privileged=False, docker_sock=False,
                     type_noeud="service")
    G0_test.add_node(OUTSIDE_NODE,
                     type_noeud="attaquant_externe",
                     score_cve=None, criticite=0, niveau="EXTERNE")
    G0_test.add_edge(OUTSIDE_NODE, "front-end", type_arete="PEUT_ATTAQUER")

    print("Démarrage du watcher Kubernetes...")
    print("Appuyez sur Ctrl+C pour arrêter\n")

    demarrer_watcher(G0_test)

    try:
        while True:
            g = get_G0_dynamique()
            if g:
                print(
                    f"\r[{datetime.now().strftime('%H:%M:%S')}] "
                    f"G0 : {g.number_of_nodes()} noeuds, "
                    f"{g.number_of_edges()} arêtes",
                    end=""
                )
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n\nArrêt du watcher...")
        arreter_watcher()
        print("Watcher arrêté.")