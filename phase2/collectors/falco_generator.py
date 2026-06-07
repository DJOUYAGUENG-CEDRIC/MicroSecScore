"""
collectors/falco_generator.py
====================================
Générateur d'alertes Falco — Format JSON officiel simulé.

Justification académique :
Falco est un outil de détection d'anomalies basé sur eBPF qui intercepte
les appels système au niveau du kernel Linux. Sur WSL2 et Docker Desktop
(Windows), le module kernel eBPF ne peut pas être chargé car l'accès
aux fonctionnalités kernel nécessaires est restreint par l'hyperviseur
Hyper-V. Ce générateur produit des alertes conformes au format JSON
officiel de Falco (documenté dans falcosecurity.org/docs), permettant
de valider le pipeline de collecte et de traitement indépendamment de
la couche kernel.

Format de sortie : identique au format Falco 0.36+
Référence : https://falco.org/docs/alerts/formatting/

DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
"""

import json
import time
import random
import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from kafka import KafkaProducer
from kafka.errors import KafkaError

from config.phase2_settings import (
    KAFKA_TOPICS,
    FALCO_GENERATOR_INTERVAL_S,
    FALCO_SCAN_PROBABILITY,
    FALCO_BRUTE_PROBABILITY,
    FALCO_LATERAL_PROBABILITY,
)

logger = logging.getLogger("phase2.falco_generator")

# ─────────────────────────────────────────
# Topologie chargée dynamiquement depuis graph_G0.json (Phase 1)
# ─────────────────────────────────────────

def _charger_topologie_depuis_g0() -> tuple:
    """
    Lit graph_G0.json et extrait :
      - all_services    : liste de tous les services (hors Outside)
      - exposed         : services avec ports publics (cibles de scan)
      - authorized      : dict {service: [services_autorisés]} (arêtes DEPENDS_ON)

    Retourne des listes vides si le fichier est absent — le générateur
    se rabattra sur les services Docker actifs.
    """
    import json as _json
    import os as _os

    g0_path = _os.path.abspath(
        _os.path.join(_os.path.dirname(__file__), "..", "..", "data", "output", "graph_G0.json")
    )

    if not _os.path.isfile(g0_path):
        logger.warning("graph_G0.json absent — FalcoGenerator sans contexte G0")
        return [], [], {}

    try:
        with open(g0_path, encoding="utf-8") as f:
            data = _json.load(f)
    except Exception as exc:
        logger.error(f"Erreur lecture graph_G0.json : {exc}")
        return [], [], {}

    nodes = data.get("nodes", [])
    links = data.get("links", [])   # format NetworkX node-link

    all_services = [
        n["id"] for n in nodes
        if n.get("id") != "Outside" and n.get("type_noeud") == "service"
    ]

    exposed = [
        n["id"] for n in nodes
        if n.get("ports_exposes") and n.get("id") != "Outside"
    ]
    # Si aucun port exposé trouvé, prendre les 2 premiers services
    if not exposed and all_services:
        exposed = all_services[:2]

    authorized: dict = {}
    for link in links:
        src = link.get("source", "")
        tgt = link.get("target", "")
        if link.get("type_arete") == "DEPENDS_ON" and src != "Outside" and tgt != "Outside":
            authorized.setdefault(src, []).append(tgt)

    logger.info(
        f"Topologie G0 chargee : {len(all_services)} services, "
        f"{len(exposed)} exposes, {len(authorized)} relations autorisees"
    )
    return all_services, exposed, authorized


# Chargement au démarrage du module
_ALL_SERVICES, _EXPOSED_SERVICES, _AUTHORIZED_RELATIONS = _charger_topologie_depuis_g0()

# Fallback si G0 absent au moment de l'import
if not _ALL_SERVICES:
    _ALL_SERVICES   = ["service-a", "service-b", "service-c", "db"]
    _EXPOSED_SERVICES = ["service-a"]
    _AUTHORIZED_RELATIONS = {"service-a": ["service-b"], "service-b": ["db"]}

# IPs sources simulées (attaquant externe)
ATTACKER_IPS = [
    "198.51.100.42",   # TEST-NET-3 (RFC 5737) — IPs de documentation
    "203.0.113.17",
    "198.51.100.99",
    "203.0.113.5",
]


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _build_falco_scan_alert() -> dict:
    """
    Génère une alerte Falco de type scan de reconnaissance.

    Correspond à la règle CEP P1 (Phase 3) :
    MITRE ATT&CK T1046 — Network Service Discovery
    Un attaquant sonde les ports exposés pour identifier les services.
    """
    target_service = random.choice(_EXPOSED_SERVICES)
    attacker_ip    = random.choice(ATTACKER_IPS)
    nb_ports       = random.randint(51, 200)  # > seuil CEP de 50

    return {
        # ── Enveloppe Falco officielle ──────────────────────
        "output":    (
            f"Network scan detected from {attacker_ip} to {target_service}: "
            f"{nb_ports} ports probed in 2 seconds "
            f"(container={target_service}, image=weaveworksdemos)"
        ),
        "priority":  "Warning",
        "rule":      "Network Port Scan Detected",
        "time":      _now_utc_iso(),
        "source":    "syscall",

        # ── Champs enrichis MicroSecScore ───────────────────
        "output_fields": {
            "container.name":    target_service,
            "container.image":   f"weaveworksdemos/{target_service}:latest",
            "evt.type":          "connect",
            "fd.sport":          random.randint(1024, 65535),
            "fd.rip":            attacker_ip,
            "fd.rport":          random.choice([80, 443, 8080, 8443, 22, 3306]),
        },

        # ── Métadonnées MicroSecScore ────────────────────────
        "microsecure": {
            "alert_type":     "ALERT_SCAN",
            "mitre_technique": "T1046",
            "mitre_tactic":   "TA0007",     # Discovery
            "service_cible":  target_service,
            "ip_source":      attacker_ip,
            "nb_ports_sondes": nb_ports,
            "simulated":      True,
        },
    }


def _build_falco_brute_alert() -> dict:
    """
    Génère une alerte Falco de type force brute.

    Correspond à la règle CEP P2 (Phase 3) :
    MITRE ATT&CK T1110 — Brute Force
    Un attaquant tente de deviner les credentials d'un service exposé.
    """
    target_service = random.choice(_EXPOSED_SERVICES)
    attacker_ip    = random.choice(ATTACKER_IPS)
    nb_attempts    = random.randint(101, 500)   # > seuil CEP de 100
    usernames      = ["admin", "root", "user", "test", "guest", "service"]
    target_user    = random.choice(usernames)

    return {
        "output":   (
            f"Brute force attack detected on {target_service}: "
            f"{nb_attempts} failed login attempts for user '{target_user}' "
            f"from {attacker_ip} in 30s"
        ),
        "priority": "Critical",
        "rule":     "Brute Force Login Attempt",
        "time":     _now_utc_iso(),
        "source":   "syscall",

        "output_fields": {
            "container.name":  target_service,
            "evt.type":        "read",
            "user.name":       target_user,
            "fd.rip":          attacker_ip,
            "proc.name":       "nginx" if target_service == "front-end" else "node",
        },

        "microsecure": {
            "alert_type":      "ALERT_BRUTE",
            "mitre_technique": "T1110",
            "mitre_tactic":    "TA0006",      # Credential Access
            "service_cible":   target_service,
            "ip_source":       attacker_ip,
            "user_cible":      target_user,
            "nb_tentatives":   nb_attempts,
            "simulated":       True,
        },
    }


def _build_falco_lateral_alert() -> dict:
    """
    Génère une alerte Falco de type mouvement latéral.

    Correspond à la règle CEP P3 (Phase 3) :
    MITRE ATT&CK T1550 — Application Access Token
    Un service compromis contacte un autre service NON AUTORISÉ dans G0.

    La paire (source, cible) est garantie NON PRÉSENTE dans G0
    pour déclencher l'alerte de mouvement latéral en Phase 3.
    """
    # Choisir une paire non autorisée dans G0
    internal = [s for s in _ALL_SERVICES if s not in _EXPOSED_SERVICES]
    if not internal:
        internal = _ALL_SERVICES

    all_pairs_non_autorises = []
    for src in internal:
        autorises = _AUTHORIZED_RELATIONS.get(src, [])
        non_autorises = [s for s in internal if s != src and s not in autorises]
        for dst in non_autorises:
            all_pairs_non_autorises.append((src, dst))

    src_service, dst_service = random.choice(all_pairs_non_autorises)

    return {
        "output":   (
            f"Unexpected network connection: {src_service} → {dst_service} "
            f"(not in authorized topology G0). "
            f"Possible lateral movement after compromise."
        ),
        "priority": "Critical",
        "rule":     "Unexpected Outbound Connection from Container",
        "time":     _now_utc_iso(),
        "source":   "syscall",

        "output_fields": {
            "container.name":  src_service,
            "fd.rip":          dst_service,   # IP interne résolue = nom service
            "fd.rport":        random.choice([3306, 5432, 27017, 6379, 8080]),
            "evt.type":        "connect",
            "proc.name":       "python" if "db" not in src_service else "mongod",
        },

        "microsecure": {
            "alert_type":      "ALERT_LATERAL",
            "mitre_technique": "T1550",
            "mitre_tactic":    "TA0008",      # Lateral Movement
            "service_source":  src_service,
            "service_cible":   dst_service,
            "autorise_g0":     False,          # Clé utilisée par la Phase 3
            "simulated":       True,
        },
    }


def _build_falco_escape_alert() -> dict:
    """
    Génère une alerte Falco de type évasion de conteneur.

    Correspond à la règle CEP P5 (Phase 3) :
    MITRE ATT&CK T1611 — Escape to Host
    Un processus dans un conteneur tente d'accéder au namespace hôte.
    """
    target_service = random.choice(_ALL_SERVICES)

    escape_scenarios = [
        ("terminal shell in container", "Terminal Shell in Container"),
        ("execve", "Execve Syscall Detected in Container"),
        ("docker.sock", "Docker Socket Accessed from Container"),
        ("mount namespace", "Container Namespace Escape Attempt"),
        ("privileged", "Launch Privileged Container"),
        ("nsenter", "Nsenter Detected in Container"),
    ]
    keyword, rule_name = random.choice(escape_scenarios)

    return {
        "output":   (
            f"Container escape attempt detected in {target_service}: "
            f"{keyword} used — possible host namespace access "
            f"(container={target_service}, image=weaveworksdemos)"
        ),
        "priority": "Critical",
        "rule":     rule_name,
        "time":     _now_utc_iso(),
        "source":   "syscall",

        "output_fields": {
            "container.name":  target_service,
            "container.image": f"weaveworksdemos/{target_service}:latest",
            "evt.type":        "execve",
            "proc.name":       "sh",
            "proc.cmdline":    f"nsenter --target 1 --mount --uts --ipc --net --pid",
        },

        "microsecure": {
            "alert_type":      "ALERT_ESCAPE",
            "mitre_technique": "T1611",
            "mitre_tactic":    "TA0004",    # Privilege Escalation
            "service_cible":   target_service,
            "keyword":         keyword,
            "simulated":       True,
        },
    }


def _wrap_for_kafka(falco_alert: dict) -> dict:
    """
    Enveloppe l'alerte Falco dans le schéma unifié Phase 2
    pour homogénéité avec les autres sources (logs, métriques).
    """
    microsecure = falco_alert.get("microsecure", {})
    return {
        "schema_version": "1.0",
        "timestamp_utc":  falco_alert.get("time", _now_utc_iso()),
        "source":         "falco_generator",
        "event_type":     microsecure.get("alert_type", "ALERT_UNKNOWN"),
        "service":        microsecure.get("service_cible")
                          or microsecure.get("service_source", "unknown"),
        "severity":       falco_alert.get("priority", "Warning").upper(),
        "fields":         falco_alert,   # Alerte Falco complète dans 'fields'
    }


class FalcoGenerator:
    """
    Générateur d'alertes Falco réalistes.

    Injecte périodiquement des alertes de sécurité simulées sur le topic
    Kafka 'alertes-securite'. Les alertes sont conformes au format JSON
    officiel de Falco 0.36+ pour garantir la compatibilité avec la Phase 3.
    """

    def __init__(self, producer: KafkaProducer):
        self.producer  = producer
        self.topic     = KAFKA_TOPICS["alerts"]
        self._running  = False
        self._thread: Optional[threading.Thread] = None
        self._stats    = {
            "scan_alerts":    0,
            "brute_alerts":   0,
            "lateral_alerts": 0,
            "escape_alerts":  0,
            "total_published": 0,
            "errors": 0,
        }

    def _publish(self, event: dict) -> None:
        try:
            payload = json.dumps(event, ensure_ascii=False).encode("utf-8")
            self.producer.send(self.topic, value=payload)
            self._stats["total_published"] += 1
        except KafkaError as exc:
            logger.warning(f"Erreur publication Kafka : {exc}")
            self._stats["errors"] += 1

    def inject_single_attack_scenario(self, scenario: str = "full") -> None:
        """
        Injecte manuellement un scénario d'attaque complet.
        Utilisé pour les tests de la Phase 3.

        scenario = 'scan'    : un scan de reconnaissance
        scenario = 'brute'   : une attaque force brute
        scenario = 'lateral' : un mouvement latéral
        scenario = 'full'    : les trois en séquence (APT complet)
        """
        logger.info(f"Injection manuelle scénario : {scenario}")

        if scenario in ("scan", "full"):
            alert = _build_falco_scan_alert()
            self._publish(_wrap_for_kafka(alert))
            self._stats["scan_alerts"] += 1
            logger.info(f"  → SCAN injecté : {alert['microsecure']['service_cible']}")

        if scenario in ("brute", "full"):
            alert = _build_falco_brute_alert()
            self._publish(_wrap_for_kafka(alert))
            self._stats["brute_alerts"] += 1
            logger.info(f"  → BRUTE injecté : {alert['microsecure']['service_cible']}")

        if scenario in ("lateral", "full"):
            alert = _build_falco_lateral_alert()
            self._publish(_wrap_for_kafka(alert))
            self._stats["lateral_alerts"] += 1
            logger.info(
                f"  → LATERAL injecté : "
                f"{alert['microsecure']['service_source']} → "
                f"{alert['microsecure']['service_cible']}"
            )

        if scenario in ("escape", "full"):
            alert = _build_falco_escape_alert()
            self._publish(_wrap_for_kafka(alert))
            self._stats["escape_alerts"] += 1
            logger.info(
                f"  → ESCAPE injecté : {alert['microsecure']['service_cible']} "
                f"({alert['microsecure']['keyword']})"
            )

        if scenario in ("escape", "full"):
            alert = _build_falco_escape_alert()
            self._publish(_wrap_for_kafka(alert))
            self._stats["escape_alerts"] += 1
            logger.info(f"  → ESCAPE injecté : {alert['microsecure']['service_cible']}")

    def _run_loop(self) -> None:
        """
        Boucle principale : injecte des alertes selon les probabilités
        définies dans phase2_settings.py.
        """
        logger.info(
            f"Générateur Falco démarré "
            f"(intervalle={FALCO_GENERATOR_INTERVAL_S}s, "
            f"P_scan={FALCO_SCAN_PROBABILITY}, "
            f"P_brute={FALCO_BRUTE_PROBABILITY}, "
            f"P_lateral={FALCO_LATERAL_PROBABILITY})"
        )

        while self._running:
            r = random.random()

            if r < FALCO_LATERAL_PROBABILITY:
                # Priorité aux mouvements latéraux (plus critiques)
                alert = _build_falco_lateral_alert()
                self._publish(_wrap_for_kafka(alert))
                self._stats["lateral_alerts"] += 1

            elif r < FALCO_LATERAL_PROBABILITY + FALCO_BRUTE_PROBABILITY:
                alert = _build_falco_brute_alert()
                self._publish(_wrap_for_kafka(alert))
                self._stats["brute_alerts"] += 1

            elif r < (FALCO_LATERAL_PROBABILITY
                      + FALCO_BRUTE_PROBABILITY
                      + FALCO_SCAN_PROBABILITY):
                alert = _build_falco_scan_alert()
                self._publish(_wrap_for_kafka(alert))
                self._stats["scan_alerts"] += 1

            elif r < (FALCO_LATERAL_PROBABILITY
                      + FALCO_BRUTE_PROBABILITY
                      + FALCO_SCAN_PROBABILITY
                      + 0.02):   # 2 % de probabilité d'évasion (très rare)
                alert = _build_falco_escape_alert()
                self._publish(_wrap_for_kafka(alert))
                self._stats["escape_alerts"] += 1

            time.sleep(FALCO_GENERATOR_INTERVAL_S)

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="falco-generator"
        )
        self._thread.start()
        logger.info("FalcoGenerator démarré.")

    def stop(self) -> None:
        self._running = False
        logger.info(f"FalcoGenerator arrêté. Stats : {self._stats}")

    def get_stats(self) -> dict:
        return dict(self._stats)
