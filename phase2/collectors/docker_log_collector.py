"""
collectors/docker_log_collector.py
====================================
Collecteur de logs applicatifs via Docker Engine API.

Principe : Pour chaque conteneur en cours d'exécution, on s'abonne
au flux stdout/stderr via le SDK Python de Docker. Chaque ligne de log
est parsée, enrichie d'un timestamp UTC unifié, et publiée sur le topic
Kafka 'logs-applicatifs'.

Référence technique :
- Docker SDK for Python : https://docker-py.readthedocs.io
- Format d'événement normalisé : voir normalizer/event_normalizer.py

DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
"""

import re
import json
import time
import random
import threading
import logging
from datetime import datetime, timezone
from typing import Optional

import docker
from kafka import KafkaProducer
from kafka.errors import KafkaError

from config.phase2_settings import (
    KAFKA_TOPICS,
    KAFKA_BOOTSTRAP_SERVERS,
    DOCKER_LOG_TAIL,
    DOCKER_LOG_INTERVAL_S,
)

logger = logging.getLogger("phase2.docker_collector")


# ─────────────────────────────────────────
# Patterns de parsing des logs HTTP
# ─────────────────────────────────────────
# ─────────────────────────────────────────
# Templates de logs simulés (réalistes)
# ─────────────────────────────────────────
SIM_HTTP_LOGS = [
    ("GET",    "/health",              200),
    ("GET",    "/catalogue",           200),
    ("GET",    "/catalogue/size",      200),
    ("GET",    "/catalogue/tags",      200),
    ("POST",   "/orders",              201),
    ("GET",    "/orders",              200),
    ("GET",    "/cart",                200),
    ("POST",   "/cart",                201),
    ("DELETE", "/cart",                204),
    ("GET",    "/users",               200),
    ("POST",   "/login",               200),
    ("POST",   "/login",               401),
    ("GET",    "/payment",             200),
    ("POST",   "/payment",             500),
    ("GET",    "/",                    200),
    ("GET",    "/metrics",             200),
    ("GET",    "/api/v1/products",     200),
    ("POST",   "/api/v1/orders",       201),
    ("GET",    "/api/v1/users/me",     401),
]

SIM_ERRORS = [
    "ERROR: Connection refused to database port 27017 after 3 retries",
    "WARN: Response time 2847ms exceeds threshold of 2000ms",
    "ERROR: Failed to connect to rabbitmq:5672",
    "Exception in thread main: NullPointerException at OrderService.java:142",
    "CRITICAL: Disk usage at 91%, write operations may be impacted",
    "ERROR: Circuit breaker OPEN for downstream service",
]

SIM_AUTH_FAILS = [
    'POST /login HTTP/1.1 401 Unauthorized - invalid credentials for user "admin"',
    "Authentication failed: JWT token expired or invalid",
    "403 Forbidden: insufficient permissions for /admin endpoint",
    "POST /register HTTP/1.1 401 - password validation failed",
    "Authorization header missing for protected resource",
]

PATTERN_HTTP = re.compile(
    r'(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+'
    r'(?P<path>/\S*)\s+HTTP/\d\.\d.*?(?P<status_code>\d{3})'
)
PATTERN_AUTH_FAIL = re.compile(
    r'(?i)(unauthorized|authentication.?failed|invalid.?token|'
    r'wrong.?password|login.?failed|auth.?error|403|401)'
)
PATTERN_ERROR = re.compile(
    r'(?i)(exception|error|critical|fatal|traceback|panic|'
    r'connection.?refused|timeout)'
)


def _classify_log_line(line: str) -> str:
    """
    Détermine le type d'événement d'une ligne de log.

    Règles de classification (par ordre de priorité) :
    1. LOG_AUTH  : contient un motif d'échec d'authentification
    2. LOG_HTTP  : contient une méthode HTTP + code de statut
    3. LOG_ERROR : contient un motif d'erreur
    4. LOG_INFO  : tout le reste (log standard non critique)
    """
    if PATTERN_AUTH_FAIL.search(line):
        return "LOG_AUTH"
    if PATTERN_HTTP.search(line):
        return "LOG_HTTP"
    if PATTERN_ERROR.search(line):
        return "LOG_ERROR"
    return "LOG_INFO"


def _parse_http_fields(line: str) -> dict:
    """Extrait la méthode, le chemin et le code HTTP d'une ligne de log."""
    m = PATTERN_HTTP.search(line)
    if m:
        return {
            "http_method":      m.group("method"),
            "http_path":        m.group("path"),
            "http_status_code": int(m.group("status_code")),
        }
    return {}


def _build_event(container_name: str, service_name: str,
                 raw_line: str, topologie: dict = None) -> dict:
    """
    Construit un événement normalisé depuis une ligne de log brute.

    Format de sortie (schéma unifié Phase 2) :
    {
        "schema_version": "1.0",
        "timestamp_utc":  "2025-01-15T10:23:45.123456Z",
        "source":         "docker_logs",
        "event_type":     "LOG_HTTP" | "LOG_AUTH" | "LOG_ERROR" | "LOG_INFO",
        "service":        "front-end",
        "container":      "frontend_container_1",
        "raw":            "<ligne originale>",
        "fields":         { ... champs extraits selon event_type ... },
        "phase1":         { "score_cve": float, "criticite": int, "image": str }  # si dispo
    }
    """
    event_type = _classify_log_line(raw_line)
    fields = {}

    if event_type == "LOG_HTTP":
        fields = _parse_http_fields(raw_line)
    elif event_type == "LOG_AUTH":
        fields = {"auth_failed": True, "raw_hint": raw_line[:120]}

    event = {
        "schema_version": "1.0",
        "timestamp_utc":  datetime.now(timezone.utc).isoformat(),
        "source":         "docker_logs",
        "event_type":     event_type,
        "service":        service_name,
        "container":      container_name,
        "raw":            raw_line[:512],   # Tronqué à 512 chars pour Kafka
        "fields":         fields,
    }

    if topologie and service_name in topologie:
        ctx = topologie[service_name]
        event["phase1"] = {
            "score_cve": ctx["score_cve"],
            "criticite": ctx["criticite"],
            "image":     ctx["image"],
        }

    return event


def _extract_service_name(container) -> str:
    """
    Extrait le nom du service depuis les labels Docker Compose (méthode fiable),
    avec fallback sur le parsing du nom de conteneur.

    Docker Compose v1/v2 injecte automatiquement le label :
      com.docker.compose.service = "front-end"

    Exemples de noms de conteneurs supportés en fallback :
      'sockshop_front-end_1'          → 'front-end'   (Compose v1, underscore)
      'mes-tests-front-end-1'         → 'front-end'   (Compose v2, tiret)
      'microsecscor-front-end-1'      → 'front-end'
    """
    # Méthode 1 — label Docker Compose (toujours prioritaire)
    if hasattr(container, "labels"):
        label = (container.labels or {}).get("com.docker.compose.service", "")
        if label:
            return label

    # Méthode 2 — parsing du nom de conteneur
    name = (container.name if hasattr(container, "name") else str(container)).strip("/")

    # Format Compose v1 : <projet>_<service>_<N>
    parts_us = name.split("_")
    if len(parts_us) >= 3 and parts_us[-1].isdigit():
        return "_".join(parts_us[1:-1])
    if len(parts_us) >= 2:
        return "_".join(parts_us[1:]) if not parts_us[-1].isdigit() else parts_us[-2]

    # Format Compose v2 : <projet>-<service>-<N>
    # Les noms de services Sock Shop contiennent eux-mêmes des tirets (front-end, cart-db…)
    # On retire le dernier segment numérique et le préfixe projet
    parts_dash = name.rsplit("-", 1)
    if len(parts_dash) == 2 and parts_dash[1].isdigit():
        # Retirer aussi le préfixe projet (premier segment)
        inner = parts_dash[0]
        idx = inner.find("-")
        if idx != -1:
            return inner[idx + 1:]
        return inner

    return name


class DockerLogCollector:
    """
    Collecteur de logs Docker.

    Pour chaque conteneur actif, lance un thread dédié qui lit
    le flux de logs en continu et publie chaque événement sur Kafka.
    """

    def __init__(self, producer: KafkaProducer, topologie_phase1: dict = None):
        self.producer            = producer
        self.topic               = KAFKA_TOPICS["logs"]
        self._running            = False
        self._threads:           list[threading.Thread] = []
        self._stats              = {"published": 0, "errors": 0, "containers": 0}
        self.topologie           = topologie_phase1 or {}
        self.services_surveilles = set(self.topologie.keys())

        self.simulation_mode = False
        try:
            self.docker_client = docker.from_env()
            logger.info("Docker Engine API connecté.")
        except Exception as exc:
            logger.warning(f"Docker indisponible — mode simulation activé : {exc}")
            self.docker_client = None
            self.simulation_mode = True

    def _publish(self, event: dict) -> None:
        """Sérialise et publie un événement sur le topic Kafka."""
        try:
            payload = json.dumps(event, ensure_ascii=False).encode("utf-8")
            self.producer.send(self.topic, value=payload)
            self._stats["published"] += 1
        except KafkaError as exc:
            logger.warning(f"Erreur publication Kafka : {exc}")
            self._stats["errors"] += 1

    def _stream_container_logs(self, container) -> None:
        """
        Thread dédié à un conteneur.
        Lit les logs en streaming et publie chaque ligne.
        """
        container_name = container.name
        service_name   = _extract_service_name(container)

        logger.info(f"Démarrage collecte logs : {container_name} → service={service_name}")

        try:
            # generator=True : flux continu (ne retourne pas tout d'un coup)
            # tail=DOCKER_LOG_TAIL : lit les N dernières lignes d'abord
            log_stream = container.logs(
                stream=True,
                follow=True,
                tail=DOCKER_LOG_TAIL,
                timestamps=False,
            )

            for raw_bytes in log_stream:
                if not self._running:
                    break

                try:
                    raw_line = raw_bytes.decode("utf-8", errors="replace").strip()
                    if not raw_line:
                        continue

                    # Filtrer les logs des conteneurs Kafka/Zookeeper eux-mêmes
                    if any(kw in container_name.lower()
                           for kw in ["kafka", "zookeeper", "kafka-ui"]):
                        continue

                    event = _build_event(container_name, service_name, raw_line, self.topologie)
                    self._publish(event)

                except Exception as exc:
                    logger.debug(f"Erreur parsing ligne {container_name}: {exc}")

        except Exception as exc:
            logger.warning(f"Flux logs interrompu ({container_name}): {exc}")

    def _build_simulated_event(self, service: str) -> dict:
        """Génère un événement de log simulé réaliste pour un service."""
        r = random.random()

        if r < 0.06:
            raw_line  = random.choice(SIM_AUTH_FAILS)
            etype     = "LOG_AUTH"
            fields    = {"auth_failed": True, "raw_hint": raw_line[:120]}
            severity  = "WARNING"
        elif r < 0.11:
            raw_line  = random.choice(SIM_ERRORS)
            etype     = "LOG_ERROR"
            fields    = {}
            severity  = "WARNING"
        else:
            method, path, code = random.choice(SIM_HTTP_LOGS)
            raw_line  = f'{method} {path} HTTP/1.1 {code}'
            etype     = "LOG_HTTP"
            fields    = {"http_method": method, "http_path": path, "http_status_code": code}
            severity  = "INFO" if code < 400 else "WARNING"

        event = {
            "schema_version": "1.0",
            "timestamp_utc":  datetime.now(timezone.utc).isoformat(),
            "source":         "docker_logs",
            "event_type":     etype,
            "service":        service,
            "container":      f"{service}_sim_1",
            "severity":       severity,
            "raw":            raw_line,
            "fields":         fields,
            "simulated":      True,
        }

        if service in self.topologie:
            ctx = self.topologie[service]
            event["phase1"] = {
                "score_cve": ctx["score_cve"],
                "criticite": ctx["criticite"],
                "image":     ctx["image"],
            }
        return event

    def _run_simulation_loop(self) -> None:
        """Boucle de génération de logs simulés quand Docker est indisponible."""
        services = list(self.topologie.keys()) if self.topologie else [
            "front-end", "orders", "catalogue", "user", "payment", "cart"
        ]
        logger.info(f"DockerLogCollector simulation démarrée — {len(services)} services")
        self._stats["containers"] = len(services)

        while self._running:
            service = random.choice(services)
            event   = self._build_simulated_event(service)
            self._publish(event)
            time.sleep(random.uniform(0.8, 2.5))

    def start(self) -> None:
        """Lance la collecte sur les conteneurs actifs (filtrés si topologie Phase 1 chargée)."""
        self._running = True

        # ── Mode simulation (Docker absent) ───────────────────────
        if self.simulation_mode:
            t = threading.Thread(
                target=self._run_simulation_loop, daemon=True, name="logs-sim"
            )
            t.start()
            self._threads.append(t)
            return

        # ── Mode réel ─────────────────────────────────────────────
        containers = self.docker_client.containers.list()

        if self.services_surveilles:
            containers = [
                c for c in containers
                if _extract_service_name(c) in self.services_surveilles
            ]
            logger.info(
                f"Filtrage Phase 1 actif : {len(containers)} conteneur(s) surveillé(s)"
            )
        else:
            logger.info("Aucune topologie Phase 1 — collecte sur tous les conteneurs.")

        self._stats["containers"] = len(containers)

        if not containers:
            logger.warning("Aucun conteneur actif — bascule en mode simulation.")
            t = threading.Thread(
                target=self._run_simulation_loop, daemon=True, name="logs-sim"
            )
            t.start()
            self._threads.append(t)
            return

        logger.info(f"Collecte logs démarrée sur {len(containers)} conteneurs.")

        for container in containers:
            t = threading.Thread(
                target=self._stream_container_logs,
                args=(container,),
                daemon=True,
                name=f"logs-{container.name[:20]}"
            )
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        """Arrête proprement tous les threads de collecte."""
        self._running = False
        logger.info(f"Collecte logs arrêtée. Stats : {self._stats}")

    def get_stats(self) -> dict:
        return dict(self._stats)
