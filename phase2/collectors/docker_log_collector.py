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
                 raw_line: str) -> dict:
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
        "fields":         { ... champs extraits selon event_type ... }
    }
    """
    event_type = _classify_log_line(raw_line)
    fields = {}

    if event_type == "LOG_HTTP":
        fields = _parse_http_fields(raw_line)
    elif event_type == "LOG_AUTH":
        fields = {"auth_failed": True, "raw_hint": raw_line[:120]}

    return {
        "schema_version": "1.0",
        "timestamp_utc":  datetime.now(timezone.utc).isoformat(),
        "source":         "docker_logs",
        "event_type":     event_type,
        "service":        service_name,
        "container":      container_name,
        "raw":            raw_line[:512],   # Tronqué à 512 chars pour Kafka
        "fields":         fields,
    }


def _extract_service_name(container_name: str) -> str:
    """
    Déduit le nom du service depuis le nom du conteneur Docker.

    Exemples :
      'sockshop_front-end_1'  →  'front-end'
      'microsecure-kafka'     →  'kafka'
      'orders_orders_1'       →  'orders'
    """
    # Format Docker Compose : <projet>_<service>_<instance>
    parts = container_name.strip("/").split("_")
    if len(parts) >= 2:
        return parts[-2] if parts[-1].isdigit() else parts[-1]
    return container_name.strip("/")


class DockerLogCollector:
    """
    Collecteur de logs Docker.

    Pour chaque conteneur actif, lance un thread dédié qui lit
    le flux de logs en continu et publie chaque événement sur Kafka.
    """

    def __init__(self, producer: KafkaProducer):
        self.producer   = producer
        self.topic      = KAFKA_TOPICS["logs"]
        self._running   = False
        self._threads:  list[threading.Thread] = []
        self._stats     = {"published": 0, "errors": 0, "containers": 0}

        try:
            self.docker_client = docker.from_env()
            logger.info("Docker Engine API connecté.")
        except Exception as exc:
            logger.error(f"Impossible de se connecter à Docker : {exc}")
            raise

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
        service_name   = _extract_service_name(container_name)

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

                    event = _build_event(container_name, service_name, raw_line)
                    self._publish(event)

                except Exception as exc:
                    logger.debug(f"Erreur parsing ligne {container_name}: {exc}")

        except Exception as exc:
            logger.warning(f"Flux logs interrompu ({container_name}): {exc}")

    def start(self) -> None:
        """Lance la collecte sur tous les conteneurs actifs."""
        self._running = True
        containers = self.docker_client.containers.list()
        self._stats["containers"] = len(containers)

        if not containers:
            logger.warning("Aucun conteneur actif. Démarrez Sock Shop d'abord.")
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
