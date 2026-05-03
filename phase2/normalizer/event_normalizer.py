"""
normalizer/event_normalizer.py
====================================
Normaliseur d'événements — Schéma unifié Phase 2.

Rôle : Consomme les événements bruts des 3 topics Kafka
(logs, métriques, alertes), valide leur schéma, et les réécrit
dans un format normalisé unique. Ce format est celui que
la Phase 3 (moteur CEP) consommera.

Schéma normalisé final :
{
    "schema_version":  "1.0",
    "event_id":        "<uuid>",          # Identifiant unique
    "timestamp_utc":   "ISO 8601 UTC",    # Horodatage unifié
    "source":          "docker_logs" | "cadvisor" | "falco_generator",
    "event_type":      voir VALID_EVENT_TYPES,
    "service":         "<nom du service>",
    "severity":        "INFO" | "WARNING" | "CRITICAL",
    "fields":          { ... champs spécifiques au type ... },
    "phase2_meta": {
        "collected_at":  "ISO 8601 UTC",
        "normalized":    true,
        "topic_origin":  "logs-applicatifs" | ...
    }
}

DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
"""

import json
import uuid
import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError

from config.phase2_settings import (
    KAFKA_TOPICS,
    KAFKA_BOOTSTRAP_SERVERS,
    VALID_EVENT_TYPES,
    EVENTS_LOG_FILE,
)

logger = logging.getLogger("phase2.normalizer")

# ─────────────────────────────────────────
# Mapping source → topic d'origine
# ─────────────────────────────────────────
SOURCE_TO_TOPIC = {
    "docker_logs":    KAFKA_TOPICS["logs"],
    "cadvisor":       KAFKA_TOPICS["metrics"],
    "falco_generator": KAFKA_TOPICS["alerts"],
}

# Types d'événements qui nécessitent une remontée en CRITICAL
CRITICAL_EVENT_TYPES = {"ALERT_SCAN", "ALERT_BRUTE", "ALERT_LATERAL"}


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _infer_severity(event: dict) -> str:
    """
    Infère la sévérité si absente de l'événement source.

    Règles :
    - Tous les types ALERT_* → CRITICAL
    - LOG_AUTH, METRIC_CPU/RAM/NET avec alert=True → WARNING
    - Tout le reste → INFO
    """
    existing = event.get("severity", "").upper()
    if existing in ("INFO", "WARNING", "CRITICAL"):
        return existing

    event_type = event.get("event_type", "")
    if event_type in CRITICAL_EVENT_TYPES:
        return "CRITICAL"

    fields = event.get("fields", {})
    if event_type == "LOG_AUTH":
        return "WARNING"
    if fields.get("alert"):
        return "WARNING"
    return "INFO"


def _validate_schema(event: dict) -> tuple[bool, str]:
    """
    Valide que l'événement contient les champs obligatoires.

    Retourne (True, "") si valide, (False, "<raison>") sinon.
    """
    required = {"schema_version", "timestamp_utc", "source",
                 "event_type", "service"}
    missing = required - set(event.keys())
    if missing:
        return False, f"Champs manquants : {missing}"

    if event.get("event_type") not in VALID_EVENT_TYPES:
        # On laisse passer LOG_INFO qui n'est pas dans VALID_EVENT_TYPES
        # mais est généré normalement par le Docker collector
        if event.get("event_type") != "LOG_INFO":
            return False, f"Type inconnu : {event.get('event_type')}"

    return True, ""


def normalize_event(raw_event: dict,
                    topic_origin: str = "unknown") -> Optional[dict]:
    """
    Normalise un événement brut vers le schéma unifié Phase 2.

    Retourne None si l'événement est invalide ou doit être filtré.
    """
    valid, reason = _validate_schema(raw_event)
    if not valid:
        logger.debug(f"Événement rejeté ({reason}): {str(raw_event)[:80]}")
        return None

    return {
        "schema_version": "1.0",
        "event_id":       str(uuid.uuid4()),
        "timestamp_utc":  raw_event.get("timestamp_utc", _now_utc_iso()),
        "source":         raw_event.get("source", "unknown"),
        "event_type":     raw_event.get("event_type"),
        "service":        raw_event.get("service", "unknown"),
        "severity":       _infer_severity(raw_event),
        "fields":         raw_event.get("fields", {}),
        "phase2_meta": {
            "collected_at": _now_utc_iso(),
            "normalized":   True,
            "topic_origin": topic_origin,
        },
    }


class EventNormalizer:
    """
    Consommateur Kafka multi-topics.

    Lit les 3 topics en continu, normalise chaque événement,
    et écrit le résultat dans le fichier JSONL de sortie.
    En Phase 3, ce composant sera remplacé par le moteur CEP
    qui consommera directement les topics.
    """

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stats = {
            "consumed": 0,
            "normalized": 0,
            "rejected": 0,
            "written": 0,
        }
        self._output_file = None

    def _init_consumer(self) -> KafkaConsumer:
        """Initialise le consommateur Kafka multi-topics."""
        topics = list(KAFKA_TOPICS.values())
        return KafkaConsumer(
            *topics,
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            auto_offset_reset="earliest",
            enable_auto_commit=True,
            group_id="microsecure-normalizer",
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            consumer_timeout_ms=1000,   # 1s de timeout pour la boucle
        )

    def _run_loop(self) -> None:
        logger.info("Normaliseur démarré — consommation des 3 topics.")

        try:
            consumer = self._init_consumer()
        except Exception as exc:
            logger.error(f"Connexion Kafka impossible : {exc}")
            return

        try:
            self._output_file = open(EVENTS_LOG_FILE, "a", encoding="utf-8")

            while self._running:
                for message in consumer:
                    if not self._running:
                        break

                    self._stats["consumed"] += 1
                    topic = message.topic
                    raw   = message.value

                    normalized = normalize_event(raw, topic_origin=topic)

                    if normalized is None:
                        self._stats["rejected"] += 1
                        continue

                    self._stats["normalized"] += 1

                    # Écriture JSONL (un événement par ligne)
                    self._output_file.write(
                        json.dumps(normalized, ensure_ascii=False) + "\n"
                    )
                    self._output_file.flush()
                    self._stats["written"] += 1

                    # Log des événements critiques uniquement
                    if normalized["severity"] == "CRITICAL":
                        logger.warning(
                            f"[CRITICAL] {normalized['event_type']} "
                            f"sur {normalized['service']} "
                            f"@ {normalized['timestamp_utc']}"
                        )

        finally:
            if self._output_file:
                self._output_file.close()
            consumer.close()
            logger.info(f"Normaliseur arrêté. Stats : {self._stats}")

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="event-normalizer"
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def get_stats(self) -> dict:
        return dict(self._stats)
