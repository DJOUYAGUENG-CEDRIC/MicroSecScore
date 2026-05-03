"""
collectors/prometheus_collector.py
====================================
Collecteur de métriques système via Prometheus + cAdvisor.

Principe : cAdvisor expose les métriques système de chaque conteneur
Docker au format Prometheus (CPU, RAM, réseau). Ce collecteur interroge
l'API de cAdvisor toutes les N secondes, détecte les anomalies selon
des seuils configurables, et publie chaque métrique comme événement
normalisé sur le topic Kafka 'metriques-systeme'.

Architecture :
  cAdvisor (port 8080) → scraping Python → Kafka topic 'metriques-systeme'

DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
"""

import json
import time
import logging
import threading
from datetime import datetime, timezone
from typing import Optional

import requests

from kafka import KafkaProducer
from kafka.errors import KafkaError

from config.phase2_settings import (
    KAFKA_TOPICS,
    CADVISOR_URL,
    METRICS_INTERVAL_S,
    CPU_ALERT_THRESHOLD_PCT,
    RAM_ALERT_THRESHOLD_PCT,
    NET_ALERT_THRESHOLD_MBPS,
)

logger = logging.getLogger("phase2.prometheus_collector")

# ─────────────────────────────────────────
# Endpoints cAdvisor
# ─────────────────────────────────────────
CADVISOR_CONTAINERS_API = f"{CADVISOR_URL}/api/v1.3/containers/docker"


def _extract_service_name(container_name: str) -> str:
    """Extrait le nom du service depuis le nom du conteneur cAdvisor."""
    # cAdvisor préfixe les noms avec /docker/<id>
    # On récupère le label Docker Compose si disponible
    name = container_name.strip("/").split("/")[-1]
    parts = name.split("_")
    if len(parts) >= 2:
        return parts[-2] if parts[-1].isdigit() else parts[-1]
    return name


def _safe_get(url: str, timeout: int = 5) -> Optional[dict]:
    """Requête HTTP avec gestion d'erreur — ne lève jamais d'exception."""
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.Timeout:
        logger.warning(f"Timeout sur {url}")
    except requests.ConnectionError:
        logger.warning(f"cAdvisor inaccessible : {url}")
    except Exception as exc:
        logger.warning(f"Erreur requête {url} : {exc}")
    return None


def _compute_cpu_percent(stats: list) -> Optional[float]:
    """
    Calcule le % CPU depuis deux snapshots successifs cAdvisor.

    Formule standard cAdvisor :
    cpu% = (delta_usage / delta_total) × nombre_cpus × 100
    """
    if len(stats) < 2:
        return None

    s1, s2 = stats[-2], stats[-1]
    try:
        delta_usage  = (s2["cpu"]["usage"]["total"]
                       - s1["cpu"]["usage"]["total"])
        delta_total  = (
            (s2["cpu"]["usage"].get("system", 0)
             - s1["cpu"]["usage"].get("system", 0))
            or 1_000_000  # fallback : 1ms en nanosecondes
        )
        nb_cpus = len(s2["cpu"]["usage"].get("per_cpu_usage", [1]))
        cpu_pct = (delta_usage / delta_total) * nb_cpus * 100.0
        return round(max(0.0, min(cpu_pct, 100.0)), 2)
    except (KeyError, ZeroDivisionError):
        return None


def _compute_ram_percent(stats: list, memory_limit: int) -> Optional[float]:
    """Calcule le % RAM depuis le snapshot courant."""
    if not stats or memory_limit <= 0:
        return None
    try:
        usage = stats[-1]["memory"]["usage"]
        return round((usage / memory_limit) * 100.0, 2)
    except KeyError:
        return None


def _compute_net_mbps(stats: list) -> Optional[dict]:
    """
    Calcule le débit réseau entrant/sortant en Mbit/s
    depuis deux snapshots successifs.
    """
    if len(stats) < 2:
        return None
    s1, s2 = stats[-2], stats[-1]

    try:
        ifaces = s2.get("network", {}).get("interfaces", [])
        if not ifaces:
            return None

        # Agrégation sur toutes les interfaces
        rx_bytes_delta = sum(
            iface.get("rx_bytes", 0) for iface in ifaces
        ) - sum(
            iface.get("rx_bytes", 0)
            for iface in s1.get("network", {}).get("interfaces", [])
        )
        tx_bytes_delta = sum(
            iface.get("tx_bytes", 0) for iface in ifaces
        ) - sum(
            iface.get("tx_bytes", 0)
            for iface in s1.get("network", {}).get("interfaces", [])
        )

        # Intervalle en secondes entre les deux snapshots
        interval_s = METRICS_INTERVAL_S or 15

        rx_mbps = round((rx_bytes_delta * 8) / (interval_s * 1_000_000), 4)
        tx_mbps = round((tx_bytes_delta * 8) / (interval_s * 1_000_000), 4)
        return {"rx_mbps": max(0.0, rx_mbps), "tx_mbps": max(0.0, tx_mbps)}

    except Exception:
        return None


def _build_metric_event(service: str, event_type: str, fields: dict,
                         severity: str = "INFO") -> dict:
    """
    Construit un événement métrique normalisé.

    Format de sortie :
    {
        "schema_version": "1.0",
        "timestamp_utc":  "...",
        "source":         "cadvisor",
        "event_type":     "METRIC_CPU" | "METRIC_RAM" | "METRIC_NET",
        "service":        "front-end",
        "severity":       "INFO" | "WARNING" | "CRITICAL",
        "fields":         { valeur_mesurée, seuil, ... }
    }
    """
    return {
        "schema_version": "1.0",
        "timestamp_utc":  datetime.now(timezone.utc).isoformat(),
        "source":         "cadvisor",
        "event_type":     event_type,
        "service":        service,
        "severity":       severity,
        "fields":         fields,
    }


class PrometheusCollector:
    """
    Collecteur de métriques cAdvisor.

    Scrape cAdvisor toutes les METRICS_INTERVAL_S secondes.
    Publie CPU, RAM, réseau pour chaque conteneur sur Kafka.
    Déclenche des alertes automatiques si les seuils sont dépassés.
    """

    def __init__(self, producer: KafkaProducer):
        self.producer = producer
        self.topic    = KAFKA_TOPICS["metrics"]
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stats   = {
            "scrapes": 0,
            "published": 0,
            "alerts_triggered": 0,
            "errors": 0,
        }

    def _publish(self, event: dict) -> None:
        try:
            payload = json.dumps(event, ensure_ascii=False).encode("utf-8")
            self.producer.send(self.topic, value=payload)
            self._stats["published"] += 1
        except KafkaError as exc:
            logger.warning(f"Erreur publication Kafka : {exc}")
            self._stats["errors"] += 1

    def _scrape_once(self) -> None:
        """Un cycle de scraping : interroge cAdvisor et publie les métriques."""
        data = _safe_get(CADVISOR_CONTAINERS_API)
        if data is None:
            self._stats["errors"] += 1
            return

        self._stats["scrapes"] += 1

        for container_id, info in data.items():
            if not isinstance(info, dict):
                continue

            service = _extract_service_name(
                info.get("aliases", ["unknown"])[0]
                if info.get("aliases") else container_id[:12]
            )

            # Ignorer les conteneurs d'infrastructure
            if any(kw in service.lower()
                   for kw in ["kafka", "zookeeper", "cadvisor", "prometheus"]):
                continue

            stats_list    = info.get("stats", [])
            memory_limit  = info.get("spec", {}).get("memory", {}).get("limit", 0)

            # ── CPU ──────────────────────────────────────────
            cpu_pct = _compute_cpu_percent(stats_list)
            if cpu_pct is not None:
                severity = "CRITICAL" if cpu_pct > CPU_ALERT_THRESHOLD_PCT else "INFO"
                if severity == "CRITICAL":
                    self._stats["alerts_triggered"] += 1
                self._publish(_build_metric_event(
                    service=service,
                    event_type="METRIC_CPU",
                    severity=severity,
                    fields={
                        "cpu_percent": cpu_pct,
                        "threshold":   CPU_ALERT_THRESHOLD_PCT,
                        "alert":       severity == "CRITICAL",
                    }
                ))

            # ── RAM ──────────────────────────────────────────
            ram_pct = _compute_ram_percent(stats_list, memory_limit)
            if ram_pct is not None:
                severity = "CRITICAL" if ram_pct > RAM_ALERT_THRESHOLD_PCT else "INFO"
                if severity == "CRITICAL":
                    self._stats["alerts_triggered"] += 1
                self._publish(_build_metric_event(
                    service=service,
                    event_type="METRIC_RAM",
                    severity=severity,
                    fields={
                        "ram_percent":    ram_pct,
                        "memory_limit_mb": round(memory_limit / 1_048_576, 1),
                        "threshold":      RAM_ALERT_THRESHOLD_PCT,
                        "alert":          severity == "CRITICAL",
                    }
                ))

            # ── Réseau ───────────────────────────────────────
            net = _compute_net_mbps(stats_list)
            if net is not None:
                total_mbps = net["rx_mbps"] + net["tx_mbps"]
                severity = ("CRITICAL"
                            if total_mbps > NET_ALERT_THRESHOLD_MBPS
                            else "INFO")
                if severity == "CRITICAL":
                    self._stats["alerts_triggered"] += 1
                self._publish(_build_metric_event(
                    service=service,
                    event_type="METRIC_NET",
                    severity=severity,
                    fields={
                        "rx_mbps":   net["rx_mbps"],
                        "tx_mbps":   net["tx_mbps"],
                        "threshold": NET_ALERT_THRESHOLD_MBPS,
                        "alert":     severity == "CRITICAL",
                    }
                ))

    def _run_loop(self) -> None:
        """Boucle de scraping principale."""
        logger.info(f"Scraping cAdvisor démarré (intervalle={METRICS_INTERVAL_S}s)")
        while self._running:
            try:
                self._scrape_once()
            except Exception as exc:
                logger.error(f"Erreur cycle scraping : {exc}")
                self._stats["errors"] += 1
            time.sleep(METRICS_INTERVAL_S)

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="metrics-scraper"
        )
        self._thread.start()
        logger.info("PrometheusCollector démarré.")

    def stop(self) -> None:
        self._running = False
        logger.info(f"PrometheusCollector arrêté. Stats : {self._stats}")

    def get_stats(self) -> dict:
        return dict(self._stats)
