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
import random
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

try:
    from utils.topology_loader import charger_topologie_phase1 as _charger_topo
except ImportError:
    _charger_topo = None

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


_INFRA_KW = ("kafka", "zookeeper", "cadvisor", "prometheus",
             "kafka-ui", "kafka_ui", "microsecure")


def _parse_docker_stats(raw: dict) -> tuple[float | None, float | None, float, float]:
    """
    Extrait CPU %, RAM % et octets réseau depuis docker container.stats().

    Retourne (cpu_pct, ram_pct, rx_bytes, tx_bytes).
    cpu_pct/ram_pct = None si impossible à calculer.
    """
    cpu_pct = None
    ram_pct = None
    rx_bytes = 0.0
    tx_bytes = 0.0

    try:
        cpu_delta = (
            raw["cpu_stats"]["cpu_usage"]["total_usage"]
            - raw["precpu_stats"]["cpu_usage"]["total_usage"]
        )
        sys_delta = (
            raw["cpu_stats"].get("system_cpu_usage", 0)
            - raw["precpu_stats"].get("system_cpu_usage", 0)
        )
        num_cpus = raw["cpu_stats"].get("online_cpus") or len(
            raw["cpu_stats"]["cpu_usage"].get("percpu_usage", [1])
        )
        if sys_delta > 0:
            cpu_pct = round((cpu_delta / sys_delta) * num_cpus * 100.0, 2)
            cpu_pct = max(0.0, min(cpu_pct, 100.0))
    except (KeyError, ZeroDivisionError):
        pass

    try:
        mem_usage = raw["memory_stats"]["usage"]
        mem_limit = raw["memory_stats"]["limit"]
        if mem_limit > 0:
            ram_pct = round((mem_usage / mem_limit) * 100.0, 2)
    except KeyError:
        pass

    try:
        for iface in raw.get("networks", {}).values():
            rx_bytes += iface.get("rx_bytes", 0)
            tx_bytes += iface.get("tx_bytes", 0)
    except Exception:
        pass

    return cpu_pct, ram_pct, rx_bytes, tx_bytes


class PrometheusCollector:
    """
    Collecteur de métriques via Docker stats API (sans cAdvisor).

    Pour chaque conteneur Sock Shop détecté, récupère CPU, RAM et réseau
    directement via le SDK Docker — aucune dépendance externe requise.
    Bascule en simulation uniquement si Docker est complètement absent.
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

        # Réseau : octets précédents par conteneur pour calculer les deltas
        self._prev_net: dict[str, tuple[float, float]] = {}

        # Topologie Phase 1 pour filtrage et simulation fallback
        self._topo_services: list[str] = []
        if _charger_topo:
            try:
                topo = _charger_topo()
                self._topo_services = [s for s in topo if s != "Outside"]
            except Exception:
                pass
        if not self._topo_services:
            self._topo_services = [
                "front-end", "orders", "catalogue", "user",
                "payment", "cart", "shipping", "queue-master",
                "rabbitmq", "edge-router",
            ]

        # Connexion Docker
        self.simulation_mode = False
        try:
            import docker as _docker
            self._docker = _docker.from_env()
            self._docker.ping()
            logger.info("PrometheusCollector : Docker API connectée.")
        except Exception as exc:
            logger.warning(f"Docker indisponible — simulation métriques : {exc}")
            self._docker = None
            self.simulation_mode = True

    # ------------------------------------------------------------------
    # Scraping Docker stats (mode réel)
    # ------------------------------------------------------------------

    def _scrape_once(self) -> None:
        """Un cycle : récupère les stats Docker de tous les conteneurs Sock Shop."""
        try:
            containers = self._docker.containers.list()
        except Exception as exc:
            logger.warning(f"Erreur liste conteneurs : {exc}")
            self._stats["errors"] += 1
            return

        # Filtrer sur les services G0 + exclure l'infra
        cibles = [
            c for c in containers
            if not any(kw in c.name.lower() for kw in _INFRA_KW)
        ]
        if self._topo_services:
            from collectors.docker_log_collector import _extract_service_name
            cibles = [
                c for c in cibles
                if _extract_service_name(c) in self._topo_services
            ]

        if not cibles:
            logger.debug("Aucun conteneur Sock Shop trouvé pour les métriques.")
            self._stats["errors"] += 1
            return

        self._stats["scrapes"] += 1

        for container in cibles:
            from collectors.docker_log_collector import _extract_service_name
            service = _extract_service_name(container)
            try:
                raw = container.stats(stream=False)
                self._publier_stats(service, container.name, raw)
            except Exception as exc:
                logger.debug(f"Stats indisponibles pour {container.name} : {exc}")

    def _publier_stats(self, service: str, container_name: str, raw: dict) -> None:
        """Parse et publie les métriques d'un conteneur."""
        cpu_pct, ram_pct, rx_bytes, tx_bytes = _parse_docker_stats(raw)

        # ── CPU ──────────────────────────────────────────────────────
        if cpu_pct is not None:
            sev = "CRITICAL" if cpu_pct > CPU_ALERT_THRESHOLD_PCT else "INFO"
            if sev == "CRITICAL":
                self._stats["alerts_triggered"] += 1
            self._publish(_build_metric_event(service, "METRIC_CPU", {
                "cpu_percent": cpu_pct,
                "threshold":   CPU_ALERT_THRESHOLD_PCT,
                "alert":       sev == "CRITICAL",
                "container":   container_name,
            }, sev))

        # ── RAM ──────────────────────────────────────────────────────
        if ram_pct is not None:
            sev = "CRITICAL" if ram_pct > RAM_ALERT_THRESHOLD_PCT else "INFO"
            if sev == "CRITICAL":
                self._stats["alerts_triggered"] += 1
            self._publish(_build_metric_event(service, "METRIC_RAM", {
                "ram_percent": ram_pct,
                "threshold":   RAM_ALERT_THRESHOLD_PCT,
                "alert":       sev == "CRITICAL",
                "container":   container_name,
            }, sev))

        # ── Réseau (delta par rapport au cycle précédent) ─────────────
        prev_rx, prev_tx = self._prev_net.get(container_name, (rx_bytes, tx_bytes))
        delta_rx = max(0.0, rx_bytes - prev_rx)
        delta_tx = max(0.0, tx_bytes - prev_tx)
        self._prev_net[container_name] = (rx_bytes, tx_bytes)

        interval = METRICS_INTERVAL_S or 15
        rx_mbps = round((delta_rx * 8) / (interval * 1_000_000), 4)
        tx_mbps = round((delta_tx * 8) / (interval * 1_000_000), 4)
        total   = rx_mbps + tx_mbps

        if delta_rx > 0 or delta_tx > 0:
            sev = "CRITICAL" if total > NET_ALERT_THRESHOLD_MBPS else "INFO"
            self._publish(_build_metric_event(service, "METRIC_NET", {
                "rx_mbps":   rx_mbps,
                "tx_mbps":   tx_mbps,
                "threshold": NET_ALERT_THRESHOLD_MBPS,
                "alert":     sev == "CRITICAL",
                "container": container_name,
            }, sev))

    # ------------------------------------------------------------------
    # Simulation (fallback si Docker absent)
    # ------------------------------------------------------------------

    def _simulate_once(self) -> None:
        """Métriques simulées — uniquement si Docker est complètement absent."""
        for service in self._topo_services:
            cpu_pct = round(random.triangular(2.0, 60.0, 20.0), 2)
            sev = "CRITICAL" if cpu_pct > CPU_ALERT_THRESHOLD_PCT else "INFO"
            self._publish(_build_metric_event(service, "METRIC_CPU", {
                "cpu_percent": cpu_pct, "threshold": CPU_ALERT_THRESHOLD_PCT,
                "alert": sev == "CRITICAL", "simulated": True,
            }, sev))

            ram_pct = round(random.triangular(10.0, 80.0, 35.0), 2)
            sev = "CRITICAL" if ram_pct > RAM_ALERT_THRESHOLD_PCT else "INFO"
            self._publish(_build_metric_event(service, "METRIC_RAM", {
                "ram_percent": ram_pct, "threshold": RAM_ALERT_THRESHOLD_PCT,
                "alert": sev == "CRITICAL", "simulated": True,
            }, sev))

        self._stats["scrapes"] += 1

    # ------------------------------------------------------------------
    # Commun
    # ------------------------------------------------------------------

    def _publish(self, event: dict) -> None:
        try:
            payload = json.dumps(event, ensure_ascii=False).encode("utf-8")
            self.producer.send(self.topic, value=payload)
            self._stats["published"] += 1
        except KafkaError as exc:
            logger.warning(f"Erreur publication Kafka métriques : {exc}")
            self._stats["errors"] += 1

    def _run_loop(self) -> None:
        mode = "SIMULATION" if self.simulation_mode else "Docker stats API"
        logger.info(f"PrometheusCollector démarré en mode {mode}.")

        while self._running:
            try:
                if self.simulation_mode:
                    self._simulate_once()
                else:
                    self._scrape_once()
            except Exception as exc:
                logger.error(f"Erreur cycle métriques : {exc}")
                self._stats["errors"] += 1
            time.sleep(METRICS_INTERVAL_S)

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="metrics-scraper"
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        logger.info(f"PrometheusCollector arrêté. Stats : {self._stats}")

    def get_stats(self) -> dict:
        return dict(self._stats)
