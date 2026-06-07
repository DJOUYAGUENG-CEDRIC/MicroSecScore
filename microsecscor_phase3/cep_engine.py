"""
MicroSecScore — Phase 3 : Moteur CEP (Complex Event Processing)

7 threads de détection avec adaptateurs de schéma Phase 2 → Phase 3.
Publie les alertes sur le topic "alertes-cep" (consommé par Phase 4).

Routage corrigé (Phase 2 → Phase 3) :
  alertes-securite  → P1 (ALERT_SCAN→CONNECTION)
                    → P2 (ALERT_BRUTE→AUTH_FAILED)
                    → P3 (ALERT_LATERAL→INTER_SERVICE_CALL)
                    → P5 (ALERT_ESCAPE→FALCO_ALERT)
  logs-applicatifs  → P4 (LOG_AUTH→AUTH_FAILED/SUCCESS)
  metriques-systeme → P6 (METRIC_NET→net_out_kb)
                    → P7 (METRIC_CPU→cpu_pct+erreurs_5xx)

Usage :
  python -X utf8 cep_engine.py

DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
"""

import json
import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone

import colorama
from colorama import Fore

colorama.init(autoreset=True)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("cep_engine")

# ── Configuration Kafka / Neo4j ───────────────────────────────────────────────
KAFKA_BOOTSTRAP   = "localhost:9092"
NEO4J_URI         = "bolt://localhost:7687"
NEO4J_USER        = "neo4j"
NEO4J_PASSWORD    = "microsecure"

TOPIC_LOGS        = "logs-applicatifs"
TOPIC_METRIQUES   = "metriques-systeme"
TOPIC_ALERTES_SEC = "alertes-securite"
TOPIC_CEP_OUT     = "alertes-cep"

KAFKA_RETRY_MAX   = 5
KAFKA_RETRY_DELAY = 5
SUPERVISION_INTERVAL = 30

# ── Fichiers de sortie (lus par le dashboard web Phase 3) ─────────────────────
_CEP_DIR        = os.path.dirname(os.path.abspath(__file__))
CEP_ALERTS_FILE = os.path.join(_CEP_DIR, "data", "alertes_cep.jsonl")
CEP_STATUS_FILE = os.path.join(_CEP_DIR, "data", "cep_status.json")
os.makedirs(os.path.join(_CEP_DIR, "data"), exist_ok=True)

_file_lock      = threading.Lock()
_CEP_START_TIME = datetime.now(timezone.utc).isoformat()


def _ecrire_alerte(alerte: dict) -> None:
    with _file_lock:
        with open(CEP_ALERTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(alerte, ensure_ascii=False) + "\n")


def _ecrire_statut(threads: list, g0_cache) -> None:
    nb_actifs     = sum(1 for t in threads if t.is_alive())
    alertes_total = sum(t.nb_alertes for t in threads)
    statut = {
        "running":        True,
        "started_at":     _CEP_START_TIME,
        "threads_total":  len(threads),
        "threads_actifs": nb_actifs,
        "alertes_total":  alertes_total,
        "last_refresh":   datetime.now(timezone.utc).isoformat(),
        "rules": [
            {"nom": t.name, "actif": t.is_alive(), "alertes": t.nb_alertes}
            for t in threads
        ],
    }
    with _file_lock:
        with open(CEP_STATUS_FILE, "w", encoding="utf-8") as f:
            json.dump(statut, f, ensure_ascii=False)


# ═══════════════════════════════════════════════════════════════════════════════
# ADAPTATEURS DE SCHÉMA Phase 2 → Phase 3
#
# Phase 2 produit des événements avec :
#   - "event_type" (pas "type")
#   - "timestamp_utc" (pas "timestamp")
#   - champs métier dans "fields" (pas au niveau racine)
#
# Chaque adaptateur traduit un événement Phase 2 en liste d'événements
# au format attendu par les règles Phase 3.
# ═══════════════════════════════════════════════════════════════════════════════

def _ms(event: dict) -> dict:
    """Extrait le sous-dict microsecure depuis fields."""
    fields = event.get("fields") or {}
    return fields.get("microsecure", {}) if isinstance(fields, dict) else {}


def _ts(event: dict) -> str:
    """Retourne le timestamp de l'événement (timestamp_utc ou timestamp)."""
    return event.get("timestamp_utc") or event.get("timestamp", "")


def _adapter_scan(event: dict) -> list[dict]:
    """
    ALERT_SCAN (Phase 2) → N événements CONNECTION/REFUSED pour P1.
    Le FalcoGenerator crée déjà une alerte agrégée avec nb_ports_sondes > 50.
    On les re-déroule en événements individuels pour que la fenêtre P1 les compte.
    """
    if event.get("event_type") != "ALERT_SCAN":
        return []
    ms      = _ms(event)
    ip_src  = ms.get("ip_source", "")
    nb_ports = int(ms.get("nb_ports_sondes", 0))
    ts      = _ts(event)
    if not ip_src or nb_ports == 0:
        return []
    return [
        {"type": "CONNECTION", "result": "REFUSED",
         "ip_src": ip_src, "port_dst": p, "timestamp": ts}
        for p in range(1, nb_ports + 1)
    ]


def _adapter_brute(event: dict) -> list[dict]:
    """
    ALERT_BRUTE (Phase 2) → N événements AUTH_FAILED pour P2.
    """
    if event.get("event_type") != "ALERT_BRUTE":
        return []
    ms         = _ms(event)
    ip_src     = ms.get("ip_source", "")
    user_cible = ms.get("user_cible", "")
    nb_tentes  = int(ms.get("nb_tentatives", 0))
    ts         = _ts(event)
    if not ip_src or nb_tentes == 0:
        return []
    return [
        {"type": "AUTH_FAILED", "ip_src": ip_src,
         "user_cible": user_cible, "timestamp": ts}
        for _ in range(nb_tentes)
    ]


def _adapter_lateral(event: dict) -> list[dict]:
    """
    ALERT_LATERAL (Phase 2) → 1 événement INTER_SERVICE_CALL pour P3.
    """
    if event.get("event_type") != "ALERT_LATERAL":
        return []
    ms  = _ms(event)
    src = ms.get("service_source", "")
    dst = ms.get("service_cible", "")
    ts  = _ts(event)
    if not src or not dst:
        return []
    return [{"type": "INTER_SERVICE_CALL", "premier_contact": True,
             "service_src": src, "service_dst": dst, "timestamp": ts}]


def _adapter_escape(event: dict) -> list[dict]:
    """
    ALERT_ESCAPE (Phase 2) → 1 événement FALCO_ALERT avec mot-clé évasion pour P5.
    """
    if event.get("event_type") != "ALERT_ESCAPE":
        return []
    fields  = event.get("fields") or {}
    ms      = _ms(event)
    output  = str(fields.get("output") or ms.get("keyword", "execve"))
    rule    = str(fields.get("rule") or "Terminal shell in container")
    return [{
        "type":      "FALCO_ALERT",
        "severity":  event.get("severity", "CRITICAL"),
        "service":   event.get("service", ""),
        "message":   output,
        "rule":      rule,
        "timestamp": _ts(event),
    }]


def _adapter_logs(event: dict) -> list[dict]:
    """
    LOG_AUTH (Phase 2) → AUTH_FAILED ou AUTH_SUCCESS pour P4.
    LOG_HTTP avec code 200 sur /login → AUTH_SUCCESS.
    """
    etype  = event.get("event_type", "")
    ts     = _ts(event)
    svc    = event.get("service", "unknown")
    fields = event.get("fields") or {}

    if etype == "LOG_AUTH":
        auth_failed = bool(fields.get("auth_failed", True) if isinstance(fields, dict) else True)
        ev_type = "AUTH_FAILED" if auth_failed else "AUTH_SUCCESS"
        return [{"type": ev_type, "ip_src": svc, "user_cible": svc, "timestamp": ts}]

    if etype == "LOG_HTTP" and isinstance(fields, dict):
        status = int(fields.get("http_status_code", 0))
        path   = str(fields.get("http_path", ""))
        if status == 200 and "login" in path:
            return [{"type": "AUTH_SUCCESS", "ip_src": svc,
                     "user_cible": svc, "timestamp": ts}]
    return []


def _adapter_metric_net(event: dict) -> list[dict]:
    """
    METRIC_NET (Phase 2) → net_out_kb pour P6.
    Conversion : tx_mbps × 1000 ≈ KB sur l'intervalle de collecte.
    """
    if event.get("event_type") != "METRIC_NET":
        return []
    fields    = event.get("fields") or {}
    tx_mbps   = float(fields.get("tx_mbps", 0) if isinstance(fields, dict) else 0)
    net_out_kb = tx_mbps * 1000
    return [{
        "service":    event.get("service", ""),
        "net_out_kb": net_out_kb,
        "timestamp":  _ts(event),
    }]


def _adapter_metric_cpu(event: dict) -> list[dict]:
    """
    METRIC_CPU (Phase 2) → cpu_pct + erreurs_5xx pour P7.
    Si alert=True (CPU > seuil), on simule des erreurs HTTP 5xx.
    """
    if event.get("event_type") != "METRIC_CPU":
        return []
    fields  = event.get("fields") or {}
    cpu_pct = float(fields.get("cpu_percent", 0) if isinstance(fields, dict) else 0)
    alerte  = bool(fields.get("alert", False) if isinstance(fields, dict) else False)
    return [{
        "service":     event.get("service", ""),
        "cpu_pct":     cpu_pct,
        "erreurs_5xx": 15 if alerte else 0,
        "timestamp":   _ts(event),
    }]


# ── Utilitaires Kafka ─────────────────────────────────────────────────────────

def _creer_consumer(topic: str, group_id: str):
    from kafka import KafkaConsumer
    for tentative in range(1, KAFKA_RETRY_MAX + 1):
        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=[KAFKA_BOOTSTRAP],
                group_id=group_id,
                auto_offset_reset="latest",
                enable_auto_commit=True,
                consumer_timeout_ms=1000,
                value_deserializer=lambda b: json.loads(b.decode("utf-8")),
            )
            logger.info("Consumer '%s' connecté au topic '%s'.", group_id, topic)
            return consumer
        except Exception as exc:
            logger.warning("Kafka indisponible (tentative %d/%d) : %s",
                           tentative, KAFKA_RETRY_MAX, exc)
            if tentative < KAFKA_RETRY_MAX:
                time.sleep(KAFKA_RETRY_DELAY)
    logger.error("Impossible de se connecter à Kafka après %d tentatives.", KAFKA_RETRY_MAX)
    sys.exit(1)


def _creer_producer():
    from kafka import KafkaProducer
    for tentative in range(1, KAFKA_RETRY_MAX + 1):
        try:
            producer = KafkaProducer(
                bootstrap_servers=[KAFKA_BOOTSTRAP],
                acks="all",
                retries=3,
                value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
            )
            logger.info("Producer Kafka connecté → topic '%s'.", TOPIC_CEP_OUT)
            return producer
        except Exception as exc:
            logger.warning("Producer Kafka indisponible (tentative %d/%d) : %s",
                           tentative, KAFKA_RETRY_MAX, exc)
            if tentative < KAFKA_RETRY_MAX:
                time.sleep(KAFKA_RETRY_DELAY)
    logger.error("Impossible de créer le producer Kafka.")
    sys.exit(1)


# ── Thread générique de détection ─────────────────────────────────────────────

class DetectionThread(threading.Thread):
    """
    Consomme un topic Kafka, applique l'adaptateur de schéma,
    puis passe chaque événement normalisé au détecteur CEP.
    """

    def __init__(self, nom: str, topic: str, group_id: str,
                 detecteur, producer, adapter=None):
        super().__init__(name=nom, daemon=True)
        self._topic     = topic
        self._group_id  = group_id
        self._detecteur = detecteur
        self._producer  = producer
        self._adapter   = adapter           # callable(dict) → list[dict]
        self._stop      = threading.Event()
        self._consumer  = None
        self.nb_alertes = 0

    def run(self) -> None:
        self._consumer = _creer_consumer(self._topic, self._group_id)
        logger.info("Thread '%s' démarré (topic=%s).", self.name, self._topic)
        while not self._stop.is_set():
            try:
                for msg in self._consumer:
                    if self._stop.is_set():
                        break
                    try:
                        # Traduire l'événement Phase 2 en format Phase 3
                        evenements = (
                            self._adapter(msg.value)
                            if self._adapter else [msg.value]
                        )
                        for ev in evenements:
                            alerte = self._detecteur.process_event(ev)
                            if alerte:
                                try:
                                    self._producer.send(TOPIC_CEP_OUT, alerte)
                                except Exception as exc:
                                    logger.error("[%s] Échec Kafka : %s", self.name, exc)
                                _ecrire_alerte(alerte)
                                self.nb_alertes += 1
                                logger.info("[%s] ALERTE %s — %s",
                                            self.name, alerte.get("severity"), alerte.get("type"))
                    except Exception as exc:
                        logger.error("[%s] Erreur traitement : %s", self.name, exc)
            except Exception as exc:
                if not self._stop.is_set():
                    logger.error("[%s] Erreur consumer : %s", self.name, exc)

    def stop(self) -> None:
        self._stop.set()
        if self._consumer:
            try:
                self._consumer.close()
            except Exception:
                pass


# ── Thread de supervision ─────────────────────────────────────────────────────

class SupervisionThread(threading.Thread):
    def __init__(self, threads: list, g0_cache):
        super().__init__(name="Supervision", daemon=True)
        self._threads = threads
        self._cache   = g0_cache
        self._stop    = threading.Event()

    def run(self) -> None:
        while not self._stop.wait(timeout=SUPERVISION_INTERVAL):
            actifs        = [t.name for t in self._threads if t.is_alive()]
            alertes_total = sum(t.nb_alertes for t in self._threads)
            refresh       = self._cache.last_refresh
            refresh_str   = refresh.strftime("%H:%M:%S UTC") if refresh else "jamais"
            logger.info("Supervision | Threads actifs : %d/%d | Alertes : %d | G0 refresh : %s",
                        len(actifs), len(self._threads), alertes_total, refresh_str)
            _ecrire_statut(self._threads, self._cache)

    def stop(self) -> None:
        self._stop.set()


# ── Moteur principal ──────────────────────────────────────────────────────────

def main() -> None:
    print(Fore.RED + "\n" + "═" * 60)
    print(Fore.RED + "  MicroSecScore — Phase 3 : Moteur CEP")
    print(Fore.RED + "  7 règles MITRE ATT&CK | Kafka → alertes-cep")
    print(Fore.RED + "═" * 60 + "\n")

    from neo4j_cache import G0Cache
    g0_cache = G0Cache(uri=NEO4J_URI, user=NEO4J_USER, password=NEO4J_PASSWORD)
    g0_cache.start()

    producer = _creer_producer()

    from rules.p1_scan         import ScanDetector
    from rules.p2_brute        import BruteForceDetector
    from rules.p3_lateral      import LateralMoveDetector
    from rules.p4_compromise   import CompromiseDetector
    from rules.p5_escape       import ContainerEscapeDetector
    from rules.p6_exfiltration import ExfiltrationDetector
    from rules.p7_dos          import DoSDetector

    def _noop(_): pass   # callback vide — la publication est faite dans DetectionThread

    det_p1 = ScanDetector(alert_callback=_noop)
    det_p2 = BruteForceDetector(alert_callback=_noop)
    det_p3 = LateralMoveDetector(g0_cache=g0_cache, alert_callback=_noop)
    det_p4 = CompromiseDetector(alert_callback=_noop)
    det_p5 = ContainerEscapeDetector(alert_callback=_noop)
    det_p6 = ExfiltrationDetector(alert_callback=_noop)
    det_p7 = DoSDetector(alert_callback=_noop)

    # Routage corrigé + adaptateurs de schéma Phase 2 → Phase 3
    threads = [
        DetectionThread("P1-Scan",         TOPIC_ALERTES_SEC, "cep-p1-scan",
                        det_p1, producer, _adapter_scan),
        DetectionThread("P2-Brute",        TOPIC_ALERTES_SEC, "cep-p2-brute",
                        det_p2, producer, _adapter_brute),
        DetectionThread("P3-Lateral",      TOPIC_ALERTES_SEC, "cep-p3-lateral",
                        det_p3, producer, _adapter_lateral),
        DetectionThread("P4-Compromise",   TOPIC_LOGS,        "cep-p4-compromise",
                        det_p4, producer, _adapter_logs),
        DetectionThread("P5-Escape",       TOPIC_ALERTES_SEC, "cep-p5-escape",
                        det_p5, producer, _adapter_escape),
        DetectionThread("P6-Exfiltration", TOPIC_METRIQUES,   "cep-p6-exfiltration",
                        det_p6, producer, _adapter_metric_net),
        DetectionThread("P7-DoS",          TOPIC_METRIQUES,   "cep-p7-dos",
                        det_p7, producer, _adapter_metric_cpu),
    ]

    supervision = SupervisionThread(threads, g0_cache)

    def _arreter(signum, frame):
        print(Fore.RED + "\n[CEP] Signal d'arrêt reçu — fermeture propre…")
        for t in threads:
            t.stop()
        for t in threads:
            t.join(timeout=5)
        supervision.stop()
        producer.flush()
        producer.close()
        g0_cache.stop()
        with _file_lock:
            with open(CEP_STATUS_FILE, "w", encoding="utf-8") as f:
                json.dump({"running": False,
                           "alertes_total": sum(t.nb_alertes for t in threads),
                           "last_refresh": datetime.now(timezone.utc).isoformat()},
                          f, ensure_ascii=False)
        logger.info("Moteur CEP arrêté.")
        sys.exit(0)

    signal.signal(signal.SIGINT,  _arreter)
    signal.signal(signal.SIGTERM, _arreter)

    for t in threads:
        t.start()
    supervision.start()
    _ecrire_statut(threads, g0_cache)

    logger.info("Moteur CEP démarré — 7 threads | topic sortie : '%s'", TOPIC_CEP_OUT)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
