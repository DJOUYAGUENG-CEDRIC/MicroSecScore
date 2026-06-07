"""
phase2_runtime.py
====================================
Orchestrateur principal de la Phase 2 — MicroSecScore.

Lance les 3 collecteurs en parallèle, démarre le normaliseur,
et affiche un tableau de bord en temps réel dans le terminal.

Usage :
    python phase2_runtime.py                    # Pipeline complet
    python phase2_runtime.py --test-kafka       # Vérifie Kafka uniquement
    python phase2_runtime.py --inject-attack    # Injecte un scénario APT complet
    python phase2_runtime.py --duration 60      # Durée fixe en secondes

DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

# ─────────────────────────────────────────
# Setup logging
# ─────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
os.makedirs("data/output", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s",
    handlers=[
        logging.FileHandler("logs/phase2.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("phase2.main")

from kafka import KafkaProducer
from kafka.errors import NoBrokersAvailable

from config.phase2_settings import (
    KAFKA_BOOTSTRAP_SERVERS,
    PHASE2_REPORT_FILE,
)
from collectors.docker_log_collector import DockerLogCollector
from collectors.prometheus_collector import PrometheusCollector
from collectors.falco_generator      import FalcoGenerator
from normalizer.event_normalizer     import EventNormalizer
from utils.topology_loader           import charger_topologie_phase1


# ─────────────────────────────────────────
# Initialisation du producteur Kafka partagé
# ─────────────────────────────────────────
def _init_producer() -> KafkaProducer:
    """
    Initialise le producteur Kafka.
    Réessaie 3 fois avec délai exponentiel.
    """
    for attempt in range(1, 4):
        try:
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                acks="all",
                retries=3,
                retry_backoff_ms=500,
            )
            logger.info(f"Producteur Kafka connecté ({KAFKA_BOOTSTRAP_SERVERS})")
            return producer
        except NoBrokersAvailable:
            logger.warning(
                f"Kafka indisponible (tentative {attempt}/3). "
                f"Attente {2**attempt}s..."
            )
            time.sleep(2 ** attempt)

    logger.error(
        "ERREUR : Kafka inaccessible après 3 tentatives.\n"
        "Vérifiez que le stack Kafka est démarré :\n"
        "  cd phase2/kafka\n"
        "  docker-compose -f docker-compose-kafka.yml up -d"
    )
    sys.exit(1)


def test_kafka_connection() -> bool:
    """Vérifie la connexion Kafka et liste les topics disponibles."""
    print("\n" + "="*60)
    print("TEST DE CONNEXION KAFKA")
    print("="*60)

    try:
        from kafka.admin import KafkaAdminClient
        admin = KafkaAdminClient(bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS)
        topics = admin.list_topics()
        admin.close()

        expected = {"logs-applicatifs", "metriques-systeme", "alertes-securite"}
        found    = set(t for t in topics if not t.startswith("_"))

        print(f"\n✅ Kafka accessible : {KAFKA_BOOTSTRAP_SERVERS}")
        print(f"\nTopics trouvés : {found}")

        missing = expected - found
        if missing:
            print(f"\n⚠️  Topics manquants : {missing}")
            print("   → Relancez kafka-init via docker-compose")
            return False
        else:
            print(f"\n✅ Les 3 topics MicroSecScore sont présents.")
            return True

    except Exception as exc:
        print(f"\n❌ Kafka inaccessible : {exc}")
        print("\nPour démarrer Kafka :")
        print("  cd phase2/kafka")
        print("  docker-compose -f docker-compose-kafka.yml up -d")
        print("  (attendre ~30 secondes)")
        return False


def _print_dashboard(
    log_stats: dict, metric_stats: dict,
    falco_stats: dict, norm_stats: dict,
    elapsed_s: float
) -> None:
    """Affiche les statistiques en temps réel."""
    os.system("cls" if os.name == "nt" else "clear")

    print("=" * 65)
    print("   MicroSecScore — Phase 2 : Collecte Runtime en cours")
    print(f"   Durée : {int(elapsed_s // 60):02d}:{int(elapsed_s % 60):02d}")
    print("=" * 65)

    print("\n📋 SOURCE 1 — Logs Docker Engine")
    print(f"   Conteneurs surveillés : {log_stats.get('containers', 0)}")
    print(f"   Événements publiés    : {log_stats.get('published', 0)}")
    print(f"   Erreurs               : {log_stats.get('errors', 0)}")

    print("\n📊 SOURCE 2 — Métriques cAdvisor/Prometheus")
    print(f"   Cycles de scraping    : {metric_stats.get('scrapes', 0)}")
    print(f"   Métriques publiées    : {metric_stats.get('published', 0)}")
    print(f"   Alertes déclenchées   : {metric_stats.get('alerts_triggered', 0)}")

    print("\n🚨 SOURCE 3 — Alertes Falco (simulées)")
    print(f"   Scans de reconn.      : {falco_stats.get('scan_alerts', 0)}")
    print(f"   Force brute           : {falco_stats.get('brute_alerts', 0)}")
    print(f"   Mouvements latéraux   : {falco_stats.get('lateral_alerts', 0)}")
    print(f"   Total publié          : {falco_stats.get('total_published', 0)}")

    print("\n🔄 NORMALISEUR")
    print(f"   Événements consommés  : {norm_stats.get('consumed', 0)}")
    print(f"   Normalisés            : {norm_stats.get('normalized', 0)}")
    print(f"   Rejetés               : {norm_stats.get('rejected', 0)}")
    print(f"   Écrits dans JSONL     : {norm_stats.get('written', 0)}")

    print("\n" + "-" * 65)
    print("   Ctrl+C pour arrêter proprement")
    print("   Interface Kafka : http://localhost:8090")
    print("=" * 65)


def save_report(log_s, metric_s, falco_s, norm_s, duration_s: float) -> None:
    """Sauvegarde le rapport JSON de fin de session."""
    report = {
        "phase": "Phase 2 — Collecte Runtime",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(duration_s, 1),
        "sources": {
            "docker_logs":    log_s,
            "cadvisor":       metric_s,
            "falco_generator": falco_s,
        },
        "normalizer": norm_s,
        "total_events": norm_s.get("normalized", 0),
    }
    with open(PHASE2_REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    logger.info(f"Rapport sauvegardé : {PHASE2_REPORT_FILE}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phase 2 MicroSecScore — Collecte Runtime"
    )
    parser.add_argument("--test-kafka", action="store_true",
                        help="Teste la connexion Kafka et quitte")
    parser.add_argument("--inject-attack", action="store_true",
                        help="Injecte un scénario APT complet et quitte")
    parser.add_argument("--duration", type=int, default=0,
                        help="Durée de collecte en secondes (0 = infini)")
    args = parser.parse_args()

    # ── Mode test Kafka ────────────────────────────────────
    if args.test_kafka:
        ok = test_kafka_connection()
        sys.exit(0 if ok else 1)

    # ── Initialisation ─────────────────────────────────────
    logger.info("Phase 2 MicroSecScore — Démarrage")
    topo = charger_topologie_phase1()
    if not topo:
        logger.warning("graph_G0.json introuvable — collecte sur tous les conteneurs")

    producer    = _init_producer()
    log_coll    = DockerLogCollector(producer, topologie_phase1=topo)
    metric_coll = PrometheusCollector(producer)
    falco_gen   = FalcoGenerator(producer)
    normalizer  = EventNormalizer()

    # ── Mode injection d'attaque ───────────────────────────
    if args.inject_attack:
        logger.info("Injection d'un scénario APT complet...")
        normalizer.start()
        time.sleep(1)
        falco_gen.inject_single_attack_scenario("full")
        time.sleep(10)   # Laisser le normaliseur traiter
        normalizer.stop()
        producer.flush()
        producer.close()
        logger.info("Scénario APT injecté. Vérifiez data/output/events_collected.jsonl")
        sys.exit(0)

    # ── Pipeline complet ───────────────────────────────────
    logger.info("Démarrage du pipeline complet...")
    start_time = time.time()

    try:
        log_coll.start()
        metric_coll.start()
        falco_gen.start()
        normalizer.start()

        while True:
            elapsed = time.time() - start_time
            _print_dashboard(
                log_coll.get_stats(),
                metric_coll.get_stats(),
                falco_gen.get_stats(),
                normalizer.get_stats(),
                elapsed,
            )

            if args.duration and elapsed >= args.duration:
                logger.info(f"Durée atteinte : {args.duration}s")
                break

            time.sleep(5)

    except KeyboardInterrupt:
        print("\n\nArrêt demandé par l'utilisateur...")

    finally:
        duration = time.time() - start_time
        log_coll.stop()
        metric_coll.stop()
        falco_gen.stop()
        normalizer.stop()
        producer.flush()
        producer.close()
        save_report(
            log_coll.get_stats(),
            metric_coll.get_stats(),
            falco_gen.get_stats(),
            normalizer.get_stats(),
            duration,
        )
        print(f"\n✅ Phase 2 arrêtée proprement après {int(duration)}s.")
        print(f"   Rapport : {PHASE2_REPORT_FILE}")
        print(f"   Événements : data/output/events_collected.jsonl")


if __name__ == "__main__":
    main()
