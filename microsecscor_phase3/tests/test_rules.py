"""
Tests unitaires Phase 3 — MicroSecScore CEP Engine.
Fonctionne SANS Kafka réel et SANS Neo4j réel.

Usage : python tests/test_rules.py
Résultat attendu : 28 tests réussis, 0 échoués.

DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
"""

import sys
import os
from datetime import datetime, timezone, timedelta

# Forcer UTF-8 sur Windows (cp1252 par défaut)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Ajouter microsecscor_phase3/ au path pour les imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rules.p1_scan         import ScanDetector
from rules.p2_brute        import BruteForceDetector
from rules.p3_lateral      import LateralMoveDetector
from rules.p4_compromise   import CompromiseDetector
from rules.p5_escape       import ContainerEscapeDetector
from rules.p6_exfiltration import ExfiltrationDetector
from rules.p7_dos          import DoSDetector


# ── Mock G0Cache (topologie Sock Shop) ───────────────────────────────────────

_DEPENDS_ON = frozenset({
    ("front-end",  "catalogue"),
    ("front-end",  "orders"),
    ("front-end",  "cart"),
    ("front-end",  "user"),
    ("orders",     "orders-db"),
    ("orders",     "payment"),
    ("orders",     "shipping"),
    ("user",       "user-db"),
    ("cart",       "cart-db"),
    ("catalogue",  "catalogue-db"),
})


class MockG0Cache:
    def is_authorized(self, src: str, dst: str) -> bool:
        return (src, dst) in _DEPENDS_ON

    def snapshot(self) -> frozenset:
        return _DEPENDS_ON

    @property
    def last_refresh(self) -> datetime:
        return datetime.now(timezone.utc)


# ── Utilitaires ───────────────────────────────────────────────────────────────

_resultats: list[tuple[str, bool, str]] = []


def _ts(delta_sec: float = 0.0) -> str:
    t = datetime.now(timezone.utc) + timedelta(seconds=delta_sec)
    return t.isoformat()


def affirmer(nom: str, condition: bool, message: str = "") -> None:
    status  = "PASS" if condition else "FAIL"
    symbole = "+" if condition else "X"
    _resultats.append((nom, condition, message))
    detail = f" -- {message}" if message else ""
    print(f"  [{symbole}] [{status}] {nom}{detail}")


def _capturer(alerte_ref: list):
    def callback(a):
        alerte_ref.append(a)
    return callback


# ════════════════════════════════════════════════════════════════════════════
# P1 — Scan de reconnaissance (4 tests)
# ════════════════════════════════════════════════════════════════════════════

def tests_p1():
    print("\n-- P1 Scan de reconnaissance --")

    # test_DECLENCHE_51_ports
    alertes = []
    det = ScanDetector(alert_callback=_capturer(alertes), seuil_ports=50, fenetre_sec=10)
    ts = _ts()
    for port in range(1, 52):
        det.process_event({"type": "CONNECTION", "result": "REFUSED",
                           "ip_src": "10.0.0.1", "port_dst": port, "timestamp": ts})
    affirmer("P1_DECLENCHE_51_ports", len(alertes) == 1, f"alertes={len(alertes)}")
    if alertes:
        affirmer("P1_DECLENCHE_type_correct",  alertes[0]["type"]     == "SCAN_RECONN")
        affirmer("P1_DECLENCHE_severity_MEDIUM", alertes[0]["severity"] == "MEDIUM")

    # test_PAS_ALERTE_50_ports_exact
    alertes2 = []
    det2 = ScanDetector(alert_callback=_capturer(alertes2), seuil_ports=50, fenetre_sec=10)
    ts2 = _ts()
    for port in range(1, 51):
        det2.process_event({"type": "CONNECTION", "result": "CLOSED",
                            "ip_src": "10.0.0.2", "port_dst": port, "timestamp": ts2})
    affirmer("P1_PAS_ALERTE_50_ports_exact", len(alertes2) == 0, f"alertes={len(alertes2)}")

    # test_ignore_connexions_OK
    alertes3 = []
    det3 = ScanDetector(alert_callback=_capturer(alertes3), seuil_ports=50, fenetre_sec=10)
    ts3 = _ts()
    for port in range(1, 100):
        det3.process_event({"type": "CONNECTION", "result": "OK",
                            "ip_src": "10.0.0.3", "port_dst": port, "timestamp": ts3})
    affirmer("P1_ignore_connexions_OK", len(alertes3) == 0)

    # test_ignore_mauvais_type
    alertes4 = []
    det4 = ScanDetector(alert_callback=_capturer(alertes4), seuil_ports=50, fenetre_sec=10)
    ts4 = _ts()
    for port in range(1, 200):
        det4.process_event({"type": "AUTH_FAILED", "result": "REFUSED",
                            "ip_src": "10.0.0.4", "port_dst": port, "timestamp": ts4})
    affirmer("P1_ignore_mauvais_type", len(alertes4) == 0)


# ════════════════════════════════════════════════════════════════════════════
# P2 — Force brute (3 tests)
# ════════════════════════════════════════════════════════════════════════════

def tests_p2():
    print("\n-- P2 Force brute --")

    # test_DECLENCHE_101_echecs
    alertes = []
    det = BruteForceDetector(alert_callback=_capturer(alertes), seuil_echecs=100, fenetre_sec=60)
    ts = _ts()
    for i in range(101):
        det.process_event({"type": "AUTH_FAILED", "ip_src": "192.168.1.1",
                           "user_cible": "admin", "timestamp": ts})
    affirmer("P2_DECLENCHE_101_echecs", len(alertes) == 1, f"alertes={len(alertes)}")
    if alertes:
        affirmer("P2_DECLENCHE_type_correct",   alertes[0]["type"]     == "BRUTE_FORCE")
        affirmer("P2_DECLENCHE_severity_HIGH",  alertes[0]["severity"] == "HIGH")

    # test_PAS_ALERTE_100_echecs_exact
    alertes2 = []
    det2 = BruteForceDetector(alert_callback=_capturer(alertes2), seuil_echecs=100, fenetre_sec=60)
    ts2 = _ts()
    for i in range(100):
        det2.process_event({"type": "AUTH_FAILED", "ip_src": "192.168.1.2",
                            "user_cible": "root", "timestamp": ts2})
    affirmer("P2_PAS_ALERTE_100_echecs_exact", len(alertes2) == 0, f"alertes={len(alertes2)}")

    # test_isolation_compteurs_par_paire
    alertes3 = []
    det3 = BruteForceDetector(alert_callback=_capturer(alertes3), seuil_echecs=100, fenetre_sec=60)
    ts3 = _ts()
    for i in range(60):
        det3.process_event({"type": "AUTH_FAILED", "ip_src": "10.0.1.1",
                            "user_cible": "alice", "timestamp": ts3})
    for i in range(60):
        det3.process_event({"type": "AUTH_FAILED", "ip_src": "10.0.1.2",
                            "user_cible": "alice", "timestamp": ts3})
    affirmer("P2_isolation_par_paire", len(alertes3) == 0, "2x60 sur 2 IP diff -- pas d'alerte")


# ════════════════════════════════════════════════════════════════════════════
# P3 — Mouvement latéral (5 tests)
# ════════════════════════════════════════════════════════════════════════════

def tests_p3():
    print("\n-- P3 Mouvement lateral --")
    cache = MockG0Cache()

    # test_DECLENCHE_communication_non_autorisee
    alertes = []
    det = LateralMoveDetector(g0_cache=cache, alert_callback=_capturer(alertes), cooldown_sec=600)
    det.process_event({"type": "INTER_SERVICE_CALL", "premier_contact": True,
                       "service_src": "payment", "service_dst": "catalogue-db",
                       "timestamp": _ts()})
    affirmer("P3_DECLENCHE_non_autorisee", len(alertes) == 1)
    if alertes:
        affirmer("P3_DECLENCHE_type_correct",     alertes[0]["type"]     == "LATERAL_MOVE")
        affirmer("P3_DECLENCHE_severity_CRITICAL", alertes[0]["severity"] == "CRITICAL")

    # test_PAS_ALERTE_communication_autorisee
    alertes2 = []
    det2 = LateralMoveDetector(g0_cache=cache, alert_callback=_capturer(alertes2), cooldown_sec=600)
    det2.process_event({"type": "INTER_SERVICE_CALL", "premier_contact": True,
                        "service_src": "orders", "service_dst": "orders-db",
                        "timestamp": _ts()})
    affirmer("P3_PAS_ALERTE_autorisee", len(alertes2) == 0)

    # test_PAS_ALERTE_non_premier_contact
    alertes3 = []
    det3 = LateralMoveDetector(g0_cache=cache, alert_callback=_capturer(alertes3), cooldown_sec=600)
    det3.process_event({"type": "INTER_SERVICE_CALL", "premier_contact": False,
                        "service_src": "payment", "service_dst": "catalogue-db",
                        "timestamp": _ts()})
    affirmer("P3_PAS_ALERTE_non_premier_contact", len(alertes3) == 0)

    # test_cooldown_anti_duplication
    alertes4 = []
    det4 = LateralMoveDetector(g0_cache=cache, alert_callback=_capturer(alertes4), cooldown_sec=600)
    base = {"type": "INTER_SERVICE_CALL", "premier_contact": True,
            "service_src": "shipping", "service_dst": "user-db"}
    det4.process_event({**base, "timestamp": _ts()})
    det4.process_event({**base, "timestamp": _ts(1)})
    det4.process_event({**base, "timestamp": _ts(2)})
    affirmer("P3_cooldown_anti_duplication", len(alertes4) == 1, f"alertes={len(alertes4)}")

    # test_cooldown_expire_alerte_renvoyee
    alertes5 = []
    det5 = LateralMoveDetector(g0_cache=cache, alert_callback=_capturer(alertes5), cooldown_sec=1)
    base2 = {"type": "INTER_SERVICE_CALL", "premier_contact": True,
             "service_src": "rabbitmq", "service_dst": "user-db"}
    det5.process_event({**base2, "timestamp": _ts()})
    # Simuler expiration du cooldown via manipulation interne
    paire = ("rabbitmq", "user-db")
    det5._cooldowns[paire] = datetime.now(timezone.utc) - timedelta(seconds=2)
    det5.process_event({**base2, "timestamp": _ts(3)})
    affirmer("P3_cooldown_expire_alerte_renvoyee", len(alertes5) == 2, f"alertes={len(alertes5)}")


# ════════════════════════════════════════════════════════════════════════════
# P4 — Compromission de compte (3 tests)
# ════════════════════════════════════════════════════════════════════════════

def tests_p4():
    print("\n-- P4 Compromission de compte --")

    # test_DECLENCHE_succes_apres_5_echecs
    alertes = []
    det = CompromiseDetector(alert_callback=_capturer(alertes),
                             seuil_echecs_avant=5, fenetre_sec=120)
    ts = _ts()
    for i in range(6):
        det.process_event({"type": "AUTH_FAILED", "ip_src": "172.16.0.1",
                           "user_cible": "admin", "timestamp": ts})
    det.process_event({"type": "AUTH_SUCCESS", "ip_src": "172.16.0.1",
                       "user_cible": "admin", "timestamp": _ts(1)})
    affirmer("P4_DECLENCHE_succes_apres_5_echecs", len(alertes) == 1, f"alertes={len(alertes)}")
    if alertes:
        affirmer("P4_DECLENCHE_type_correct",     alertes[0]["type"]     == "COMPROMISE")
        affirmer("P4_DECLENCHE_severity_CRITICAL", alertes[0]["severity"] == "CRITICAL")

    # test_PAS_ALERTE_succes_sans_echecs
    alertes2 = []
    det2 = CompromiseDetector(alert_callback=_capturer(alertes2),
                              seuil_echecs_avant=5, fenetre_sec=120)
    det2.process_event({"type": "AUTH_SUCCESS", "ip_src": "172.16.0.2",
                        "user_cible": "bob", "timestamp": _ts()})
    affirmer("P4_PAS_ALERTE_succes_sans_echecs", len(alertes2) == 0)

    # test_PAS_ALERTE_4_echecs_insuffisant
    alertes3 = []
    det3 = CompromiseDetector(alert_callback=_capturer(alertes3),
                              seuil_echecs_avant=5, fenetre_sec=120)
    ts3 = _ts()
    for i in range(4):
        det3.process_event({"type": "AUTH_FAILED", "ip_src": "172.16.0.3",
                            "user_cible": "alice", "timestamp": ts3})
    det3.process_event({"type": "AUTH_SUCCESS", "ip_src": "172.16.0.3",
                        "user_cible": "alice", "timestamp": _ts(1)})
    affirmer("P4_PAS_ALERTE_4_echecs_insuffisant", len(alertes3) == 0, f"alertes={len(alertes3)}")


# ════════════════════════════════════════════════════════════════════════════
# P5 — Évasion de conteneur (5 tests)
# ════════════════════════════════════════════════════════════════════════════

def tests_p5():
    print("\n-- P5 Evasion de conteneur --")

    # test_DECLENCHE_execve_critical
    alertes = []
    det = ContainerEscapeDetector(alert_callback=_capturer(alertes), cooldown_sec=300)
    det.process_event({"type": "FALCO_ALERT", "severity": "CRITICAL",
                       "service": "payment", "message": "Syscall execve detected in container",
                       "rule": "Execve detected", "timestamp": _ts()})
    affirmer("P5_DECLENCHE_execve_critical", len(alertes) == 1)
    if alertes:
        affirmer("P5_DECLENCHE_type_correct", alertes[0]["type"] == "CONTAINER_ESCAPE")

    # test_DECLENCHE_docker_sock
    alertes2 = []
    det2 = ContainerEscapeDetector(alert_callback=_capturer(alertes2), cooldown_sec=300)
    det2.process_event({"type": "FALCO_ALERT", "severity": "ERROR",
                        "service": "orders", "message": "Access to docker.sock detected",
                        "rule": "Docker socket access", "timestamp": _ts()})
    affirmer("P5_DECLENCHE_docker_sock", len(alertes2) == 1)

    # test_PAS_ALERTE_severity_WARNING
    alertes3 = []
    det3 = ContainerEscapeDetector(alert_callback=_capturer(alertes3), cooldown_sec=300)
    det3.process_event({"type": "FALCO_ALERT", "severity": "WARNING",
                        "service": "cart", "message": "execve detected",
                        "rule": "Some rule", "timestamp": _ts()})
    affirmer("P5_PAS_ALERTE_severity_WARNING", len(alertes3) == 0)

    # test_PAS_ALERTE_sans_mot_cle_evasion
    alertes4 = []
    det4 = ContainerEscapeDetector(alert_callback=_capturer(alertes4), cooldown_sec=300)
    det4.process_event({"type": "FALCO_ALERT", "severity": "CRITICAL",
                        "service": "user", "message": "Random network connection alert",
                        "rule": "Generic rule", "timestamp": _ts()})
    affirmer("P5_PAS_ALERTE_sans_mot_cle", len(alertes4) == 0)

    # test_cooldown_par_service
    alertes5 = []
    det5 = ContainerEscapeDetector(alert_callback=_capturer(alertes5), cooldown_sec=300)
    base = {"type": "FALCO_ALERT", "severity": "CRITICAL",
            "service": "front-end", "message": "nsenter used in container",
            "rule": "Namespace escape"}
    det5.process_event({**base, "timestamp": _ts()})
    det5.process_event({**base, "timestamp": _ts(1)})
    det5.process_event({**base, "timestamp": _ts(2)})
    affirmer("P5_cooldown_par_service", len(alertes5) == 1, f"alertes={len(alertes5)}")


# ════════════════════════════════════════════════════════════════════════════
# P6 — Exfiltration de données (4 tests)
# ════════════════════════════════════════════════════════════════════════════

def tests_p6():
    print("\n-- P6 Exfiltration de donnees --")

    # test_DECLENCHE_pic_5x_baseline
    alertes = []
    det = ExfiltrationDetector(alert_callback=_capturer(alertes),
                               baseline_fenetre_sec=120, multiplicateur=5,
                               min_baseline_kb=100, cooldown_sec=300)
    ts = _ts()
    for i in range(5):
        det.process_event({"service": "user-db", "net_out_kb": 200, "timestamp": ts})
    det.process_event({"service": "user-db", "net_out_kb": 2000, "timestamp": _ts(1)})
    affirmer("P6_DECLENCHE_pic_5x", len(alertes) == 1, f"alertes={len(alertes)}")
    if alertes:
        affirmer("P6_DECLENCHE_ratio_ok", alertes[0]["ratio"] >= 5,
                 f"ratio={alertes[0]['ratio']}")

    # test_PAS_ALERTE_pic_modere
    alertes2 = []
    det2 = ExfiltrationDetector(alert_callback=_capturer(alertes2),
                                baseline_fenetre_sec=120, multiplicateur=5,
                                min_baseline_kb=100, cooldown_sec=300)
    ts2 = _ts()
    for i in range(5):
        det2.process_event({"service": "orders", "net_out_kb": 300, "timestamp": ts2})
    det2.process_event({"service": "orders", "net_out_kb": 400, "timestamp": _ts(1)})
    affirmer("P6_PAS_ALERTE_pic_modere", len(alertes2) == 0)

    # test_PAS_ALERTE_baseline_insuffisante
    alertes3 = []
    det3 = ExfiltrationDetector(alert_callback=_capturer(alertes3),
                                baseline_fenetre_sec=120, multiplicateur=5,
                                min_baseline_kb=100, cooldown_sec=300)
    ts3 = _ts()
    det3.process_event({"service": "cart", "net_out_kb": 200, "timestamp": ts3})
    det3.process_event({"service": "cart", "net_out_kb": 200, "timestamp": _ts(0.1)})
    det3.process_event({"service": "cart", "net_out_kb": 5000, "timestamp": _ts(0.2)})
    affirmer("P6_PAS_ALERTE_baseline_insuffisante", len(alertes3) == 0, f"alertes={len(alertes3)}")

    # test_CRITICAL_service_sensible
    alertes4 = []
    det4 = ExfiltrationDetector(alert_callback=_capturer(alertes4),
                                baseline_fenetre_sec=120, multiplicateur=5,
                                min_baseline_kb=100, cooldown_sec=300)
    ts4 = _ts()
    for i in range(5):
        det4.process_event({"service": "payment", "net_out_kb": 200, "timestamp": ts4})
    det4.process_event({"service": "payment", "net_out_kb": 2000, "timestamp": _ts(1)})
    affirmer("P6_CRITICAL_service_sensible",
             len(alertes4) == 1 and alertes4[0]["severity"] == "CRITICAL",
             f"sev={alertes4[0]['severity'] if alertes4 else 'N/A'}")


# ════════════════════════════════════════════════════════════════════════════
# P7 — Déni de service (4 tests)
# ════════════════════════════════════════════════════════════════════════════

def tests_p7():
    print("\n-- P7 Deni de service --")

    # test_DECLENCHE_cpu_ET_erreurs_simultanes
    alertes = []
    det = DoSDetector(alert_callback=_capturer(alertes),
                      seuil_cpu=90, seuil_erreurs=10,
                      duree_confirmation_sec=60, cooldown_sec=300)
    ts = _ts()
    for i in range(3):
        det.process_event({"service": "front-end", "cpu_pct": 95,
                           "erreurs_5xx": 15, "timestamp": ts})
    affirmer("P7_DECLENCHE_cpu_ET_erreurs", len(alertes) == 1, f"alertes={len(alertes)}")
    if alertes:
        affirmer("P7_DECLENCHE_type_correct",   alertes[0]["type"]     == "DOS_DETECTED")
        affirmer("P7_DECLENCHE_severity_HIGH",  alertes[0]["severity"] == "HIGH")

    # test_PAS_ALERTE_cpu_seul
    alertes2 = []
    det2 = DoSDetector(alert_callback=_capturer(alertes2),
                       seuil_cpu=90, seuil_erreurs=10,
                       duree_confirmation_sec=60, cooldown_sec=300)
    ts2 = _ts()
    for i in range(3):
        det2.process_event({"service": "orders", "cpu_pct": 95,
                            "erreurs_5xx": 5, "timestamp": ts2})
    affirmer("P7_PAS_ALERTE_cpu_seul", len(alertes2) == 0)

    # test_PAS_ALERTE_erreurs_seules
    alertes3 = []
    det3 = DoSDetector(alert_callback=_capturer(alertes3),
                       seuil_cpu=90, seuil_erreurs=10,
                       duree_confirmation_sec=60, cooldown_sec=300)
    ts3 = _ts()
    for i in range(3):
        det3.process_event({"service": "cart", "cpu_pct": 50,
                            "erreurs_5xx": 20, "timestamp": ts3})
    affirmer("P7_PAS_ALERTE_erreurs_seules", len(alertes3) == 0)

    # test_PAS_ALERTE_un_seul_point
    alertes4 = []
    det4 = DoSDetector(alert_callback=_capturer(alertes4),
                       seuil_cpu=90, seuil_erreurs=10,
                       duree_confirmation_sec=60, cooldown_sec=300)
    det4.process_event({"service": "payment", "cpu_pct": 99,
                        "erreurs_5xx": 50, "timestamp": _ts()})
    affirmer("P7_PAS_ALERTE_un_seul_point", len(alertes4) == 0)


# ════════════════════════════════════════════════════════════════════════════
# Runner principal
# ════════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("  MicroSecScore Phase 3 -- Tests unitaires CEP")
    print("=" * 60)

    tests_p1()
    tests_p2()
    tests_p3()
    tests_p4()
    tests_p5()
    tests_p6()
    tests_p7()

    print("\n" + "=" * 60)
    reussis = sum(1 for _, ok, _ in _resultats if ok)
    echoues = sum(1 for _, ok, _ in _resultats if not ok)
    total   = len(_resultats)
    print(f"  Resultat : {reussis} reussis | {echoues} echoues | {total} total")

    if echoues > 0:
        print("\nTests en echec :")
        for nom, ok, msg in _resultats:
            if not ok:
                print(f"  [X] {nom}" + (f" -- {msg}" if msg else ""))

    print("=" * 60)
    sys.exit(0 if echoues == 0 else 1)


if __name__ == "__main__":
    main()
