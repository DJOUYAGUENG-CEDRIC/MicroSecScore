"""
Règle P6 — Exfiltration de données — MITRE T1041 (Exfiltration Over C2 Channel)

Détecte un pic anormal de trafic réseau sortant : net_out_kb dépasse
P6_MULTIPLICATEUR fois la baseline glissante du service.

Source    : topic "metriques"
Filtre    : champ net_out_kb présent
Fenêtre   : 120 secondes glissantes par service
Condition : net_out_kb > baseline × 5 ET au moins 3 points baseline
Baseline  : moyenne des net_out_kb précédents (hors point courant)
Minimum   : 100 KB (évite les faux positifs sur trafic quasi nul)
Sévérité  : CRITICAL pour services sensibles, HIGH sinon

DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
"""

import json
import logging
import threading
from collections import deque
from datetime import datetime, timezone

import colorama
from colorama import Fore

colorama.init(autoreset=True)

logger = logging.getLogger(__name__)

# ── Constantes configurables ──────────────────────────────────────────────────
P6_BASELINE_FENETRE_SEC: int    = 120
P6_MULTIPLICATEUR: int          = 5
P6_MIN_BASELINE_KB: float       = 100.0
P6_COOLDOWN_SEC: int            = 300

_SERVICES_SENSIBLES = frozenset((
    "user-db", "orders-db", "catalogue-db",
    "cart-db", "payment", "user",
))


class ExfiltrationDetector:
    """
    Détecteur d'exfiltration de données (baseline glissante par service).

    Paramètres :
        alert_callback       : callable(dict) — défaut : print JSON
        baseline_fenetre_sec : durée de la fenêtre de baseline (secondes)
        multiplicateur       : seuil de déclenchement (multiple de baseline)
        min_baseline_kb      : baseline minimale (évite faux positifs)
        cooldown_sec         : anti-duplication par service
    """

    def __init__(
        self,
        alert_callback=None,
        baseline_fenetre_sec: int    = P6_BASELINE_FENETRE_SEC,
        multiplicateur: int          = P6_MULTIPLICATEUR,
        min_baseline_kb: float       = P6_MIN_BASELINE_KB,
        cooldown_sec: int            = P6_COOLDOWN_SEC,
    ):
        self._callback  = alert_callback or self._default_callback
        self._fenetre   = baseline_fenetre_sec
        self._multi     = multiplicateur
        self._min_kb    = min_baseline_kb
        self._cooldown  = cooldown_sec
        self._lock      = threading.RLock()
        # {service: deque[(datetime_utc, net_out_kb)]}
        self._historiques: dict[str, deque] = {}
        # {service: datetime UTC de la dernière alerte}
        self._cooldowns: dict[str, datetime] = {}

    # ── Traitement d'un événement ─────────────────────────────────────────────

    def process_event(self, event: dict) -> dict | None:
        net_out = event.get("net_out_kb")
        if net_out is None:
            return None

        service = event.get("service", "")
        if not service:
            return None

        now = self._parse_ts(event.get("timestamp"))

        with self._lock:
            if service not in self._historiques:
                self._historiques[service] = deque()

            historique = self._historiques[service]

            # Nettoyer les entrées expirées
            seuil_ts = now.timestamp() - self._fenetre
            while historique and historique[0][0].timestamp() < seuil_ts:
                historique.popleft()

            # Ajouter le point courant
            historique.append((now, float(net_out)))

            # Baseline = moyenne des points PRÉCÉDENTS (hors point courant)
            points_precedents = list(historique)[:-1]

            if len(points_precedents) < 3:
                return None

            baseline = sum(v for _, v in points_precedents) / len(points_precedents)

            if baseline < self._min_kb:
                return None

            ratio = float(net_out) / baseline

            if ratio <= self._multi:
                return None

            # Cooldown par service
            derniere = self._cooldowns.get(service)
            if derniere is not None:
                delta = (now - derniere).total_seconds()
                if delta < self._cooldown:
                    logger.debug(
                        "P6 cooldown actif pour '%s' — %.0fs restants",
                        service, self._cooldown - delta,
                    )
                    return None

            self._cooldowns[service] = now

        severity = "CRITICAL" if service in _SERVICES_SENSIBLES else "HIGH"

        alerte = {
            "type":        "EXFILTRATION",
            "service":     service,
            "net_out_kb":  round(float(net_out), 2),
            "baseline_kb": round(baseline, 2),
            "ratio":       round(ratio, 2),
            "severity":    severity,
            "timestamp":   now.isoformat(),
            "mitre":       "T1041",
            "detail": (
                f"Pic de trafic sortant sur '{service}' : "
                f"{net_out:.1f} KB (×{ratio:.1f} la baseline de {baseline:.1f} KB)"
            ),
        }
        self._log_alert(alerte)
        self._callback(alerte)
        return alerte

    # ── Interne ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_ts(raw: str | None) -> datetime:
        if raw:
            try:
                from dateutil import parser as dp
                return dp.parse(raw).astimezone(timezone.utc)
            except Exception:
                pass
        return datetime.now(timezone.utc)

    @staticmethod
    def _default_callback(alerte: dict) -> None:
        print(json.dumps(alerte, ensure_ascii=False))

    @staticmethod
    def _log_alert(a: dict) -> None:
        if a["severity"] == "CRITICAL":
            sep = Fore.RED + "═" * 60
            print(sep)
            print(Fore.RED + "🚨  ALERTE CRITIQUE — EXFILTRATION DE DONNÉES")
            print(Fore.RED + f"   Technique  : MITRE {a['mitre']}")
            print(Fore.RED + f"   Service    : {a['service']}")
            print(Fore.RED + f"   Net out    : {a['net_out_kb']} KB (×{a['ratio']} baseline)")
            print(Fore.RED + f"   Horodatage : {a['timestamp']}")
            print(sep)
        else:
            print(Fore.LIGHTYELLOW_EX + "⚠  ALERTE HIGH — EXFILTRATION DE DONNÉES")
            print(Fore.LIGHTYELLOW_EX + f"   Technique  : MITRE {a['mitre']}")
            print(Fore.LIGHTYELLOW_EX + f"   Service    : {a['service']}")
            print(Fore.LIGHTYELLOW_EX + f"   Net out    : {a['net_out_kb']} KB (×{a['ratio']} baseline)")
            print(Fore.LIGHTYELLOW_EX + f"   Horodatage : {a['timestamp']}")
