"""
Règle P3 — Mouvement latéral — MITRE T1550 (Application Access Token)

Détecte une communication inter-service non autorisée : un service contacte
un autre service dont la paire (src, dst) est ABSENTE du graphe G0.

Source    : topic "logs"
Filtre    : type == "INTER_SERVICE_CALL" ET premier_contact == True
Condition : paire (service_src, service_dst) absente du cache G0
Cooldown  : P3_COOLDOWN_SEC secondes par paire (anti-duplication)
Sévérité  : CRITICAL

DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
"""

import json
import logging
import threading
from datetime import datetime, timezone

import colorama
from colorama import Fore

colorama.init(autoreset=True)

logger = logging.getLogger(__name__)

# ── Constantes configurables ──────────────────────────────────────────────────
P3_COOLDOWN_SEC: int = 600   # 10 minutes d'anti-duplication par paire


class LateralMoveDetector:
    """
    Détecteur de mouvement latéral inter-service.

    Paramètres :
        g0_cache       : instance de G0Cache (doit implémenter is_authorized)
        alert_callback : callable(dict) — défaut : print JSON
        cooldown_sec   : secondes d'anti-duplication par paire (src, dst)
    """

    def __init__(
        self,
        g0_cache,
        alert_callback=None,
        cooldown_sec: int = P3_COOLDOWN_SEC,
    ):
        self._cache       = g0_cache
        self._callback    = alert_callback or self._default_callback
        self._cooldown    = cooldown_sec
        self._lock        = threading.RLock()
        # {(src, dst): datetime UTC de la dernière alerte}
        self._cooldowns: dict[tuple, datetime] = {}

    # ── Traitement d'un événement ─────────────────────────────────────────────

    def process_event(self, event: dict) -> dict | None:
        """
        Analyse un événement et retourne une alerte si P3 se déclenche.

        Retourne None si l'événement ne correspond pas ou si cooldown actif.
        """
        if event.get("type") != "INTER_SERVICE_CALL":
            return None
        if not event.get("premier_contact", False):
            return None

        src = event.get("service_src", "")
        dst = event.get("service_dst", "")
        if not src or not dst:
            return None

        # Communication autorisée dans G0 → pas d'alerte
        if self._cache.is_authorized(src, dst):
            return None

        now   = self._parse_ts(event.get("timestamp"))
        paire = (src, dst)

        with self._lock:
            derniere = self._cooldowns.get(paire)
            if derniere is not None:
                delta = (now - derniere).total_seconds()
                if delta < self._cooldown:
                    logger.debug(
                        "P3 cooldown actif pour (%s → %s) — %.0fs restants",
                        src, dst, self._cooldown - delta,
                    )
                    return None
            self._cooldowns[paire] = now

        alerte = {
            "type":      "LATERAL_MOVE",
            "src":       src,
            "dst":       dst,
            "severity":  "CRITICAL",
            "timestamp": now.isoformat(),
            "mitre":     "T1550",
            "detail": (
                f"Communication non autorisée : {src} → {dst} "
                f"absente du graphe G0 DEPENDS_ON"
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
        sep = Fore.RED + "═" * 60
        print(sep)
        print(Fore.RED + "🚨  ALERTE CRITIQUE — MOUVEMENT LATÉRAL DÉTECTÉ")
        print(Fore.RED + f"   Technique  : MITRE {a['mitre']} (Application Access Token)")
        print(Fore.RED + f"   Source     : {a['src']}")
        print(Fore.RED + f"   Destination: {a['dst']}")
        print(Fore.RED + f"   Détail     : {a['detail']}")
        print(Fore.RED + f"   Horodatage : {a['timestamp']}")
        print(sep)


# Alias pour compatibilité
LateralMovementDetector = LateralMoveDetector
