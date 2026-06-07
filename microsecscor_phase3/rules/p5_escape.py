"""
Règle P5 — Évasion de conteneur — MITRE T1611 (Escape to Host)

Détecte une tentative d'évasion via une alerte Falco CRITICAL ou ERROR
contenant des mots-clés liés aux techniques d'évasion connues.

Source    : topic "alertes-securite"
Filtre    : type == "FALCO_ALERT" ET severity IN ("CRITICAL","ERROR")
Condition : "message" OU "rule" contient un mot-clé d'évasion
Cooldown  : P5_COOLDOWN_SEC secondes par service (anti-duplication)
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
P5_COOLDOWN_SEC: int = 300   # 5 minutes par service

_SEVERITES_ACTIVES = frozenset(("CRITICAL", "ERROR"))

_MOTS_CLES_EVASION = (
    "execve",
    "docker.sock",
    "/proc/host",
    "mount namespace",
    "privileged",
    "nsenter",
    "escape",
    "terminal shell in container",
    "launch privileged container",
)


class ContainerEscapeDetector:
    """
    Détecteur d'évasion de conteneur (alertes Falco).

    Paramètres :
        alert_callback : callable(dict) — défaut : print JSON
        cooldown_sec   : secondes d'anti-duplication par service
    """

    def __init__(
        self,
        alert_callback=None,
        cooldown_sec: int = P5_COOLDOWN_SEC,
    ):
        self._callback    = alert_callback or self._default_callback
        self._cooldown    = cooldown_sec
        self._lock        = threading.RLock()
        # {service: datetime UTC de la dernière alerte}
        self._cooldowns: dict[str, datetime] = {}

    # ── Traitement d'un événement ─────────────────────────────────────────────

    def process_event(self, event: dict) -> dict | None:
        if event.get("type") != "FALCO_ALERT":
            return None
        if event.get("severity", "").upper() not in _SEVERITES_ACTIVES:
            return None

        service = event.get("service", "")
        message = (event.get("message") or "").lower()
        rule    = (event.get("rule")    or "").lower()
        texte   = message + " " + rule

        mot_cle = None
        for mot in _MOTS_CLES_EVASION:
            if mot.lower() in texte:
                mot_cle = mot
                break

        if mot_cle is None:
            return None

        now = self._parse_ts(event.get("timestamp"))

        with self._lock:
            derniere = self._cooldowns.get(service)
            if derniere is not None:
                delta = (now - derniere).total_seconds()
                if delta < self._cooldown:
                    logger.debug(
                        "P5 cooldown actif pour '%s' — %.0fs restants",
                        service, self._cooldown - delta,
                    )
                    return None
            self._cooldowns[service] = now

        alerte = {
            "type":       "CONTAINER_ESCAPE",
            "service":    service,
            "severity":   "CRITICAL",
            "falco_rule": event.get("rule", ""),
            "keyword":    mot_cle,
            "timestamp":  now.isoformat(),
            "mitre":      "T1611",
            "detail": (
                f"Évasion de conteneur sur '{service}' : "
                f"mot-clé '{mot_cle}' dans la règle Falco '{event.get('rule', '')}'"
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
        print(Fore.RED + "🚨  ALERTE CRITIQUE — ÉVASION DE CONTENEUR")
        print(Fore.RED + f"   Technique  : MITRE {a['mitre']} (Escape to Host)")
        print(Fore.RED + f"   Service    : {a['service']}")
        print(Fore.RED + f"   Règle Falco: {a['falco_rule']}")
        print(Fore.RED + f"   Mot-clé    : {a['keyword']}")
        print(Fore.RED + f"   Horodatage : {a['timestamp']}")
        print(sep)
