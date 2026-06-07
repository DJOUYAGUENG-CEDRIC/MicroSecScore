"""
Règle P2 — Force brute — MITRE T1110 (Brute Force)

Détecte une attaque par dictionnaire : plus de P2_SEUIL_ECHECS tentatives
d'authentification échouées en P2_FENETRE_SEC secondes pour une même
paire (ip_src, user_cible).

Source    : topic "logs"
Filtre    : type == "AUTH_FAILED"
Fenêtre   : 30 secondes glissantes par (ip_src, user_cible)
Condition : COUNT(*) > 100
Sévérité  : HIGH

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
P2_SEUIL_ECHECS: int = 100
P2_FENETRE_SEC: int  = 30


class BruteForceDetector:
    """
    Détecteur de force brute (fenêtre glissante par paire ip_src/user_cible).

    Paramètres :
        alert_callback : callable(dict) — défaut : print JSON
        seuil_echecs   : nb d'échecs déclenchant l'alerte (strictement >)
        fenetre_sec    : durée de la fenêtre glissante en secondes
    """

    def __init__(
        self,
        alert_callback=None,
        seuil_echecs: int = P2_SEUIL_ECHECS,
        fenetre_sec: int  = P2_FENETRE_SEC,
    ):
        self._callback  = alert_callback or self._default_callback
        self._seuil     = seuil_echecs
        self._fenetre   = fenetre_sec
        self._lock      = threading.RLock()
        # {(ip_src, user_cible): deque[datetime_utc]}
        self._fenetres: dict[tuple, deque] = {}

    # ── Traitement d'un événement ─────────────────────────────────────────────

    def process_event(self, event: dict) -> dict | None:
        if event.get("type") != "AUTH_FAILED":
            return None

        ip_src     = event.get("ip_src", "")
        user_cible = event.get("user_cible", "")
        if not ip_src:
            return None

        now   = self._parse_ts(event.get("timestamp"))
        paire = (ip_src, user_cible)

        with self._lock:
            if paire not in self._fenetres:
                self._fenetres[paire] = deque()

            fenetre = self._fenetres[paire]
            fenetre.append(now)

            # Nettoyer les entrées expirées
            seuil_ts = now.timestamp() - self._fenetre
            while fenetre and fenetre[0].timestamp() < seuil_ts:
                fenetre.popleft()

            nb_echecs = len(fenetre)
            if nb_echecs <= self._seuil:
                return None

            # Alerte déclenchée — vider le compteur de la paire
            fenetre.clear()

        alerte = {
            "type":      "BRUTE_FORCE",
            "ip":        ip_src,
            "user":      user_cible,
            "nb_echecs": nb_echecs,
            "severity":  "HIGH",
            "timestamp": now.isoformat(),
            "mitre":     "T1110",
            "detail": (
                f"Force brute depuis {ip_src} sur '{user_cible}' : "
                f"{nb_echecs} échecs en {self._fenetre}s"
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
        print(Fore.LIGHTYELLOW_EX + "⚠  ALERTE HIGH — FORCE BRUTE")
        print(Fore.LIGHTYELLOW_EX + f"   Technique  : MITRE {a['mitre']} (Brute Force)")
        print(Fore.LIGHTYELLOW_EX + f"   IP source  : {a['ip']}")
        print(Fore.LIGHTYELLOW_EX + f"   Cible      : {a['user']}")
        print(Fore.LIGHTYELLOW_EX + f"   Échecs     : {a['nb_echecs']}")
        print(Fore.LIGHTYELLOW_EX + f"   Horodatage : {a['timestamp']}")
