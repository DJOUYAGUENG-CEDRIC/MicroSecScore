"""
Règle P4 — Compromission de compte — MITRE T1078 (Valid Accounts)

Détecte un compte compromis : un AUTH_SUCCESS survient après au moins
P4_SEUIL_ECHECS_AVANT AUTH_FAILED depuis la même ip_src dans une
fenêtre glissante de P4_FENETRE_SEC secondes.

Source    : topic "logs"
Filtre    : type IN ("AUTH_FAILED", "AUTH_SUCCESS")
Fenêtre   : 120 secondes glissantes par ip_src
Condition : AUTH_SUCCESS reçu ET nb AUTH_FAILED dans fenêtre >= seuil
Sévérité  : CRITICAL

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
P4_SEUIL_ECHECS_AVANT: int = 5
P4_FENETRE_SEC: int        = 120


class CompromiseDetector:
    """
    Détecteur de compromission de compte.

    Paramètres :
        alert_callback      : callable(dict) — défaut : print JSON
        seuil_echecs_avant  : nb minimum d'AUTH_FAILED avant AUTH_SUCCESS
        fenetre_sec         : durée de la fenêtre glissante en secondes
    """

    def __init__(
        self,
        alert_callback=None,
        seuil_echecs_avant: int = P4_SEUIL_ECHECS_AVANT,
        fenetre_sec: int        = P4_FENETRE_SEC,
    ):
        self._callback = alert_callback or self._default_callback
        self._seuil    = seuil_echecs_avant
        self._fenetre  = fenetre_sec
        self._lock     = threading.RLock()
        # {ip_src: deque[(datetime_utc, user_cible, ev_type)]}
        self._fenetres: dict[str, deque] = {}

    # ── Traitement d'un événement ─────────────────────────────────────────────

    def process_event(self, event: dict) -> dict | None:
        ev_type = event.get("type", "")
        if ev_type not in ("AUTH_FAILED", "AUTH_SUCCESS"):
            return None

        ip_src     = event.get("ip_src", "")
        user_cible = event.get("user_cible", "")
        if not ip_src:
            return None

        now = self._parse_ts(event.get("timestamp"))

        with self._lock:
            if ip_src not in self._fenetres:
                self._fenetres[ip_src] = deque()

            fenetre = self._fenetres[ip_src]
            fenetre.append((now, user_cible, ev_type))

            # Nettoyer les entrées expirées
            seuil_ts = now.timestamp() - self._fenetre
            while fenetre and fenetre[0][0].timestamp() < seuil_ts:
                fenetre.popleft()

            # P4 se déclenche uniquement sur AUTH_SUCCESS
            if ev_type != "AUTH_SUCCESS":
                return None

            # Compter les AUTH_FAILED antérieurs dans la fenêtre
            echecs = [(ts, u) for ts, u, t in fenetre if t == "AUTH_FAILED"]
            nb_echecs = len(echecs)

            if nb_echecs < self._seuil:
                return None

            comptes_tentes = list({u for _, u in echecs if u})

        alerte = {
            "type":            "COMPROMISE",
            "ip":              ip_src,
            "user_compromis":  user_cible,
            "comptes_tentes":  comptes_tentes,
            "nb_echecs_avant": nb_echecs,
            "severity":        "CRITICAL",
            "timestamp":       now.isoformat(),
            "mitre":           "T1078",
            "detail": (
                f"Compte compromis depuis {ip_src} : "
                f"succès pour '{user_cible}' après {nb_echecs} échecs en {self._fenetre}s"
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
        print(Fore.RED + "🚨  ALERTE CRITIQUE — COMPROMISSION DE COMPTE")
        print(Fore.RED + f"   Technique    : MITRE {a['mitre']} (Valid Accounts)")
        print(Fore.RED + f"   IP source    : {a['ip']}")
        print(Fore.RED + f"   Compte       : {a['user_compromis']}")
        print(Fore.RED + f"   Échecs avant : {a['nb_echecs_avant']}")
        print(Fore.RED + f"   Horodatage   : {a['timestamp']}")
        print(sep)
