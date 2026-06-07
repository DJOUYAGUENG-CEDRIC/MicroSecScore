"""
Règle P1 — Scan de reconnaissance — MITRE T1046 (Network Service Discovery)

Détecte un balayage de ports : une même IP source tente plus de
P1_SEUIL_PORTS ports distincts en P1_FENETRE_SEC secondes.

Source    : topic "logs"
Filtre    : type == "CONNECTION" ET result IN ("CLOSED","REFUSED","FILTERED")
Fenêtre   : 2 secondes glissantes par ip_src
Condition : COUNT(DISTINCT port_dst) > 50
Sévérité  : MEDIUM

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
P1_SEUIL_PORTS: int = 50
P1_FENETRE_SEC: int = 2

_RESULTS_SCAN = frozenset(("CLOSED", "REFUSED", "FILTERED"))


class ScanDetector:
    """
    Détecteur de scan de ports (fenêtre glissante par ip_src).

    Paramètres :
        alert_callback : callable(dict) — défaut : print JSON
        seuil_ports    : nb de ports distincts déclenchant l'alerte
        fenetre_sec    : durée de la fenêtre glissante en secondes
    """

    def __init__(
        self,
        alert_callback=None,
        seuil_ports: int = P1_SEUIL_PORTS,
        fenetre_sec: int = P1_FENETRE_SEC,
    ):
        self._callback    = alert_callback or self._default_callback
        self._seuil       = seuil_ports
        self._fenetre     = fenetre_sec
        self._lock        = threading.RLock()
        # {ip_src: deque[(datetime_utc, port_dst)]}
        self._fenetres: dict[str, deque] = {}

    # ── Traitement d'un événement ─────────────────────────────────────────────

    def process_event(self, event: dict) -> dict | None:
        if event.get("type") != "CONNECTION":
            return None
        if event.get("result") not in _RESULTS_SCAN:
            return None

        ip_src   = event.get("ip_src", "")
        port_dst = event.get("port_dst")
        if not ip_src or port_dst is None:
            return None

        now = self._parse_ts(event.get("timestamp"))

        with self._lock:
            if ip_src not in self._fenetres:
                self._fenetres[ip_src] = deque()

            fenetre   = self._fenetres[ip_src]
            fenetre.append((now, port_dst))

            # Nettoyer les entrées expirées
            seuil_ts = now.timestamp() - self._fenetre
            while fenetre and fenetre[0][0].timestamp() < seuil_ts:
                fenetre.popleft()

            ports_distincts = {p for _, p in fenetre}
            nb_ports        = len(ports_distincts)

            if nb_ports <= self._seuil:
                return None

            # Alerte déclenchée — vider la fenêtre pour éviter les rafales
            fenetre.clear()

        alerte = {
            "type":      "SCAN_RECONN",
            "ip":        ip_src,
            "nb_ports":  nb_ports,
            "severity":  "MEDIUM",
            "timestamp": now.isoformat(),
            "mitre":     "T1046",
            "detail": (
                f"Scan de ports détecté depuis {ip_src} : "
                f"{nb_ports} ports distincts en {self._fenetre}s"
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
        print(Fore.YELLOW + f"⚠  ALERTE MEDIUM — SCAN DE RECONNAISSANCE")
        print(Fore.YELLOW + f"   Technique  : MITRE {a['mitre']} (Network Service Discovery)")
        print(Fore.YELLOW + f"   IP source  : {a['ip']}")
        print(Fore.YELLOW + f"   Ports      : {a['nb_ports']} ports distincts")
        print(Fore.YELLOW + f"   Horodatage : {a['timestamp']}")
