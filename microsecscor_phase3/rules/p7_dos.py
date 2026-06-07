"""
Règle P7 — Déni de service — MITRE T1499 (Endpoint Denial of Service)

Détecte un DoS confirmé : TOUS les points de la fenêtre satisfont
SIMULTANÉMENT cpu_pct >= 90 ET erreurs_5xx >= 10, avec au moins 2 points.

Source    : topic "metriques"
Filtre    : champs cpu_pct ET erreurs_5xx présents
Fenêtre   : 30 secondes glissantes par service
Condition : TOUS les points satisfont les deux seuils EN MÊME TEMPS
            ET au moins 2 points dans la fenêtre
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
P7_SEUIL_CPU_PCT: float          = 90.0
P7_SEUIL_ERREURS_5XX: int        = 10
P7_DUREE_CONFIRMATION_SEC: int   = 30
P7_COOLDOWN_SEC: int             = 300


class DoSDetector:
    """
    Détecteur de déni de service (double condition simultanée sur fenêtre).

    Paramètres :
        alert_callback          : callable(dict) — défaut : print JSON
        seuil_cpu               : seuil CPU en % (>= déclenche la condition)
        seuil_erreurs           : seuil d'erreurs 5xx (>= déclenche la condition)
        duree_confirmation_sec  : durée de la fenêtre de confirmation
        cooldown_sec            : anti-duplication par service
    """

    def __init__(
        self,
        alert_callback=None,
        seuil_cpu: float             = P7_SEUIL_CPU_PCT,
        seuil_erreurs: int           = P7_SEUIL_ERREURS_5XX,
        duree_confirmation_sec: int  = P7_DUREE_CONFIRMATION_SEC,
        cooldown_sec: int            = P7_COOLDOWN_SEC,
    ):
        self._callback      = alert_callback or self._default_callback
        self._seuil_cpu     = seuil_cpu
        self._seuil_err     = seuil_erreurs
        self._confirmation  = duree_confirmation_sec
        self._cooldown      = cooldown_sec
        self._lock          = threading.RLock()
        # {service: deque[(datetime_utc, cpu_pct, erreurs_5xx)]}
        self._fenetres: dict[str, deque] = {}
        # {service: datetime UTC de la dernière alerte}
        self._cooldowns: dict[str, datetime] = {}

    # ── Traitement d'un événement ─────────────────────────────────────────────

    def process_event(self, event: dict) -> dict | None:
        cpu     = event.get("cpu_pct")
        erreurs = event.get("erreurs_5xx")
        if cpu is None or erreurs is None:
            return None

        service = event.get("service", "")
        if not service:
            return None

        now = self._parse_ts(event.get("timestamp"))

        with self._lock:
            if service not in self._fenetres:
                self._fenetres[service] = deque()

            fenetre = self._fenetres[service]
            fenetre.append((now, float(cpu), int(erreurs)))

            # Nettoyer les entrées expirées
            seuil_ts = now.timestamp() - self._confirmation
            while fenetre and fenetre[0][0].timestamp() < seuil_ts:
                fenetre.popleft()

            if len(fenetre) < 2:
                return None

            # TOUS les points doivent satisfaire les deux conditions simultanément
            if not all(
                c >= self._seuil_cpu and e >= self._seuil_err
                for _, c, e in fenetre
            ):
                return None

            # Cooldown par service
            derniere = self._cooldowns.get(service)
            if derniere is not None:
                delta = (now - derniere).total_seconds()
                if delta < self._cooldown:
                    logger.debug(
                        "P7 cooldown actif pour '%s' — %.0fs restants",
                        service, self._cooldown - delta,
                    )
                    return None

            self._cooldowns[service] = now

            cpu_moy     = sum(c for _, c, _ in fenetre) / len(fenetre)
            erreurs_moy = sum(e for _, _, e in fenetre) / len(fenetre)
            nb_points   = len(fenetre)

            # Vider la fenêtre après alerte
            fenetre.clear()

        alerte = {
            "type":        "DOS_DETECTED",
            "service":     service,
            "cpu_moy_pct": round(cpu_moy, 1),
            "erreurs_moy": round(erreurs_moy, 1),
            "nb_points":   nb_points,
            "severity":    "HIGH",
            "timestamp":   now.isoformat(),
            "mitre":       "T1499",
            "detail": (
                f"DoS détecté sur '{service}' : "
                f"CPU moyen {cpu_moy:.1f}% et {erreurs_moy:.1f} erreurs/s "
                f"sur {nb_points} points ({self._confirmation}s)"
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
        print(Fore.LIGHTYELLOW_EX + "⚠  ALERTE HIGH — DÉNI DE SERVICE")
        print(Fore.LIGHTYELLOW_EX + f"   Technique  : MITRE {a['mitre']} (Endpoint DoS)")
        print(Fore.LIGHTYELLOW_EX + f"   Service    : {a['service']}")
        print(Fore.LIGHTYELLOW_EX + f"   CPU moyen  : {a['cpu_moy_pct']}%")
        print(Fore.LIGHTYELLOW_EX + f"   Erreurs/s  : {a['erreurs_moy']}")
        print(Fore.LIGHTYELLOW_EX + f"   Points     : {a['nb_points']}")
        print(Fore.LIGHTYELLOW_EX + f"   Horodatage : {a['timestamp']}")
