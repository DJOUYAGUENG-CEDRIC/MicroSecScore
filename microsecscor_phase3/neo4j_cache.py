"""
neo4j_cache.py — Cache mémoire des arêtes DEPENDS_ON du graphe G0.

Pourquoi un cache ?
Neo4j prend ~10 ms par requête. À 1 000 événements/seconde, interroger
Neo4j à chaque INTER_SERVICE_CALL génère 10 secondes de latence par
seconde de traitement. Solution : charger toutes les arêtes en mémoire
au démarrage, rafraîchir en arrière-plan toutes les 60 secondes.

DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang
"""

import logging
import threading
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("cep.neo4j_cache")


class G0Cache:
    """
    Cache thread-safe des arêtes DEPENDS_ON du graphe G0 (Neo4j).

    Usage :
        cache = G0Cache("bolt://localhost:7687", "neo4j", "password")
        cache.start()
        cache.is_authorized("orders", "orders-db")  # → True
        cache.stop()
    """

    def __init__(self, uri: str, user: str, password: str, refresh_sec: int = 60):
        self._uri          = uri
        self._user         = user
        self._password     = password
        self._refresh_sec  = refresh_sec

        self._authorized: set[tuple[str, str]] = set()
        self._lock         = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self._stop         = threading.Event()
        self._last_refresh: Optional[datetime] = None

    @property
    def last_refresh(self) -> Optional[datetime]:
        with self._lock:
            return self._last_refresh

    def start(self) -> None:
        """Charge le cache initial puis lance le thread de refresh (daemon)."""
        self._charger()
        self._thread = threading.Thread(
            target=self._refresh_loop,
            daemon=True,
            name="g0-cache-refresh",
        )
        self._thread.start()
        logger.info("G0Cache démarré (refresh toutes les %ds).", self._refresh_sec)

    def stop(self) -> None:
        """Arrête le thread de refresh."""
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("G0Cache arrêté.")

    def is_authorized(self, src: str, dst: str) -> bool:
        """Retourne True si l'arête src → dst existe dans DEPENDS_ON."""
        with self._lock:
            return (src, dst) in self._authorized

    def snapshot(self) -> frozenset:
        """Copie immuable du cache courant (utile pour les tests)."""
        with self._lock:
            return frozenset(self._authorized)

    def _charger(self) -> None:
        """Charge les arêtes DEPENDS_ON depuis Neo4j. Ne lève jamais d'exception."""
        try:
            from neo4j import GraphDatabase
            driver = GraphDatabase.driver(self._uri, auth=(self._user, self._password))
            with driver.session() as session:
                result = session.run(
                    "MATCH (a:Service)-[:DEPENDS_ON]->(b:Service) "
                    "RETURN a.nom AS src, b.nom AS dst"
                )
                nouvelles = {
                    (r["src"], r["dst"])
                    for r in result
                    if r["src"] and r["dst"]
                }
            driver.close()
            with self._lock:
                self._authorized   = nouvelles
                self._last_refresh = datetime.now(timezone.utc)
            logger.info("G0Cache : %d arêtes DEPENDS_ON chargées.", len(nouvelles))
        except Exception as exc:
            logger.warning(
                "G0Cache : échec chargement Neo4j (%s) — ancien cache conservé.", exc
            )

    def _refresh_loop(self) -> None:
        while not self._stop.wait(timeout=self._refresh_sec):
            self._charger()


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    class _MockCache(G0Cache):
        def start(self) -> None:
            with self._lock:
                self._authorized = {
                    ("orders", "orders-db"), ("orders", "payment"),
                    ("front-end", "catalogue"), ("front-end", "orders"),
                    ("user", "user-db"), ("cart", "cart-db"),
                    ("catalogue", "catalogue-db"),
                }
                self._last_refresh = datetime.now(timezone.utc)

        def stop(self) -> None:
            pass

    cache = _MockCache("bolt://localhost:7687", "neo4j", "test")
    cache.start()
    assert cache.is_authorized("orders", "orders-db"), "ECHEC"
    assert not cache.is_authorized("payment", "catalogue-db"), "ECHEC"
    print("OK is_authorized('orders','orders-db')      -> True")
    print("OK is_authorized('payment','catalogue-db') -> False")
    sys.exit(0)
