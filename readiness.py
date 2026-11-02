"""Bounded, read-only database readiness independent of account housekeeping."""
from __future__ import annotations

import threading

import psycopg


class ReadinessProbe:
    """Allow at most one connection attempt and bound how long callers wait.

    libpq's connect timeout applies separately to possible addresses, and a
    statement timeout cannot bound a broken network read. A daemon worker gives
    the HTTP request its own deadline on Windows and Linux. Until that worker
    closes its connection, additional probes fail closed rather than creating
    more threads or connections. No successful result is cached.
    """

    def __init__(self, *, timeout_seconds: float = 3.0):
        self.timeout_seconds = timeout_seconds
        self._in_flight = threading.Lock()

    def check(self, database_url: str) -> bool:
        if not database_url or not self._in_flight.acquire(blocking=False):
            return False

        finished = threading.Event()
        result = [False]

        def run() -> None:
            ready = False
            try:
                connection = psycopg.connect(
                    database_url, autocommit=True, connect_timeout=2,
                    options="-c default_transaction_read_only=on -c statement_timeout=1000",
                    application_name="geomapper-readiness",
                )
                try:
                    ready = connection.execute("SELECT 1").fetchone() == (1,)
                finally:
                    connection.close()
            except Exception:
                # This public check must never expose credentials, host names,
                # driver errors or account state through responses or logs.
                ready = False
            finally:
                result[0] = ready
                self._in_flight.release()
                finished.set()

        try:
            threading.Thread(target=run, name="geomapper-readiness", daemon=True).start()
        except Exception:
            self._in_flight.release()
            return False

        return finished.wait(self.timeout_seconds) and result[0]


_probe = ReadinessProbe()


def database_is_ready(database_url: str) -> bool:
    """Check only connectivity and a fixed SELECT, without account side effects."""
    return _probe.check(database_url)
