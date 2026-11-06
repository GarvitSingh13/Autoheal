"""SQLite read model for the API/dashboard.

The store is a projection of the bus: the API consumes ``alarms``, ``incidents`` and
``remediations`` from the beginning of the topics and upserts snapshots (ignoring
stale versions), so it can be deleted and rebuilt from Kafka at any time.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from autoheal.models import Alarm, Incident, Remediation

SCHEMA = """
CREATE TABLE IF NOT EXISTS alarms (
    fingerprint TEXT PRIMARY KEY,
    device TEXT, type TEXT, resource TEXT, severity TEXT,
    active INTEGER, first_seen REAL, last_seen REAL, data TEXT
);
CREATE TABLE IF NOT EXISTS alarm_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, alarm_id TEXT UNIQUE, ts REAL, fingerprint TEXT, severity TEXT, data TEXT
);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY, status TEXT, device TEXT, created_at REAL, updated_at REAL, version INTEGER, data TEXT
);
CREATE TABLE IF NOT EXISTS remediations (
    id TEXT PRIMARY KEY, incident_id TEXT, status TEXT, updated_at REAL, version INTEGER, data TEXT
);
CREATE INDEX IF NOT EXISTS idx_rem_incident ON remediations(incident_id);
CREATE INDEX IF NOT EXISTS idx_inc_updated ON incidents(updated_at);
"""

ALARM_LOG_MAX = 5000


class Store:
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        if path != ":memory:":
            self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self.lock = threading.Lock()

    # ------------------------------------------------------------------ writes
    def put_alarm(self, alarm: Alarm) -> bool:
        data = alarm.model_dump_json()
        with self.lock, self.db:
            if alarm.attributes.get("resync") and not alarm.is_clear:
                # Periodic re-assertion of an alarm that is still active: refresh it, but it
                # is not a new occurrence, so it stays out of the alarm log and the counts.
                cur = self.db.execute("UPDATE alarms SET last_seen=? WHERE fingerprint=? AND active=1",
                                      (alarm.timestamp, alarm.fingerprint))
                if cur.rowcount:
                    return False
            cur = self.db.execute(
                "INSERT OR IGNORE INTO alarm_log(alarm_id, ts, fingerprint, severity, data) VALUES (?,?,?,?,?)",
                (alarm.id, alarm.timestamp, alarm.fingerprint, alarm.severity.value, data))
            if cur.rowcount == 0:
                return False  # already projected (replay after restart)
            self.db.execute("DELETE FROM alarm_log WHERE seq <= (SELECT MAX(seq) FROM alarm_log) - ?", (ALARM_LOG_MAX,))
            if alarm.is_clear:
                self.db.execute("UPDATE alarms SET active=0, last_seen=? WHERE fingerprint=?",
                                (alarm.timestamp, alarm.fingerprint))
                return True
            row = self.db.execute("SELECT active, first_seen FROM alarms WHERE fingerprint=?",
                                  (alarm.fingerprint,)).fetchone()
            first = row["first_seen"] if row and row["active"] else alarm.timestamp
            self.db.execute(
                "INSERT OR REPLACE INTO alarms VALUES (?,?,?,?,?,?,?,?,?)",
                (alarm.fingerprint, alarm.device, alarm.type.value, alarm.resource, alarm.severity.value,
                 1, first, alarm.timestamp, data),
            )
            return True

    def put_incident(self, inc: Incident) -> bool:
        with self.lock, self.db:
            row = self.db.execute("SELECT version FROM incidents WHERE id=?", (inc.id,)).fetchone()
            if row and row["version"] >= inc.version:
                return False
            self.db.execute("INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?,?)",
                            (inc.id, inc.status.value, inc.device, inc.created_at, inc.updated_at,
                             inc.version, inc.model_dump_json()))
            return True

    def put_remediation(self, rem: Remediation) -> bool:
        with self.lock, self.db:
            row = self.db.execute("SELECT version FROM remediations WHERE id=?", (rem.id,)).fetchone()
            if row and row["version"] >= rem.version:
                return False
            self.db.execute("INSERT OR REPLACE INTO remediations VALUES (?,?,?,?,?,?)",
                            (rem.id, rem.incident_id, rem.status.value, rem.updated_at, rem.version,
                             rem.model_dump_json()))
            return True

    # ------------------------------------------------------------------- reads
    def _rows(self, sql: str, args: tuple = ()) -> list[dict[str, Any]]:
        with self.lock:
            return [json.loads(r["data"]) for r in self.db.execute(sql, args).fetchall()]

    def alarms(self, active_only: bool = True, limit: int = 500) -> list[dict[str, Any]]:
        if active_only:
            return self._rows("SELECT data FROM alarms WHERE active=1 ORDER BY last_seen DESC LIMIT ?", (limit,))
        return self._rows("SELECT data FROM alarms ORDER BY last_seen DESC LIMIT ?", (limit,))

    def alarm_log(self, limit: int = 200) -> list[dict[str, Any]]:
        return self._rows("SELECT data FROM alarm_log ORDER BY seq DESC LIMIT ?", (limit,))

    def incidents(self, status: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        if status:
            return self._rows("SELECT data FROM incidents WHERE status=? ORDER BY created_at DESC LIMIT ?",
                              (status, limit))
        return self._rows("SELECT data FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,))

    def incident(self, inc_id: str) -> dict[str, Any] | None:
        rows = self._rows("SELECT data FROM incidents WHERE id=?", (inc_id,))
        return rows[0] if rows else None

    def remediations(self, status: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        if status:
            return self._rows("SELECT data FROM remediations WHERE status=? ORDER BY updated_at DESC LIMIT ?",
                              (status, limit))
        return self._rows("SELECT data FROM remediations ORDER BY updated_at DESC LIMIT ?", (limit,))

    def remediation(self, rem_id: str) -> dict[str, Any] | None:
        rows = self._rows("SELECT data FROM remediations WHERE id=?", (rem_id,))
        return rows[0] if rows else None

    def remediation_for(self, inc_id: str) -> dict[str, Any] | None:
        rows = self._rows("SELECT data FROM remediations WHERE incident_id=? ORDER BY updated_at DESC LIMIT 1",
                          (inc_id,))
        return rows[0] if rows else None

    def summary(self) -> dict[str, Any]:
        with self.lock:
            q = lambda sql, *a: self.db.execute(sql, a).fetchone()[0]  # noqa: E731
            total_alarms = q("SELECT COUNT(*) FROM alarm_log WHERE severity != 'clear'")
            active = q("SELECT COUNT(*) FROM alarms WHERE active=1")
            incidents = q("SELECT COUNT(*) FROM incidents WHERE status != 'superseded'")
            open_inc = q("SELECT COUNT(*) FROM incidents WHERE status='open'")
            by_status = {r[0]: r[1] for r in self.db.execute(
                "SELECT status, COUNT(*) FROM remediations GROUP BY status").fetchall()}
            heal_rows = self.db.execute(
                "SELECT r.data AS rd, i.data AS id FROM remediations r JOIN incidents i ON i.id = r.incident_id "
                "WHERE r.status IN ('healed','mitigated')").fetchall()
        durations = []
        for row in heal_rows:
            rem, inc = json.loads(row["rd"]), json.loads(row["id"])
            if rem.get("finished_at"):
                durations.append(rem["finished_at"] - inc["root_cause"]["timestamp"])
        auto = by_status.get("healed", 0) + by_status.get("mitigated", 0)
        decided = sum(v for k, v in by_status.items() if k not in ("running", "scheduled", "pending_approval"))
        return {
            "alarms_total": total_alarms,
            "alarms_active": active,
            "incidents_total": incidents,
            "incidents_open": open_inc,
            "noise_reduction": round(1 - incidents / total_alarms, 3) if total_alarms else 0.0,
            "remediations": by_status,
            "auto_healed": auto,
            "auto_heal_rate": round(auto / decided, 3) if decided else 0.0,
            "mean_time_to_heal_s": round(sum(durations) / len(durations), 1) if durations else None,
        }
