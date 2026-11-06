"""Builds the API read model (SQLite) and Prometheus metrics from bus events."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

from autoheal.bus import Bus, Topics
from autoheal.models import TERMINAL_REMEDIATION, Alarm, Incident, IncidentStatus, Remediation, RemediationStatus
from autoheal.store import Store

ALARMS = Counter("autoheal_alarms_total", "Alarms received", ["type", "severity"])
INCIDENTS = Counter("autoheal_incidents_total", "Incidents opened by RCA", ["rule"])
REMEDIATIONS = Counter("autoheal_remediations_total", "Remediations reaching a final state", ["status", "playbook"])
OPEN_INCIDENTS = Gauge("autoheal_open_incidents", "Currently open incidents")
HEAL_SECONDS = Histogram("autoheal_time_to_heal_seconds", "First alarm to verified heal",
                         buckets=(5, 10, 20, 30, 60, 120, 300, 600, 1800))


class Projector:
    def __init__(self, store: Store, bus: Bus):
        self.store = store
        bus.subscribe([Topics.ALARMS, Topics.INCIDENTS, Topics.REMEDIATIONS], self.handle,
                      group="api", from_beginning=True)
        self._seen_incidents: set[str] = set()

    async def handle(self, topic: str, data: dict) -> None:
        if topic == Topics.ALARMS:
            alarm = Alarm.model_validate(data)
            if self.store.put_alarm(alarm):
                ALARMS.labels(alarm.type.value, alarm.severity.value).inc()
        elif topic == Topics.INCIDENTS:
            inc = Incident.model_validate(data)
            if self.store.put_incident(inc) and inc.id not in self._seen_incidents and inc.status == IncidentStatus.OPEN:
                self._seen_incidents.add(inc.id)
                INCIDENTS.labels(inc.rule).inc()
            OPEN_INCIDENTS.set(self.store.summary()["incidents_open"])
        elif topic == Topics.REMEDIATIONS:
            rem = Remediation.model_validate(data)
            if self.store.put_remediation(rem) and rem.status in TERMINAL_REMEDIATION:
                REMEDIATIONS.labels(rem.status.value, rem.playbook or "none").inc()
                if rem.status in (RemediationStatus.HEALED, RemediationStatus.MITIGATED) and rem.finished_at:
                    inc = self.store.incident(rem.incident_id)
                    if inc:
                        HEAL_SECONDS.observe(rem.finished_at - inc["root_cause"]["timestamp"])
