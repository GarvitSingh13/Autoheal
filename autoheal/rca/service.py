"""RCA service: consumes ``alarms`` and publishes ``incidents``.

Run exactly one RCA instance per alarm stream: correlation needs a global view.
"""

from __future__ import annotations

import logging

from autoheal.bus import Bus, Topics
from autoheal.config import Settings
from autoheal.models import Alarm, Incident, Remediation
from autoheal.rca.engine import RcaEngine
from autoheal.rca.rules import load_rules
from autoheal.topology import Topology

log = logging.getLogger(__name__)


class RcaService:
    def __init__(self, settings: Settings, bus: Bus, topology: Topology):
        self.bus = bus
        self.engine = RcaEngine(settings.rca, topology, load_rules(settings.paths.rules), self._publish)
        bus.subscribe([Topics.ALARMS, Topics.REMEDIATIONS], self._on_message, group="rca")

    async def _publish(self, incident: Incident) -> None:
        await self.bus.publish(Topics.INCIDENTS, incident, key=incident.id)

    async def _on_message(self, topic: str, data: dict) -> None:
        if topic == Topics.ALARMS:
            await self.engine.handle_alarm(Alarm.model_validate(data))
        elif topic == Topics.REMEDIATIONS:
            self.engine.handle_remediation(Remediation.model_validate(data))
