"""Safety policy for automated changes.

Automation that misfires at scale is worse than no automation, so every remediation
passes these checks before it touches a device:

* exclusions   – devices listed in settings or tagged ``no-auto-heal`` are never touched
* flap guard   – the same fault remediated N times within a window means the fix is not
                 holding; stop and hand over to a human instead of looping
* rate limit   – at most N actions per device per hour
* circuit breaker – at most N actions network-wide per window; a burst means something
                 systemic (or the platform itself is wrong)
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass

from autoheal.config import RemediationSettings
from autoheal.topology import Topology

NO_AUTO_TAG = "no-auto-heal"


@dataclass
class Execution:
    ts: float
    device: str
    key: str


class Guardrails:
    def __init__(self, settings: RemediationSettings, topology: Topology):
        self.cfg = settings
        self.topology = topology
        self.history: deque[Execution] = deque()

    def _prune(self, now: float) -> None:
        horizon = max(self.cfg.flap_limit.window, self.cfg.circuit_breaker.window, 3600.0)
        while self.history and now - self.history[0].ts > horizon:
            self.history.popleft()

    def check(self, device: str, key: str, now: float | None = None) -> str | None:
        """Return a reason string if the action must not run automatically."""
        now = now or time.time()
        self._prune(now)
        dev = self.topology.devices.get(device)
        if device in self.cfg.excluded_devices or (dev is not None and NO_AUTO_TAG in dev.tags):
            return f"{device} is excluded from automatic remediation"
        flap = self.cfg.flap_limit
        repeats = sum(1 for e in self.history if e.key == key and now - e.ts <= flap.window)
        if repeats >= flap.count:
            return (f"flap guard: {key} already remediated {repeats} time(s) in the last "
                    f"{int(flap.window)}s; the fix is not holding, automation suspended for this fault")
        per_device = sum(1 for e in self.history if e.device == device and now - e.ts <= 3600)
        if per_device >= self.cfg.max_actions_per_device_per_hour:
            return (f"rate limit: {per_device} automated action(s) on {device} in the last hour "
                    f"(max {self.cfg.max_actions_per_device_per_hour})")
        cb = self.cfg.circuit_breaker
        recent = sum(1 for e in self.history if now - e.ts <= cb.window)
        if recent >= cb.max_actions:
            return (f"circuit breaker open: {recent} automated action(s) network-wide in the last "
                    f"{int(cb.window)}s (max {cb.max_actions})")
        return None

    def record(self, device: str, key: str, now: float | None = None) -> None:
        self.history.append(Execution(now or time.time(), device, key))
