"""Event and entity models exchanged over the bus."""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def now() -> float:
    return time.time()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class AlarmType(str, Enum):
    LINK_DOWN = "LINK_DOWN"
    INTERFACE_ADMIN_DOWN = "INTERFACE_ADMIN_DOWN"
    BGP_SESSION_DOWN = "BGP_SESSION_DOWN"
    OSPF_NEIGHBOR_DOWN = "OSPF_NEIGHBOR_DOWN"
    HIGH_CPU = "HIGH_CPU"
    HIGH_ERROR_RATE = "HIGH_ERROR_RATE"
    DEVICE_UNREACHABLE = "DEVICE_UNREACHABLE"
    GENERIC = "GENERIC"


# Alarm types whose ``resource`` is an interface name.
INTERFACE_ALARMS = {
    AlarmType.LINK_DOWN,
    AlarmType.INTERFACE_ADMIN_DOWN,
    AlarmType.OSPF_NEIGHBOR_DOWN,
    AlarmType.HIGH_ERROR_RATE,
}


class Severity(str, Enum):
    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"
    WARNING = "warning"
    CLEAR = "clear"


class Alarm(BaseModel):
    id: str = Field(default_factory=lambda: new_id("alm"))
    source: str = "unknown"
    device: str
    resource: str = ""
    type: AlarmType
    severity: Severity = Severity.MAJOR
    message: str = ""
    timestamp: float = Field(default_factory=now)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return f"{self.device}|{self.type.value}|{self.resource}"

    @property
    def is_clear(self) -> bool:
        return self.severity == Severity.CLEAR

    def label(self) -> str:
        res = f":{self.resource}" if self.resource else ""
        return f"{self.type.value} on {self.device}{res}"


class IncidentStatus(str, Enum):
    OPEN = "open"
    CLEARED = "cleared"
    SUPERSEDED = "superseded"


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: new_id("inc"))
    status: IncidentStatus = IncidentStatus.OPEN
    root_cause: Alarm
    rule: str
    confidence: float
    explanation: str = ""
    symptoms: list[Alarm] = Field(default_factory=list)
    cleared_symptoms: list[str] = Field(default_factory=list)  # fingerprints of symptoms that cleared
    affected_devices: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=now)
    updated_at: float = Field(default_factory=now)
    cleared_at: float | None = None
    superseded_by: str | None = None
    version: int = 1

    @property
    def device(self) -> str:
        return self.root_cause.device

    @property
    def alarm_count(self) -> int:
        return 1 + len(self.symptoms)


class RemediationStatus(str, Enum):
    NO_PLAYBOOK = "no_playbook"
    SCHEDULED = "scheduled"  # waiting for hold-down to elapse
    PENDING_APPROVAL = "pending_approval"
    RUNNING = "running"
    HEALED = "healed"
    MITIGATED = "mitigated"
    FAILED = "failed"
    ESCALATED = "escalated"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    DRY_RUN = "dry_run"


TERMINAL_REMEDIATION = {
    RemediationStatus.NO_PLAYBOOK,
    RemediationStatus.HEALED,
    RemediationStatus.MITIGATED,
    RemediationStatus.FAILED,
    RemediationStatus.ESCALATED,
    RemediationStatus.REJECTED,
    RemediationStatus.CANCELLED,
    RemediationStatus.EXPIRED,
    RemediationStatus.DRY_RUN,
}


class StepRecord(BaseModel):
    index: int
    kind: str
    description: str
    target: str = ""
    status: str = "pending"  # pending | running | ok | failed | skipped | rolled_back
    detail: str = ""
    started_at: float | None = None
    finished_at: float | None = None


class Remediation(BaseModel):
    id: str = Field(default_factory=lambda: new_id("rem"))
    incident_id: str
    device: str
    root_cause: str
    resource: str = ""
    playbook: str | None = None
    status: RemediationStatus
    reason: str = ""
    follow_up: str = ""
    confidence: float = 0.0
    steps: list[StepRecord] = Field(default_factory=list)
    # Alarm fingerprints this remediation is expected to cause (e.g. an interface bounce
    # raises INTERFACE_ADMIN_DOWN); RCA suppresses them while the remediation runs.
    suppressions: list[str] = Field(default_factory=list)
    approved_by: str | None = None
    created_at: float = Field(default_factory=now)
    updated_at: float = Field(default_factory=now)
    started_at: float | None = None
    finished_at: float | None = None
    version: int = 1

    def touch(self) -> None:
        self.updated_at = now()
        self.version += 1


class Command(BaseModel):
    """Operator command sent from the API to the remediation engine."""

    command: str  # approve | reject
    remediation_id: str
    user: str = "operator"
    comment: str = ""
    timestamp: float = Field(default_factory=now)
