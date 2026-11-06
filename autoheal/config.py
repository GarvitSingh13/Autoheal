"""Settings loading.

Settings come from a YAML file (default ``config/settings.yaml``). Any value can be
overridden with an environment variable named ``AUTOHEAL__<SECTION>__<KEY>``, e.g.
``AUTOHEAL__BUS__BOOTSTRAP_SERVERS=kafka:9092``. YAML files may reference environment
variables as ``${VAR}`` or ``${VAR:-default}``.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def expand_env(text: str) -> str:
    return _ENV_REF.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), text)


def load_yaml(path: str | Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(expand_env(fh.read())) or {}


class BusSettings(BaseModel):
    backend: Literal["kafka", "memory"] = "kafka"
    bootstrap_servers: str = "localhost:9092"
    topic_prefix: str = "autoheal"
    group_id: str = "autoheal"
    partitions: int = 3
    replication_factor: int = 1


class ApiSettings(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    db_path: str = "data/autoheal.db"


class CollectorSettings(BaseModel):
    reconnect_interval: float = 3.0
    unreachable_after_failures: int = 2
    resync_interval: float = 60.0
    connect_timeout: float = 5.0


class RcaSettings(BaseModel):
    correlation_window: float = 5.0
    standalone_confidence: float = 0.6
    residual_grace: float = 30.0  # time for protocols to reconverge after a root cause clears


class FlapLimit(BaseModel):
    count: int = 3
    window: float = 3600.0


class CircuitBreaker(BaseModel):
    max_actions: int = 20
    window: float = 600.0


class RemediationSettings(BaseModel):
    mode: Literal["auto", "approval", "dry_run"] = "auto"
    min_confidence: float = 0.7
    max_concurrent: int = 4
    max_actions_per_device_per_hour: int = 6
    flap_limit: FlapLimit = Field(default_factory=FlapLimit)
    circuit_breaker: CircuitBreaker = Field(default_factory=CircuitBreaker)
    confirm_timeout: int = 120
    approval_timeout: float = 1800.0
    excluded_devices: list[str] = Field(default_factory=list)
    notify_webhook: str | None = None


class Credentials(BaseModel):
    username: str = "admin"
    password: str = "admin"


class CredentialSettings(BaseModel):
    netconf: Credentials = Field(default_factory=Credentials)
    restconf: Credentials = Field(default_factory=Credentials)


class Endpoint(BaseModel):
    base_url: str
    username: str | None = None
    password: str | None = None
    verify_tls: bool = True
    timeout: float = 10.0


class PathSettings(BaseModel):
    topology: str = "config/topology.yaml"
    rules: str = "config/rca_rules.yaml"
    playbooks: str = "config/playbooks.yaml"
    vendors_dir: str = "config/vendors"


class LabSettings(BaseModel):
    simulator_url: str | None = None


class Settings(BaseModel):
    bus: BusSettings = Field(default_factory=BusSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)
    collector: CollectorSettings = Field(default_factory=CollectorSettings)
    rca: RcaSettings = Field(default_factory=RcaSettings)
    remediation: RemediationSettings = Field(default_factory=RemediationSettings)
    credentials: CredentialSettings = Field(default_factory=CredentialSettings)
    endpoints: dict[str, Endpoint] = Field(default_factory=dict)
    paths: PathSettings = Field(default_factory=PathSettings)
    lab: LabSettings = Field(default_factory=LabSettings)
    log_level: str = "INFO"

    def resolve(self, base_dir: Path) -> "Settings":
        """Make relative file paths absolute against the settings file directory's parent."""
        for name in ("topology", "rules", "playbooks", "vendors_dir"):
            p = Path(getattr(self.paths, name))
            if not p.is_absolute():
                setattr(self.paths, name, str((base_dir / p).resolve()))
        db = Path(self.api.db_path)
        if not db.is_absolute():
            self.api.db_path = str((base_dir / db).resolve())
        return self


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    for key, value in os.environ.items():
        if not key.startswith("AUTOHEAL__"):
            continue
        parts = [p.lower() for p in key[len("AUTOHEAL__"):].split("__") if p]
        if not parts:
            continue
        node = data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        parsed = yaml.safe_load(value) if value else value
        node[parts[-1]] = parsed
    return data


def load_settings(path: str | Path | None = None) -> Settings:
    path = Path(path or os.environ.get("AUTOHEAL_CONFIG", "config/settings.yaml"))
    data: dict[str, Any] = load_yaml(path) if path.exists() else {}
    data = _apply_env_overrides(data)
    settings = Settings.model_validate(data)
    # Paths in settings.yaml are relative to the project root (parent of config/).
    base_dir = path.resolve().parent.parent if path.exists() else Path.cwd()
    return settings.resolve(base_dir)
