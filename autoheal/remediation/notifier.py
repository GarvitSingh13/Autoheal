"""Escalation notifications (log + optional Slack/Teams-compatible webhook)."""

from __future__ import annotations

import logging

import httpx

from autoheal.models import Remediation

log = logging.getLogger(__name__)


class Notifier:
    def __init__(self, webhook: str | None = None):
        self.webhook = webhook

    async def send(self, rem: Remediation) -> None:
        text = (f"[autoheal] {rem.status.value.upper()}: {rem.root_cause} on {rem.device}"
                f"{':' + rem.resource if rem.resource else ''} (incident {rem.incident_id}"
                f"{', playbook ' + rem.playbook if rem.playbook else ''}). {rem.reason}")
        if rem.follow_up:
            text += f" Follow-up: {rem.follow_up}"
        log.warning(text)
        if not self.webhook:
            return
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(self.webhook, json={"text": text, "remediation": rem.model_dump(mode="json")})
        except httpx.HTTPError as exc:
            log.error("webhook notification failed: %s", exc)
