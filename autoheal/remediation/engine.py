"""Remediation engine: incident -> playbook -> guarded, verified, reversible execution.

Decision flow for each new incident::

    select playbook ──none──> NO_PLAYBOOK (escalate)
          │
    confidence / exclusions / flap guard / rate limit / circuit breaker ──fail──> ESCALATED
          │
    mode=dry_run ──> DRY_RUN (rendered payloads recorded, nothing sent)
          │
    hold_down? ──> SCHEDULED (cancelled if the incident clears or is superseded meanwhile)
          │
    approval needed? ──> PENDING_APPROVAL ──reject/timeout──> REJECTED / EXPIRED
          │
    RUNNING: steps in order; NETCONF changes use commit-confirmed and are confirmed only
             after every verify step passes; any failure -> cancel-commit/rollback -> FAILED
          │
    HEALED | MITIGATED (mitigated = service restored, follow-up work for a human)
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Any, Awaitable, Callable

from autoheal.config import Settings
from autoheal.models import (
    Command,
    Incident,
    IncidentStatus,
    Remediation,
    RemediationStatus,
    StepRecord,
    now,
)
from autoheal.remediation.drivers.netconf import NetconfError, NetconfSession, connect
from autoheal.remediation.drivers.rest import RestError, RestTarget
from autoheal.remediation.guardrails import Guardrails
from autoheal.remediation.notifier import Notifier
from autoheal.remediation.playbooks import Playbook, Step, select_playbook
from autoheal.topology import Topology
from autoheal.vendors import VendorProfile, render, render_obj

log = logging.getLogger(__name__)

Publisher = Callable[[Remediation], Awaitable[None]]

NOTIFY_ON = {
    RemediationStatus.NO_PLAYBOOK,
    RemediationStatus.ESCALATED,
    RemediationStatus.FAILED,
    RemediationStatus.PENDING_APPROVAL,
    RemediationStatus.MITIGATED,
    RemediationStatus.EXPIRED,
}


class StepFailure(Exception):
    pass


class RemediationEngine:
    def __init__(self, settings: Settings, topology: Topology, playbooks: list[Playbook],
                 vendors: dict[str, VendorProfile], publish: Publisher, notifier: Notifier | None = None):
        self.cfg = settings.remediation
        self.settings = settings
        self.topology = topology
        self.playbooks = playbooks
        self.vendors = vendors
        self._publish = publish
        self.notifier = notifier or Notifier(self.cfg.notify_webhook)
        self.guard = Guardrails(self.cfg, topology)
        self.records: dict[str, Remediation] = {}
        self.by_incident: dict[str, str] = {}
        self.incidents: dict[str, Incident] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._approvals: dict[str, asyncio.Future] = {}
        self._device_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._sem = asyncio.Semaphore(self.cfg.max_concurrent)

    # ------------------------------------------------------------------ inputs
    async def handle_incident(self, inc: Incident) -> None:
        known = self.incidents.get(inc.id)
        if known is not None and known.version > inc.version:
            return  # stale redelivery
        self.incidents[inc.id] = inc
        rem_id = self.by_incident.get(inc.id)

        if inc.status != IncidentStatus.OPEN:
            rem = self.records.get(rem_id) if rem_id else None
            if rem and rem.status in (RemediationStatus.SCHEDULED, RemediationStatus.PENDING_APPROVAL):
                task = self._tasks.pop(rem.id, None)
                if task:
                    task.cancel()
                why = ("superseded by incident " + inc.superseded_by) if inc.superseded_by else "cleared"
                await self._set(rem, RemediationStatus.CANCELLED, f"incident {why} before remediation started")
            return
        if rem_id is None:
            await self._decide(inc)

    async def handle_command(self, cmd: Command) -> None:
        fut = self._approvals.get(cmd.remediation_id)
        rem = self.records.get(cmd.remediation_id)
        if fut is None or fut.done() or rem is None:
            log.info("ignoring %s for %s: not awaiting approval", cmd.command, cmd.remediation_id)
            return
        if cmd.command == "approve":
            rem.approved_by = cmd.user
        fut.set_result(cmd)

    # ---------------------------------------------------------------- decision
    async def _decide(self, inc: Incident) -> None:
        root = inc.root_cause
        ctx = self._context(inc)
        rem = Remediation(incident_id=inc.id, device=root.device, root_cause=root.type.value,
                          resource=root.resource, status=RemediationStatus.SCHEDULED,
                          confidence=inc.confidence)
        self.records[rem.id] = rem
        self.by_incident[inc.id] = rem.id

        pb = select_playbook(self.playbooks, root.type, ctx)
        if pb is None:
            candidates = [p.name for p in self.playbooks if p.root_cause == root.type]
            why = (f"playbook(s) {', '.join(candidates)} exist for {root.type.value} but their conditions do not "
                   f"hold here" if candidates else f"no playbook handles {root.type.value}")
            await self._set(rem, RemediationStatus.NO_PLAYBOOK, f"{why}; manual investigation required")
            return
        pctx = {**ctx, "params": pb.params}
        rem.playbook = pb.name
        rem.follow_up = render(pb.follow_up, pctx) if pb.follow_up else ""
        rem.steps = [StepRecord(index=i, kind=s.action, description=self._describe(s, pctx),
                                target=self._target_name(pctx, s.target)) for i, s in enumerate(pb.steps)]
        rem.suppressions = self._suppressions(pb, pctx)

        required = max(self.cfg.min_confidence, pb.min_confidence)
        if inc.confidence < required:
            await self._set(rem, RemediationStatus.ESCALATED,
                            f"RCA confidence {inc.confidence:.2f} below threshold {required:.2f}; "
                            f"not acting automatically on an uncertain diagnosis")
            return
        blocked = self.guard.check(rem.device, self._fault_key(rem))
        if blocked:
            await self._set(rem, RemediationStatus.ESCALATED, blocked)
            return
        if self.cfg.mode == "dry_run":
            for rec, step in zip(rem.steps, pb.steps):
                rec.detail = self._preview(step, pctx)
                rec.status = "skipped"
            await self._set(rem, RemediationStatus.DRY_RUN, "dry-run mode: rendered actions recorded, nothing sent")
            return
        self._tasks[rem.id] = asyncio.create_task(self._proceed(rem, pb, pctx), name=f"rem:{rem.id}")

    async def _proceed(self, rem: Remediation, pb: Playbook, ctx: dict[str, Any]) -> None:
        try:
            if pb.hold_down > 0:
                await self._set(rem, RemediationStatus.SCHEDULED,
                                f"hold-down {pb.hold_down:g}s: waiting for the fault to settle or self-clear")
                await asyncio.sleep(pb.hold_down)
            if self.cfg.mode == "approval" or pb.requires_approval:
                why = "approval mode" if self.cfg.mode == "approval" else f"playbook '{pb.name}' requires approval"
                await self._set(rem, RemediationStatus.PENDING_APPROVAL, f"{why}: waiting for an operator")
                fut = asyncio.get_running_loop().create_future()
                self._approvals[rem.id] = fut
                try:
                    cmd: Command = await asyncio.wait_for(fut, self.cfg.approval_timeout)
                except asyncio.TimeoutError:
                    await self._set(rem, RemediationStatus.EXPIRED,
                                    f"no operator decision within {int(self.cfg.approval_timeout)}s")
                    return
                finally:
                    self._approvals.pop(rem.id, None)
                if cmd.command != "approve":
                    await self._set(rem, RemediationStatus.REJECTED,
                                    f"rejected by {cmd.user}" + (f": {cmd.comment}" if cmd.comment else ""))
                    return
                blocked = self.guard.check(rem.device, self._fault_key(rem))
                if blocked:
                    await self._set(rem, RemediationStatus.ESCALATED, blocked)
                    return
            inc = self.incidents.get(rem.incident_id)
            if inc is not None and inc.status != IncidentStatus.OPEN:
                await self._set(rem, RemediationStatus.CANCELLED, f"incident {inc.status.value} before execution")
                return
            await self._execute(rem, pb, ctx)
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # defensive: never leave a record dangling
            log.exception("remediation %s crashed", rem.id)
            await self._set(rem, RemediationStatus.FAILED, f"internal error: {exc}")
        finally:
            self._tasks.pop(rem.id, None)

    # --------------------------------------------------------------- execution
    async def _execute(self, rem: Remediation, pb: Playbook, ctx: dict[str, Any]) -> None:
        async with self._sem, self._device_locks[rem.device]:
            self.guard.record(rem.device, self._fault_key(rem))
            rem.started_at = now()
            await self._set(rem, RemediationStatus.RUNNING, f"executing playbook '{pb.name}'")
            sessions: dict[str, NetconfSession] = {}
            current: StepRecord | None = None
            try:
                for step, rec in zip(pb.steps, rem.steps):
                    current = rec
                    sctx = self._step_ctx(ctx, step)
                    if not step.enabled(sctx):
                        rec.status, rec.detail = "skipped", f"condition not met: {step.when}"
                        continue
                    rec.status, rec.started_at = "running", now()
                    await self._publish_rem(rem)
                    rec.detail = await self._run_step(step, sctx, sessions)
                    rec.status, rec.finished_at = "ok", now()
                    await self._publish_rem(rem)
                current = None
                for s in sessions.values():
                    await asyncio.to_thread(s.confirm)
                outcome = RemediationStatus.MITIGATED if pb.outcome == "mitigated" else RemediationStatus.HEALED
                reason = "all steps succeeded and verification passed"
                if any(s.action == "netconf_config" for s in pb.steps):
                    reason += "; configuration change confirmed"
                rem.finished_at = now()
                await self._set(rem, outcome, reason)
            except Exception as exc:
                if current is not None:
                    current.status, current.finished_at = "failed", now()
                    current.detail = str(exc)
                notes = []
                for dev, s in sessions.items():
                    try:
                        notes.append(f"{dev}: {await asyncio.to_thread(s.rollback)}")
                    except Exception as rb_exc:
                        notes.append(f"{dev}: rollback failed ({rb_exc})")
                if sessions:
                    for rec in rem.steps:
                        if rec.kind == "netconf_config" and rec.status == "ok":
                            rec.status = "rolled_back"
                failed_at = f"step {current.index + 1} ({current.description})" if current else "confirmation"
                reason = f"{failed_at} failed: {exc}."
                if notes:
                    reason += " Rollback: " + "; ".join(notes) + "."
                reason += " Escalated to operator."
                rem.finished_at = now()
                await self._set(rem, RemediationStatus.FAILED, reason)
            finally:
                for s in sessions.values():
                    await asyncio.to_thread(s.close)

    async def _run_step(self, step: Step, ctx: dict[str, Any], sessions: dict[str, NetconfSession]) -> str:
        p = step.params
        dev = ctx["device"]
        if step.action == "wait":
            await asyncio.sleep(float(p["seconds"]))
            return f"waited {p['seconds']}s"
        if step.action == "netconf_config":
            session = await self._session(dev, sessions)
            xml = session.profile.config(p["template"], ctx)
            timeout = int(p.get("confirm_timeout", self.cfg.confirm_timeout))
            return await asyncio.to_thread(session.apply_config, xml, timeout)
        if step.action == "netconf_rpc":
            session = await self._session(dev, sessions)
            xml = session.profile.rpc(p["rpc"], ctx)
            await asyncio.to_thread(session.rpc, xml)
            return f"rpc '{p['rpc']}' ok"
        if step.action == "rest":
            target = self._rest_target(p.get("endpoint", "device"), dev)
            method, path = p.get("method", "POST"), render(p["path"], ctx)
            resp = await target.request(method, path, render_obj(p.get("json"), ctx))
            expected = p.get("expect_status", [200, 201, 202, 204])
            if resp.status_code not in expected:
                raise StepFailure(f"{method} {path} returned HTTP {resp.status_code}: {resp.text[:200]}")
            return f"{method.upper()} {path} -> HTTP {resp.status_code}"
        if step.action == "verify":
            return await self._verify(p, ctx, sessions)
        raise StepFailure(f"unknown step action {step.action}")

    async def _verify(self, p: dict[str, Any], ctx: dict[str, Any], sessions: dict[str, NetconfSession]) -> str:
        p = {**p, **render_obj({k: p[k] for k in ("expect", "max", "min") if k in p}, ctx)}
        probe, timeout, interval = p["probe"], float(p.get("timeout", 30)), float(p.get("interval", 2))
        deadline = asyncio.get_running_loop().time() + timeout
        value: Any = None
        error = ""
        while True:
            try:
                value, error = await self._read_probe(probe, ctx, sessions), ""
            except (NetconfError, RestError, OSError, EOFError) as exc:
                value, error = None, str(exc)
            except Exception as exc:  # ncclient raises a zoo of transport errors
                value, error = None, f"{type(exc).__name__}: {exc}"
            if _satisfied(value, p):
                return f"{probe}@{ctx['device']} = {value}"
            if asyncio.get_running_loop().time() >= deadline:
                break
            await asyncio.sleep(interval)
        want = p.get("expect", p.get("max", p.get("min")))
        raise StepFailure(f"verification failed: {probe}@{ctx['device']} = {value!r} after {timeout:g}s "
                          f"(wanted {want!r}){' - ' + error if error else ''}")

    async def _read_probe(self, name: str, ctx: dict[str, Any], sessions: dict[str, NetconfSession]) -> Any:
        dev = ctx["device"]
        probe = self._profile(dev).probe(name)
        if probe.kind == "builtin":  # device_reachable
            device = self.topology.devices[dev]
            try:
                m = await asyncio.to_thread(connect, device, self.settings.credentials.netconf,
                                            self.settings.collector.connect_timeout)
                await asyncio.to_thread(m.close_session)
                return True
            except Exception:
                return False
        if probe.kind == "restconf_get":
            target = self._rest_target("device", dev)
            return await target.get_value(render(probe.path, ctx), probe.json_path)
        session = await self._session(dev, sessions)
        return await asyncio.to_thread(session.read_probe, name, ctx)

    # ---------------------------------------------------------------- helpers
    async def _session(self, dev: str, sessions: dict[str, NetconfSession]) -> NetconfSession:
        s = sessions.get(dev)
        if s is not None and s.m is not None and s.m.connected:
            return s
        device = self.topology.devices.get(dev)
        if device is None:
            raise StepFailure(f"device {dev} not in topology")
        s = NetconfSession(device, self.settings.credentials.netconf, self._profile(dev),
                           self.settings.collector.connect_timeout)
        await asyncio.to_thread(s.open)
        sessions[dev] = s
        return s

    def _profile(self, dev: str) -> VendorProfile:
        device = self.topology.devices.get(dev)
        vendor = device.vendor if device else "sim"
        if vendor not in self.vendors:
            raise StepFailure(f"no vendor profile '{vendor}' for {dev}")
        return self.vendors[vendor]

    def _rest_target(self, endpoint: str, dev: str) -> RestTarget:
        if endpoint == "device":
            device = self.topology.devices.get(dev)
            if device is None or not device.restconf_url:
                raise StepFailure(f"{dev} has no restconf_url in topology")
            return RestTarget.for_device(device.restconf_url, self.settings.credentials.restconf)
        if endpoint not in self.settings.endpoints:
            raise StepFailure(f"REST endpoint '{endpoint}' not configured in settings.endpoints")
        return RestTarget.from_endpoint(self.settings.endpoints[endpoint])

    def _context(self, inc: Incident) -> dict[str, Any]:
        root = inc.root_cause
        ctx = self.topology.context_for(root.device, root.resource, root.type)
        ctx.update(alarm=root.model_dump(mode="json"), attributes=dict(root.attributes),
                   incident=inc.model_dump(mode="json"), resource=root.resource)
        return ctx

    @staticmethod
    def _target_ctx(ctx: dict[str, Any], target: str) -> dict[str, Any]:
        if target == "device":
            return ctx
        if not ctx.get("peer_device"):
            raise StepFailure("step targets the link peer but the topology has no peer for this resource")
        swapped = dict(ctx)
        swapped.update(device=ctx["peer_device"], interface=ctx["peer_interface"],
                       peer_device=ctx["device"], peer_interface=ctx["interface"],
                       local_ip=ctx.get("peer_ip"), peer_ip=ctx.get("local_ip"), neighbor=ctx.get("local_ip"))
        return swapped

    @staticmethod
    def _target_name(ctx: dict[str, Any], target: str) -> str:
        if target == "peer":
            return f"{ctx.get('peer_device')}:{ctx.get('peer_interface')}"
        return ctx["device"] + (f":{ctx['interface']}" if ctx.get("interface") else "")

    def _suppressions(self, pb: Playbook, ctx: dict[str, Any]) -> list[str]:
        out = []
        targets = {"device"} | {s.target for s in pb.steps}
        for t in targets:
            if t == "peer" and not ctx.get("peer_device"):
                continue
            tctx = self._target_ctx(ctx, t)
            for at in pb.suppress_alarms:
                out.append(f"{tctx['device']}|{at.value}|{tctx.get('interface') or ''}")
        return sorted(set(out))

    def _describe(self, step: Step, ctx: dict[str, Any]) -> str:
        try:
            return render(step.describe(), self._step_ctx(ctx, step))
        except Exception:
            return step.describe()

    def _step_ctx(self, ctx: dict[str, Any], step: Step) -> dict[str, Any]:
        sctx = self._target_ctx(ctx, step.target)
        if step.params.get("vars"):
            sctx = {**sctx, **render_obj(step.params["vars"], sctx)}
        return sctx

    def _preview(self, step: Step, ctx: dict[str, Any]) -> str:
        p = step.params
        try:
            ctx = self._step_ctx(ctx, step)
            if not step.enabled(ctx):
                return f"skipped (condition not met: {step.when})"
            prof = self._profile(ctx["device"])
            if step.action == "netconf_config":
                return prof.config(p["template"], ctx)
            if step.action == "netconf_rpc":
                return prof.rpc(p["rpc"], ctx)
            if step.action == "rest":
                body = render_obj(p.get("json"), ctx)
                return f"{p.get('method', 'POST').upper()} {render(p['path'], ctx)} {body if body else ''}".strip()
        except Exception as exc:
            return f"render error: {exc}"
        return step.describe()

    @staticmethod
    def _fault_key(rem: Remediation) -> str:
        return f"{rem.device}|{rem.root_cause}|{rem.resource}"

    async def _set(self, rem: Remediation, status: RemediationStatus, reason: str) -> None:
        rem.status = status
        rem.reason = reason
        log.info("remediation %s [%s] %s: %s", rem.id, rem.playbook or "-", status.value, reason)
        await self._publish_rem(rem)
        if status in NOTIFY_ON:
            await self.notifier.send(rem)

    async def _publish_rem(self, rem: Remediation) -> None:
        rem.touch()
        await self._publish(rem.model_copy(deep=True))

    async def shutdown(self) -> None:
        for t in list(self._tasks.values()):
            t.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)


def _satisfied(value: Any, p: dict[str, Any]) -> bool:
    if value is None:
        return False
    if "expect" in p:
        expected = p["expect"] if isinstance(p["expect"], list) else [p["expect"]]
        return str(value).strip().lower() in {str(e).strip().lower() for e in expected}
    try:
        num = float(value)
    except (TypeError, ValueError):
        return False
    if "max" in p and num > float(p["max"]):
        return False
    if "min" in p and num < float(p["min"]):
        return False
    return "max" in p or "min" in p
