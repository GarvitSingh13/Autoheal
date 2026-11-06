"""NETCONF driver (ncclient, RFC 6241).

Change safety follows the standard NETCONF pattern:

* candidate datastore: ``lock`` -> ``edit-config`` -> ``validate`` -> ``commit confirmed``
  (the device reverts automatically if we never confirm, e.g. if we lose the session
  because the change cut us off) -> verify -> confirming ``commit`` or ``cancel-commit``.
* running-only devices: snapshot ``get-config`` first; roll back by replacing with it.

ncclient is synchronous; the remediation engine calls these methods via ``asyncio.to_thread``.
"""

from __future__ import annotations

import logging
from typing import Any

from lxml import etree
from ncclient import manager
from ncclient.operations import RPCError

from autoheal.config import Credentials
from autoheal.topology import Device
from autoheal.vendors import VendorProfile, render

log = logging.getLogger(__name__)

NC_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
CAP_CANDIDATE = ":candidate"
CAP_CONFIRMED = ":confirmed-commit"
CAP_VALIDATE = ":validate"


class NetconfError(Exception):
    pass


def connect(device: Device, creds: Credentials, timeout: float = 10.0) -> manager.Manager:
    return manager.connect(
        host=device.host,
        port=device.netconf_port,
        username=creds.username,
        password=creds.password,
        hostkey_verify=False,
        allow_agent=False,
        look_for_keys=False,
        timeout=timeout,
        device_params={"name": "default"},
    )


def wrap_config(inner: str) -> str:
    return f'<config xmlns="{NC_NS}">{inner}</config>'


class NetconfSession:
    def __init__(self, device: Device, creds: Credentials, profile: VendorProfile, timeout: float = 10.0):
        self.device = device
        self.creds = creds
        self.profile = profile
        self.timeout = timeout
        self.m: manager.Manager | None = None
        self.pending_confirm = False
        self._snapshot: str | None = None
        self._changed_running = False

    # --------------------------------------------------------------- lifecycle
    def open(self) -> "NetconfSession":
        try:
            self.m = connect(self.device, self.creds, self.timeout)
        except Exception as exc:
            raise NetconfError(f"cannot open NETCONF session to {self.device.name} "
                               f"({self.device.host}:{self.device.netconf_port}): {exc}") from exc
        return self

    def close(self) -> None:
        if self.m is not None:
            try:
                if self.m.connected:
                    self.m.close_session()
            except Exception:
                pass
            self.m = None

    def _has(self, cap: str) -> bool:
        assert self.m is not None
        return cap in self.m.server_capabilities

    # ----------------------------------------------------------------- config
    def apply_config(self, inner_xml: str, confirm_timeout: int) -> str:
        assert self.m is not None
        config = wrap_config(inner_xml)
        try:
            if self._has(CAP_CANDIDATE):
                with self.m.locked("candidate"):
                    self.m.discard_changes()
                    self.m.edit_config(target="candidate", config=config, default_operation="merge")
                    if self._has(CAP_VALIDATE):
                        self.m.validate(source="candidate")
                    if self._has(CAP_CONFIRMED):
                        self.m.commit(confirmed=True, timeout=str(confirm_timeout))
                        self.pending_confirm = True
                        return f"committed (confirmed, auto-rollback in {confirm_timeout}s unless confirmed)"
                    self.m.commit()
                    return "committed"
            if self._snapshot is None:
                self._snapshot = self.m.get_config(source="running").data_xml
            self.m.edit_config(target="running", config=config, default_operation="merge")
            self._changed_running = True
            return "applied to running (snapshot taken for rollback)"
        except RPCError as exc:
            raise NetconfError(f"{self.device.name} rejected config: {exc.message or exc}") from exc

    def confirm(self) -> None:
        if self.pending_confirm and self.m is not None:
            self.m.commit()
            self.pending_confirm = False

    def rollback(self) -> str:
        if self.m is None or not self.m.connected:
            return ("session lost; device reverts on confirm timeout" if self.pending_confirm
                    else "session lost; nothing to roll back")
        if self.pending_confirm:
            self.m.cancel_commit()
            self.pending_confirm = False
            return "cancel-commit issued: device reverted to pre-change configuration"
        if self._changed_running and self._snapshot:
            data = etree.fromstring(self._snapshot.encode())
            inner = "".join(etree.tostring(child, encoding="unicode") for child in data)
            self.m.edit_config(target="running", config=wrap_config(inner), default_operation="replace")
            self._changed_running = False
            return "running configuration restored from snapshot"
        return "nothing to roll back"

    # -------------------------------------------------------------- operations
    def rpc(self, rpc_xml: str) -> str:
        assert self.m is not None
        try:
            reply = self.m.dispatch(etree.fromstring(rpc_xml.encode()))
        except RPCError as exc:
            raise NetconfError(f"{self.device.name} rpc failed: {exc.message or exc}") from exc
        return reply.xml if hasattr(reply, "xml") else str(reply)

    def read_probe(self, probe_name: str, ctx: dict[str, Any]) -> Any:
        assert self.m is not None
        probe = self.profile.probe(probe_name)
        flt = ("subtree", render(probe.filter, ctx)) if probe.filter else None
        if probe.kind == "netconf_get":
            data = self.m.get(filter=flt).data_ele
        elif probe.kind == "netconf_get_config":
            data = self.m.get_config(source="running", filter=flt).data_ele
        else:
            raise NetconfError(f"probe {probe_name} is not a NETCONF probe")
        result = data.xpath(render(probe.xpath, ctx), namespaces=self.profile.namespaces)
        if isinstance(result, list):
            result = result[0].text if result and hasattr(result[0], "text") else (result[0] if result else None)
        return result if result != "" else None
