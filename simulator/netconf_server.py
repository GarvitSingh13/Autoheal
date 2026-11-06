"""Minimal but standards-shaped NETCONF-over-SSH server (RFC 6241/6242/5277).

Supports: hello/capabilities (base:1.0 framing), get, get-config (subtree filters),
edit-config (merge/replace/create/delete/remove, candidate + running), lock/unlock,
commit (incl. confirmed commit + timeout), cancel-commit, discard-changes, validate,
close-session, kill-session, create-subscription (notifications), plus device RPCs
in ``urn:autoheal:sim:ops`` (clear-bgp-neighbor, restart-process).
"""

from __future__ import annotations

import itertools
import logging
import queue
import socket
import threading

import paramiko
from lxml import etree

from simulator.datastore import NC_NS, EditError, subtree_filter
from simulator.network import Network

log = logging.getLogger("simulator.netconf")

DELIM = b"]]>]]>"
OPS_NS = "urn:autoheal:sim:ops"
CAPABILITIES = [
    "urn:ietf:params:netconf:base:1.0",
    "urn:ietf:params:netconf:capability:writable-running:1.0",
    "urn:ietf:params:netconf:capability:candidate:1.0",
    "urn:ietf:params:netconf:capability:confirmed-commit:1.0",
    "urn:ietf:params:netconf:capability:confirmed-commit:1.1",
    "urn:ietf:params:netconf:capability:validate:1.0",
    "urn:ietf:params:netconf:capability:validate:1.1",
    "urn:ietf:params:netconf:capability:rollback-on-error:1.0",
    "urn:ietf:params:netconf:capability:notification:1.0",
    "urn:ietf:params:netconf:capability:interleave:1.0",
    "urn:ietf:params:xml:ns:yang:ietf-interfaces?module=ietf-interfaces&revision=2018-02-20",
    "urn:ietf:params:xml:ns:yang:ietf-ip?module=ietf-ip&revision=2018-02-22",
    "urn:autoheal:sim:routing?module=autoheal-sim-routing&revision=2026-01-01",
    "urn:autoheal:sim:system?module=autoheal-sim-system&revision=2026-01-01",
    "urn:autoheal:sim:ops?module=autoheal-sim-ops&revision=2026-01-01",
]

_session_ids = itertools.count(1)


class RpcError(Exception):
    def __init__(self, tag: str, message: str, etype: str = "application"):
        super().__init__(message)
        self.tag, self.message, self.etype = tag, message, etype


class _SSHIface(paramiko.ServerInterface):
    def __init__(self, username: str, password: str):
        self.username, self.password = username, password
        self.netconf_requested = threading.Event()

    def check_auth_password(self, username, password):
        ok = username == self.username and password == self.password
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request(self, channel, name):
        if name == "netconf":
            self.netconf_requested.set()
            return True
        return False


class NetconfSession:
    def __init__(self, net: Network, device: str, chan: paramiko.Channel, transport: paramiko.Transport):
        self.net, self.device, self.chan, self.transport = net, device, chan, transport
        self.id = next(_session_ids)
        self.wlock = threading.Lock()
        self.notifq: queue.Queue | None = None
        self.closed = threading.Event()

    # ------------------------------------------------------------------- I/O
    def send(self, xml: str) -> None:
        with self.wlock:
            self.chan.sendall(xml.encode() + DELIM)

    def close(self) -> None:
        if self.closed.is_set():
            return
        self.closed.set()
        try:
            self.transport.close()
        except Exception:
            pass

    def _messages(self):
        buf = b""
        while not self.closed.is_set():
            try:
                data = self.chan.recv(65536)
            except (socket.timeout, OSError, EOFError):
                return
            if not data:
                return
            buf += data
            while DELIM in buf:
                msg, buf = buf.split(DELIM, 1)
                if msg.strip():
                    yield msg

    def run(self) -> None:
        self.net.session_closers[self.device][self.id] = self.close
        hello = (f'<hello xmlns="{NC_NS}"><capabilities>'
                 + "".join(f"<capability>{c.replace('&', '&amp;')}</capability>" for c in CAPABILITIES)
                 + f"</capabilities><session-id>{self.id}</session-id></hello>")
        try:
            self.send(hello)
            msgs = self._messages()
            next(msgs, None)  # client hello
            for raw in msgs:
                if not self._handle(raw):
                    break
        except Exception as exc:
            log.debug("%s session %d ended: %s", self.device, self.id, exc)
        finally:
            self.close()
            if self.notifq is not None:
                try:
                    self.net.subscribers[self.device].remove(self.notifq.put)
                except ValueError:
                    pass
                self.notifq.put(None)
            self.net.session_closed(self.device, self.id)

    def _notification_pump(self) -> None:
        while True:
            item = self.notifq.get()
            if item is None or self.closed.is_set():
                return
            try:
                self.send(item)
            except Exception:
                return

    # ------------------------------------------------------------------- RPCs
    def _handle(self, raw: bytes) -> bool:
        try:
            rpc = etree.fromstring(raw)
        except etree.XMLSyntaxError:
            self.send(self._reply(None, self._error("malformed-message", "unparseable XML", "rpc")))
            return True
        mid = rpc.get("message-id")
        ops = [c for c in rpc if isinstance(c.tag, str)]
        if etree.QName(rpc).localname != "rpc" or not ops:
            self.send(self._reply(mid, self._error("operation-not-supported", "expected <rpc>", "protocol")))
            return True
        op = ops[0]
        keep_open = True
        try:
            body, keep_open = self._dispatch(op)
        except RpcError as e:
            body = self._error(e.tag, e.message, e.etype)
        except EditError as e:
            body = self._error(e.tag, e.message)
        self.send(self._reply(mid, body))
        if not keep_open:
            self.close()
        return keep_open

    def _dispatch(self, op) -> tuple[str, bool]:
        qn = etree.QName(op)
        name, ns = qn.localname, qn.namespace
        dev = self.device
        if ns == OPS_NS:
            if name == "clear-bgp-neighbor":
                self.net.clear_bgp(dev, (op.findtext(f"{{{OPS_NS}}}address") or "").strip())
                return "<ok/>", True
            if name == "restart-process":
                self.net.restart_process(dev, (op.findtext(f"{{{OPS_NS}}}name") or "").strip())
                return "<ok/>", True
            raise RpcError("operation-not-supported", f"unknown rpc {name}")
        if ns != NC_NS and name != "create-subscription":
            raise RpcError("operation-not-supported", f"unknown rpc {{{ns}}}{name}")

        if name == "get":
            return self._data(self.net.get_state(dev), op), True
        if name == "get-config":
            return self._data(self.net.get_config(dev, self._datastore(op, "source")), op), True
        if name == "edit-config":
            target = self._datastore(op, "target")
            config = op.find(f"{{{NC_NS}}}config")
            if config is None:
                raise RpcError("missing-element", "edit-config requires <config>")
            default_op = (op.findtext(f"{{{NC_NS}}}default-operation") or "merge").strip()
            self.net.edit_config(dev, target, config, default_op, self.id)
            return "<ok/>", True
        if name == "lock":
            self.net.lock_ds(dev, self._datastore(op, "target"), self.id)
            return "<ok/>", True
        if name == "unlock":
            self.net.unlock_ds(dev, self._datastore(op, "target"), self.id)
            return "<ok/>", True
        if name == "commit":
            confirmed = op.find(f"{{{NC_NS}}}confirmed") is not None
            timeout = int((op.findtext(f"{{{NC_NS}}}confirm-timeout") or "600").strip())
            self.net.commit(dev, self.id, confirmed, timeout)
            return "<ok/>", True
        if name == "cancel-commit":
            self.net.cancel_commit(dev)
            return "<ok/>", True
        if name == "discard-changes":
            self.net.discard_changes(dev)
            return "<ok/>", True
        if name == "validate":
            src = op.find(f"{{{NC_NS}}}source")
            inline = src.find(f"{{{NC_NS}}}config") if src is not None else None
            if inline is None:
                self.net.validate_ds(dev, self._datastore(op, "source"))
            return "<ok/>", True
        if name == "create-subscription":
            if self.notifq is None:
                self.notifq = queue.Queue()
                self.net.subscribers[dev].append(self.notifq.put)
                threading.Thread(target=self._notification_pump, daemon=True,
                                 name=f"notif:{dev}:{self.id}").start()
            return "<ok/>", True
        if name == "close-session":
            return "<ok/>", False
        if name == "kill-session":
            return "<ok/>", True
        raise RpcError("operation-not-supported", f"operation {name} not supported")

    @staticmethod
    def _datastore(op, wrapper: str) -> str:
        w = op.find(f"{{{NC_NS}}}{wrapper}")
        ds = [c for c in w if isinstance(c.tag, str)] if w is not None else []
        if not ds:
            raise RpcError("missing-element", f"<{wrapper}> datastore required")
        name = etree.QName(ds[0]).localname
        if name not in ("running", "candidate"):
            raise RpcError("invalid-value", f"datastore {name} not supported")
        return name

    @staticmethod
    def _data(tree, op) -> str:
        flt = op.find(f"{{{NC_NS}}}filter")
        if flt is not None:
            if flt.get("type", "subtree") != "subtree":
                raise RpcError("operation-not-supported", "only subtree filters are supported")
            tree = subtree_filter(tree, flt)
        inner = "".join(etree.tostring(c, encoding="unicode") for c in tree if isinstance(c.tag, str))
        return f"<data>{inner}</data>"

    @staticmethod
    def _error(tag: str, message: str, etype: str = "application") -> str:
        msg = message.replace("&", "&amp;").replace("<", "&lt;")
        return (f"<rpc-error><error-type>{etype}</error-type><error-tag>{tag}</error-tag>"
                f"<error-severity>error</error-severity>"
                f'<error-message xml:lang="en">{msg}</error-message></rpc-error>')

    @staticmethod
    def _reply(mid: str | None, body: str) -> str:
        attr = f' message-id="{mid}"' if mid is not None else ""
        return f'<rpc-reply xmlns="{NC_NS}"{attr}>{body}</rpc-reply>'


class NetconfServer:
    """Listens on one TCP port and serves NETCONF for one simulated device."""

    def __init__(self, net: Network, device: str, host: str, port: int, host_key: paramiko.PKey,
                 username: str = "admin", password: str = "admin"):
        self.net, self.device, self.host, self.port = net, device, host, port
        self.host_key, self.username, self.password = host_key, username, password
        self.sock: socket.socket | None = None
        self.stopping = threading.Event()

    def start(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(32)
        self.sock.settimeout(0.5)
        threading.Thread(target=self._accept_loop, daemon=True, name=f"netconf:{self.device}").start()
        log.info("%s NETCONF on %s:%d", self.device, self.host, self.port)

    def stop(self) -> None:
        self.stopping.set()
        if self.sock:
            self.sock.close()
        for close in list(self.net.session_closers[self.device].values()):
            close()

    def _accept_loop(self) -> None:
        while not self.stopping.is_set():
            try:
                client, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self.net.is_reachable(self.device):
                client.close()  # powered off or cut off from the management network
                continue
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client: socket.socket) -> None:
        transport = paramiko.Transport(client)
        transport.add_server_key(self.host_key)
        iface = _SSHIface(self.username, self.password)
        try:
            transport.start_server(server=iface)
            chan = transport.accept(timeout=10)
            if chan is None or not iface.netconf_requested.wait(10):
                transport.close()
                return
            NetconfSession(self.net, self.device, chan, transport).run()
        except Exception as exc:
            log.debug("%s: SSH session error: %s", self.device, exc)
            transport.close()
