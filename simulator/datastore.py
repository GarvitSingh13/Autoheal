"""XML datastore operations for the simulated NETCONF server.

* :func:`merge` implements ``edit-config`` semantics (merge / replace / create / delete /
  remove) for YANG-style trees where list entries are keyed by a ``name``, ``address``
  or ``id`` leaf.
* :func:`subtree_filter` implements RFC 6241 section 6 subtree filtering (containment,
  selection and content-match nodes).
"""

from __future__ import annotations

import copy

from lxml import etree

NC_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
OP_ATTR = f"{{{NC_NS}}}operation"
KEY_LEAVES = ("name", "address", "id")


class EditError(Exception):
    def __init__(self, tag: str, message: str):
        super().__init__(message)
        self.tag = tag
        self.message = message


def localname(el) -> str:
    return etree.QName(el).localname


def _elements(el):
    return [c for c in el if isinstance(c.tag, str)]


def _key(el):
    for child in _elements(el):
        if localname(child) in KEY_LEAVES and len(child) == 0:
            return child.tag, (child.text or "").strip()
    return None


def _find_match(parent, el):
    key = _key(el)
    for c in _elements(parent):
        if c.tag != el.tag:
            continue
        if key is None or _key(c) == key:
            return c
    return None


def _clean(el):
    new = copy.deepcopy(el)
    for node in new.iter():
        if isinstance(node.tag, str) and OP_ATTR in node.attrib:
            del node.attrib[OP_ATTR]
    return new


def merge(parent, src, default_op: str = "merge") -> None:
    op = src.get(OP_ATTR, default_op)
    existing = _find_match(parent, src)
    if op in ("delete", "remove"):
        if existing is None:
            if op == "delete":
                raise EditError("data-missing", f"cannot delete {localname(src)}: not present")
            return
        parent.remove(existing)
        return
    if op == "create" and existing is not None:
        raise EditError("data-exists", f"cannot create {localname(src)}: already exists")
    if op == "replace" or existing is None or len(_elements(src)) == 0:
        new = _clean(src)
        if existing is not None:
            parent.replace(existing, new)
        else:
            parent.append(new)
        return
    child_op = "merge" if op in ("none", "create") else op
    for child in _elements(src):
        merge(existing, child, child_op)


def apply_edit(datastore, config, default_op: str = "merge"):
    """Return a new datastore tree with ``config``'s children applied."""
    result = copy.deepcopy(datastore)
    if default_op == "replace":
        for c in _elements(result):
            result.remove(c)
        for c in _elements(config):
            result.append(_clean(c))
        return result
    for c in _elements(config):
        merge(result, c, default_op)
    return result


def subtree_filter(data, flt):
    """Apply a subtree filter element (``<filter>``) to a ``<data>`` tree."""
    out = etree.Element(data.tag, nsmap=data.nsmap)
    fnodes = _elements(flt)
    if not fnodes:
        return out
    for d in _elements(data):
        for f in fnodes:
            if d.tag != f.tag:
                continue
            r = _filter(d, f)
            if r is not None:
                out.append(r)
                break
    return out


def _filter(d, f):
    fchildren = _elements(f)
    if not fchildren:
        txt = (f.text or "").strip()
        if txt:
            return copy.deepcopy(d) if (d.text or "").strip() == txt else None
        return copy.deepcopy(d)
    content = [c for c in fchildren if len(c) == 0 and (c.text or "").strip()]
    for c in content:
        if not any(x.tag == c.tag and (x.text or "").strip() == c.text.strip() for x in _elements(d)):
            return None
    others = [c for c in fchildren if not any(c is k for k in content)]
    if not others:
        return copy.deepcopy(d)
    out = etree.Element(d.tag, nsmap=d.nsmap)
    content_tags = {c.tag for c in content}
    matched = False
    for x in _elements(d):
        if x.tag in content_tags:
            out.append(copy.deepcopy(x))
            continue
        for c in others:
            if x.tag != c.tag:
                continue
            r = _filter(x, c)
            if r is not None:
                out.append(r)
                matched = True
                break
    return out if matched else None
