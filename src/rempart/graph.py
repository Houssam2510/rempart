"""Resource graph: which deployable thing does each finding belong to, and how are
those things connected?

Attack paths are only as good as the links between their pieces. Two findings
in the same repository are a coincidence; an SSRF in the `api` service that
depends on a `mongo` service publishing 27017 on every interface is a path.
This module reads the infrastructure files already in the repository and builds
a small undirected graph:

* Terraform blocks are nodes; a reference `aws_iam_role.app` in another block
  is an edge.
* docker-compose services are nodes; `depends_on`, `links`, shared networks
  and the default project network are edges. A service owns the files of its
  build context and of its bind-mounted host paths.
* Kubernetes objects are nodes; Service selectors, serviceAccountName,
  RoleBinding subjects and roleRef, and Ingress backends are edges.
* A Dockerfile directory owns the files below it.

`resources_of(finding)` places a finding on nodes; `link(a, b)` returns the
shortest path between two findings, or None.
"""

from __future__ import annotations

import os
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

import yaml

from rempart.models import Finding

_TF_REF = re.compile(r"\b(?:(data)\.)?([a-z][a-z0-9]*_[a-z0-9_]+)\.([A-Za-z_][\w-]*)\b")


@dataclass
class ResourceGraph:
    edges: dict[str, set[str]] = field(default_factory=dict)
    spans: dict[str, list[tuple[int, int, str]]] = field(default_factory=dict)  # file -> (start, end, node)
    owners: list[tuple[str, str]] = field(default_factory=list)  # (directory prefix, node)
    labels: dict[str, str] = field(default_factory=dict)

    def add_node(self, node: str, label: str = "") -> None:
        self.edges.setdefault(node, set())
        if label:
            self.labels[node] = label

    def connect(self, a: str, b: str) -> None:
        if a == b:
            return
        self.add_node(a)
        self.add_node(b)
        self.edges[a].add(b)
        self.edges[b].add(a)

    # ------------------------------------------------------------ placement
    def resources_of(self, f: Finding) -> set[str]:
        out: set[str] = set()
        explicit = f.extra.get("resource")
        if explicit:
            out.add(str(explicit))
        if f.path.startswith("aws://"):
            out.add(f.path)
            return out
        for start, end, node in self.spans.get(f.path, []):
            if f.line == 0 or start <= f.line <= end:
                out.add(node)
        if not out:
            # the most specific owner wins: a file under api/ belongs to the api service, not to a root image
            best = -1
            for prefix, node in self.owners:
                if prefix == "" or f.path == prefix or f.path.startswith(prefix + "/"):
                    if len(prefix) > best:
                        best, out = len(prefix), {node}
                    elif len(prefix) == best:
                        out.add(node)
        return out

    def path_between(self, a: set[str], b: set[str], max_hops: int = 5) -> list[str] | None:
        if not a or not b:
            return None
        common = a & b
        if common:
            return [sorted(common)[0]]
        seen = {n: [n] for n in a}
        queue = deque(a)
        while queue:
            n = queue.popleft()
            if len(seen[n]) > max_hops:
                continue
            for m in sorted(self.edges.get(n, ())):
                if m in seen:
                    continue
                seen[m] = seen[n] + [m]
                if m in b:
                    return seen[m]
                queue.append(m)
        return None

    def link(self, x: Finding, y: Finding) -> list[str] | None:
        if x.path == y.path and not x.path.startswith("aws://") and x.path.endswith((".yml", ".yaml")) and ".github/workflows/" in x.path:
            return [f"workflow {x.path}"]
        return self.path_between(self.resources_of(x), self.resources_of(y))

    def describe(self, path: list[str]) -> str:
        return " → ".join(self.labels.get(n, n) for n in path)


# ---------------------------------------------------------------- builders

def build_graph(files: Iterable[str], read: Callable[[str], str | None]) -> ResourceGraph:
    g = ResourceGraph()
    files = list(files)
    tf_files = [f for f in files if f.endswith(".tf")]
    if tf_files:
        _terraform(g, tf_files, read)
    for rel in files:
        base = os.path.basename(rel)
        if re.fullmatch(r"(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml", base):
            _compose(g, rel, read(rel) or "")
        elif rel.endswith((".yaml", ".yml")):
            text = read(rel) or ""
            if "apiVersion" in text and "kind" in text and "{{" not in text:
                _kubernetes(g, rel, text)
        elif base == "Dockerfile" or base.startswith("Dockerfile."):
            d = os.path.dirname(rel)
            node = f"docker:{d or '.'}"
            g.add_node(node, f"image built from {d or '.'}/")
            g.owners.append((d, node))
    _image_links(g, files, read)
    # a compose service and the Dockerfile it builds are the same deployable
    by_prefix: dict[str, list[str]] = {}
    for prefix, node in g.owners:
        by_prefix.setdefault(prefix, []).append(node)
    for nodes in by_prefix.values():
        for a in nodes[1:]:
            g.connect(nodes[0], a)
    return g


_BUILD_TAG = re.compile(r"(?:docker|podman)\s+(?:buildx\s+)?build\b([^\n]*)")
_TAG = re.compile(r"(?:-t|--tag)[ =]['\"]?([\w./-]+)")


def _repo(image: str) -> str:
    """'ghcr.io/acme/api:1.2@sha256:..' -> 'ghcr.io/acme/api'."""
    image = image.split("@")[0]
    last = image.rsplit("/", 1)
    if ":" in last[-1]:
        image = image[: image.rfind(":")]
    return image.strip("'\"")


def _image_links(g: ResourceGraph, files: list[str], read: Callable[[str], str | None]) -> None:
    """Connect the place an image is built to every place that runs it (k8s, compose, Terraform user_data)."""
    builders: dict[str, str] = {}
    for rel in files:
        base = os.path.basename(rel)
        if not (rel.endswith((".yml", ".yaml", ".sh", ".mk")) or base in ("Makefile", "Justfile", "Taskfile")):
            continue
        text = read(rel) or ""
        for m in _BUILD_TAG.finditer(text):
            args = m.group(1)
            tag = _TAG.search(args)
            if not tag:
                continue
            ctx_dir = args.split()[-1] if args.split() else "."
            ctx_dir = "." if ctx_dir.startswith("-") or ctx_dir.startswith("$") else ctx_dir
            d = _join(os.path.dirname(rel) if not rel.startswith(".github/") else "", ctx_dir)
            node = f"docker:{d or '.'}"
            g.add_node(node, f"image built from {d or '.'}/")
            if (d, node) not in g.owners:
                g.owners.append((d, node))
            builders[_repo(tag.group(1))] = node
    # compose services that both build and name an image
    for rel in files:
        if re.fullmatch(r"(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml", os.path.basename(rel)):
            try:
                doc = yaml.safe_load(read(rel) or "")
            except yaml.YAMLError:
                continue
            for name, svc in ((doc or {}).get("services") or {}).items() if isinstance(doc, dict) else []:
                if isinstance(svc, dict) and svc.get("image") and svc.get("build"):
                    builders.setdefault(_repo(str(svc["image"])), f"compose:{rel}:{name}")
    if not builders:
        return
    names = sorted(builders, key=len, reverse=True)
    pattern = re.compile(r"(?<![\w./-])(" + "|".join(re.escape(n) for n in names) + r")(?=[:@\s'\"]|$)", re.M)
    for rel, spans in list(g.spans.items()):
        text = read(rel) or ""
        lines = text.splitlines()
        for start, end, node in spans:
            chunk = "\n".join(lines[max(0, start - 1):end])
            for m in pattern.finditer(chunk):
                g.connect(node, builders[m.group(1)])


def _terraform(g: ResourceGraph, tf_files: list[str], read: Callable[[str], str | None]) -> None:
    from rempart.scanners.terraform import blocks

    bodies: list[tuple[str, str]] = []
    for rel in tf_files:
        text = read(rel) or ""
        for b in blocks(text):
            if b.kind not in ("resource", "data", "module") or not b.type:
                continue
            node = f"tf:{'data.' if b.kind == 'data' else ''}{b.type}.{b.name}" if b.kind != "module" else f"tf:module.{b.type}"
            g.add_node(node, node[3:])
            start = text.count("\n", 0, b.offset) + 1
            end = start + b.body.count("\n") + 1
            g.spans.setdefault(rel, []).append((start, end, node))
            bodies.append((node, b.body))
    known = set(g.edges)
    for node, body in bodies:
        for m in _TF_REF.finditer(body):
            ref = f"tf:{'data.' if m.group(1) else ''}{m.group(2)}.{m.group(3)}"
            if ref in known:
                g.connect(node, ref)
        for m in re.finditer(r"\bmodule\.([\w-]+)", body):
            if f"tf:module.{m.group(1)}" in known:
                g.connect(node, f"tf:module.{m.group(1)}")


def _compose(g: ResourceGraph, rel: str, text: str) -> None:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return
    if not isinstance(doc, dict) or not isinstance(doc.get("services"), dict):
        return
    base = os.path.dirname(rel)
    lines = text.splitlines()
    services: dict[str, dict[str, Any]] = {n: (s if isinstance(s, dict) else {}) for n, s in doc["services"].items()}
    starts = []
    for name in services:
        i = next((k for k, l in enumerate(lines, 1) if re.match(rf"^\s{{2,4}}['\"]?{re.escape(str(name))}['\"]?\s*:", l)), 0)
        starts.append((i, str(name)))
    starts.sort()
    for idx, (start, name) in enumerate(starts):
        end = starts[idx + 1][0] - 1 if idx + 1 < len(starts) else len(lines)
        node = f"compose:{rel}:{name}"
        g.add_node(node, f"compose service {name}")
        if start:
            g.spans.setdefault(rel, []).append((start, end, node))
    networks: dict[str, set[str]] = {}
    for name, svc in services.items():
        node = f"compose:{rel}:{name}"
        g.add_node(node)  # also tag findings built with extra={"resource": "compose:<svc>"}
        g.connect(node, f"compose:{name}")
        for dep in _names(svc.get("depends_on")) + _names(svc.get("links")):
            dep = dep.split(":")[0]
            if dep in services:
                g.connect(node, f"compose:{rel}:{dep}")
        nets = _names(svc.get("networks")) or ["default"]
        if svc.get("network_mode"):
            nets = []
        for n in nets:
            networks.setdefault(n, set()).add(node)
        build = svc.get("build")
        ctx_dir = build if isinstance(build, str) else (build or {}).get("context") if isinstance(build, dict) else None
        if isinstance(ctx_dir, str) and not ctx_dir.startswith(("http", "git")):
            g.owners.append((_join(base, ctx_dir), node))
        for vol in svc.get("volumes") or []:
            host = vol.split(":")[0] if isinstance(vol, str) else (vol or {}).get("source") if isinstance(vol, dict) else None
            if isinstance(host, str) and host.startswith((".", "/")) and not host.startswith("/var/run"):
                if host.startswith("."):
                    g.owners.append((_join(base, host), node))
    for members in networks.values():
        members_sorted = sorted(members)
        for a in members_sorted:
            for b in members_sorted:
                g.connect(a, b)


def _names(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, (str, int))]
    if isinstance(value, dict):
        return [str(k) for k in value]
    return []


def _join(base: str, rel: str) -> str:
    p = os.path.normpath(os.path.join(base, rel)).replace("\\", "/")
    return "" if p == "." else p


def _kubernetes(g: ResourceGraph, rel: str, text: str) -> None:
    chunks = re.split(r"(?m)^---\s*$", text)
    line = 1
    objects: list[tuple[str, dict[str, Any]]] = []
    for chunk in chunks:
        start = line
        line += chunk.count("\n")
        try:
            doc = yaml.safe_load(chunk)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict) or "kind" not in doc:
            continue
        meta = doc.get("metadata") or {}
        ns = str(meta.get("namespace") or "default")
        node = f"k8s:{ns}/{doc['kind']}/{meta.get('name', '?')}"
        g.add_node(node, f"{doc['kind']}/{meta.get('name', '?')}")
        g.spans.setdefault(rel, []).append((start, line, node))
        g.connect(node, f"k8s:{doc['kind']}/{meta.get('name', '?')}")  # how the static scanner names it
        objects.append((node, doc))
    for node, doc in objects:
        kind, spec = doc.get("kind"), doc.get("spec") or {}
        ns = node.split(":", 1)[1].split("/")[0]
        pod = (spec.get("template") or {}) if isinstance(spec, dict) else {}
        pod_spec = pod.get("spec") or (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
        if pod_spec.get("serviceAccountName"):
            g.connect(node, f"k8s:{ns}/ServiceAccount/{pod_spec['serviceAccountName']}")
        labels = (pod.get("metadata") or {}).get("labels") or {}
        if labels:
            for other, odoc in objects:
                if odoc.get("kind") == "Service":
                    sel = (odoc.get("spec") or {}).get("selector") or {}
                    if sel and all(labels.get(k) == v for k, v in sel.items()):
                        g.connect(node, other)
        if kind in ("RoleBinding", "ClusterRoleBinding"):
            for s in doc.get("subjects") or []:
                if s.get("kind") == "ServiceAccount":
                    g.connect(node, f"k8s:{s.get('namespace') or ns}/ServiceAccount/{s.get('name')}")
            ref = doc.get("roleRef") or {}
            if ref.get("name"):
                g.connect(node, f"k8s:{ns}/{ref.get('kind', 'Role')}/{ref['name']}")
                g.connect(node, f"k8s:default/{ref.get('kind', 'Role')}/{ref['name']}")
        if kind == "Ingress":
            for r in (spec.get("rules") or []):
                for p in ((r.get("http") or {}).get("paths") or []):
                    svc = ((p.get("backend") or {}).get("service") or {}).get("name") or (p.get("backend") or {}).get("serviceName")
                    if svc:
                        g.connect(node, f"k8s:{ns}/Service/{svc}")
