"""Live Kubernetes audit through kubectl.

Reads workloads, services and RBAC objects from the current (or given)
context with `kubectl get -o json` and runs the same checks as manifest
scanning, so drift between Git and the cluster shows up. Secrets are never
fetched. Requires only kubectl and read access (the `view` ClusterRole plus
read on RBAC objects).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Callable

from rempart.models import Finding
from rempart.scanners.kubernetes import KubernetesScanner

KINDS = "pods,deployments,statefulsets,daemonsets,replicasets,jobs,cronjobs,services,roles,clusterroles,rolebindings,clusterrolebindings"
SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "gatekeeper-system", "calico-system", "tigera-operator", "cert-manager"}


def kubectl_json(context: str | None = None) -> dict[str, Any]:
    if not shutil.which("kubectl"):
        raise RuntimeError("kubectl not found on PATH")
    cmd = ["kubectl", "get", KINDS, "--all-namespaces", "-o", "json"]
    if context:
        cmd[1:1] = ["--context", context]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or "kubectl failed")
    return json.loads(out.stdout)


def audit(items: dict[str, Any] | None = None, *, context: str | None = None, include_system: bool = False,
          fetch: Callable[[str | None], dict[str, Any]] = kubectl_json) -> list[Finding]:
    data = items if items is not None else fetch(context)
    scanner = KubernetesScanner()
    findings: list[Finding] = []
    for obj in data.get("items", []):
        meta = obj.get("metadata") or {}
        ns = meta.get("namespace", "")
        if ns in SYSTEM_NAMESPACES and not include_system:
            continue
        if meta.get("ownerReferences") and obj.get("kind") in ("Pod", "ReplicaSet", "Job"):
            continue  # judged through the owning Deployment/StatefulSet/CronJob, not once per replica
        if (meta.get("name") or "").startswith("system:") and obj.get("kind", "").startswith("Cluster"):
            continue  # built-in RBAC
        where = f"k8s://{context or 'current'}/{ns or '_cluster'}/{obj.get('kind')}/{meta.get('name')}"
        for f in scanner.document(where, obj, []):
            f.path = where
            f.line = 0
            f.verification = "observed"
            findings.append(f)
    findings.sort(key=lambda f: -f.risk)
    return findings
