"""Kubernetes manifest checks, mapped to the OWASP Kubernetes Top 10 (2025)
and the Pod Security Standards (restricted profile)."""

from __future__ import annotations

import re
from typing import Any, Iterator

import yaml

from rempart.engine import ScanContext
from rempart.models import Finding, Severity
from rempart.registry import A01, A02, A03, A07, C, H, L, M, rule

K01 = "K01:2025 Insecure Workload Configurations"
K02 = "K02:2025 Overly Permissive Authorization Configurations"
K03 = "K03:2025 Secrets Management Failures"
K05 = "K05:2025 Missing Network Segmentation Controls"
K06 = "K06:2025 Overly Exposed Kubernetes Components"
PSS = "Pod Security Standards (restricted)"


def r(id, title, sev, fix, cwe, owasp=A02, fw=(K01, PSS), conf=0.85):
    return rule(id, title, sev, "kubernetes", cwe=cwe, owasp=owasp, frameworks=fw, fix=fix, confidence=conf)


R_PRIV = r("K8S-PRIVILEGED", "Privileged container", C, "Remove `privileged: true`. A privileged container is root on the node.", "CWE-250")
R_ESC = r("K8S-PRIV-ESCALATION", "Privilege escalation not disabled", M, "Set securityContext.allowPrivilegeEscalation: false.", "CWE-269")
R_ROOT = r("K8S-RUNS-AS-ROOT", "Container may run as root", M, "Set runAsNonRoot: true and a non-zero runAsUser.", "CWE-250")
R_HOSTNS = r("K8S-HOST-NAMESPACE", "Pod shares host namespaces", H, "Remove hostNetwork, hostPID and hostIPC.", "CWE-668")
R_HOSTPATH = r("K8S-HOSTPATH", "hostPath volume", H, "Use PersistentVolumes, ConfigMaps or emptyDir. hostPath exposes the node filesystem; docker.sock or / is full node takeover.", "CWE-668")
R_CAPS = r("K8S-DANGEROUS-CAPS", "Dangerous Linux capabilities added", H, "Drop ALL capabilities and add back only what is required (e.g. NET_BIND_SERVICE).", "CWE-250")
R_RO_FS = r("K8S-WRITABLE-ROOTFS", "Root filesystem writable", L, "Set readOnlyRootFilesystem: true and mount emptyDir where writes are needed.", "CWE-732", conf=0.6)
R_LIMITS = rule("K8S-NO-RESOURCE-LIMITS", "No CPU/memory requests or limits", M, "performance", cwe=("CWE-770", "CWE-400"), owasp=A02, frameworks=(K01,),
                fix="Set resources.requests and resources.limits so one pod cannot starve its neighbours and the scheduler can place it correctly.", confidence=0.8)
R_PROBES = rule("K8S-NO-PROBES", "No readiness/liveness probe", L, "quality", cwe="CWE-1188", owasp=A02,
                fix="Add readinessProbe (traffic) and livenessProbe (restart) so broken pods are taken out of rotation.", confidence=0.6)
R_IMAGE = r("K8S-UNPINNED-IMAGE", "Image not pinned", M, "Pin a version tag and preferably a digest; set imagePullPolicy accordingly.", "CWE-1357", owasp=A03, fw=(K01,))
R_SA_TOKEN = r("K8S-SA-TOKEN-AUTOMOUNT", "Service account token mounted by default", L, "Set automountServiceAccountToken: false unless the pod calls the Kubernetes API.", "CWE-668", owasp=A01, fw=(K02,), conf=0.6)
R_ENV_SECRET = r("K8S-SECRET-IN-ENV", "Secret value written in the manifest", H, "Reference a Secret with valueFrom.secretKeyRef, backed by an external secret store.", "CWE-798", owasp=A07, fw=(K03,))
R_SECRET_OBJ = r("K8S-SECRET-COMMITTED", "Kubernetes Secret with data committed", H, "Base64 is encoding, not encryption. Use Sealed Secrets, SOPS, or External Secrets Operator.", "CWE-312", owasp=A07, fw=(K03,))
R_SECCOMP = r("K8S-NO-SECCOMP", "No seccomp profile", L, "Set securityContext.seccompProfile.type: RuntimeDefault.", "CWE-693", conf=0.6)
R_RBAC_WILD = r("K8S-RBAC-WILDCARD", "RBAC rule grants every verb on every resource", C, "List explicit verbs and resources.", "CWE-269", owasp=A01, fw=(K02,))
R_RBAC_SECRETS = r("K8S-RBAC-SECRETS", "RBAC grants read access to Secrets", M, "Limit get/list/watch on secrets to named resources (resourceNames).", "CWE-269", owasp=A01, fw=(K02, K03), conf=0.7)
R_RBAC_ESC = r("K8S-RBAC-ESCALATE", "RBAC allows escalate/bind/impersonate or pod exec", H, "These verbs let a subject grant itself more power. Restrict them to cluster admins.", "CWE-269", owasp=A01, fw=(K02,))
R_ADMIN_BIND = r("K8S-CLUSTER-ADMIN-BINDING", "Binding to cluster-admin or anonymous users", H, "Bind narrowly scoped Roles. Never bind system:anonymous or system:unauthenticated.", "CWE-269", owasp=A01, fw=(K02, K06))
R_SVC_EXPOSED = r("K8S-SERVICE-EXPOSED", "Data service exposed outside the cluster", H, "Use ClusterIP for databases and caches, and add NetworkPolicies.", "CWE-668", owasp=A02, fw=(K05, K06))

WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "ReplicationController"}
DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "NET_RAW", "BPF", "PERFMON"}
DATA_PORTS = {3306, 5432, 27017, 6379, 9200, 11211, 1433, 5984, 9042, 7474, 9092, 2181}


def pod_spec(doc: dict[str, Any]) -> dict[str, Any] | None:
    kind = doc.get("kind")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
    return ((spec.get("template") or {}).get("spec")) if kind in WORKLOADS else None


class KubernetesScanner:
    name = "kubernetes"

    def scan(self, ctx: ScanContext) -> Iterator[Finding]:
        for rel in ctx.by_suffix(".yaml", ".yml"):
            text = ctx.text(rel)
            if not text or "apiVersion" not in text or "kind" not in text or "{{" in text:
                continue
            try:
                docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
            except yaml.YAMLError:
                continue
            lines = text.splitlines()
            for doc in docs:
                if "apiVersion" in doc and "kind" in doc:
                    yield from self.document(rel, doc, lines)

    def document(self, rel: str, doc: dict[str, Any], lines: list[str]) -> Iterator[Finding]:
        kind = str(doc.get("kind"))
        name = str((doc.get("metadata") or {}).get("name", "?"))
        where = f"{kind}/{name}"

        def ln(needle: str) -> int:
            hits = [i for i, l in enumerate(lines, 1) if needle in l]
            anchor = next((i for i, l in enumerate(lines, 1) if re.search(rf"name:\s*['\"]?{re.escape(name)}\b", l)), 1)
            after = [h for h in hits if h >= anchor]
            return after[0] if after else (hits[0] if hits else anchor)

        def F(rule_, msg, needle="", sev=None):
            f = Finding(rule_, rel, ln(needle or "kind:"), f"{where}: {msg}", snippet=needle or where, extra={"anchor": f"{where}:{rule_.id}:{needle}"})
            if sev is not None:
                f.severity = sev
            return f

        if kind == "Secret" and (doc.get("data") or doc.get("stringData")):
            yield F(R_SECRET_OBJ, "Secret values are in the repository.", "kind: Secret")
        if kind in ("Role", "ClusterRole"):
            for rule_ in doc.get("rules") or []:
                verbs = set(map(str, rule_.get("verbs") or []))
                res = set(map(str, rule_.get("resources") or []))
                if "*" in verbs and "*" in res:
                    yield F(R_RBAC_WILD, "verbs ['*'] on resources ['*'].", "verbs")
                elif "secrets" in res and verbs & {"get", "list", "watch", "*"} and not rule_.get("resourceNames"):
                    yield F(R_RBAC_SECRETS, "can read every Secret in scope.", "secrets")
                if verbs & {"escalate", "bind", "impersonate"} or ("pods/exec" in res and verbs & {"create", "*"}):
                    yield F(R_RBAC_ESC, f"verbs {sorted(verbs & {'escalate', 'bind', 'impersonate', 'create', '*'})} on {sorted(res)}.", "verbs")
        if kind in ("RoleBinding", "ClusterRoleBinding"):
            ref = str((doc.get("roleRef") or {}).get("name", ""))
            subjects = [str(s.get("name", "")) for s in doc.get("subjects") or [] if isinstance(s, dict)]
            if ref == "cluster-admin":
                yield F(R_ADMIN_BIND, f"binds cluster-admin to {subjects}.", "cluster-admin")
            if set(subjects) & {"system:anonymous", "system:unauthenticated"}:
                yield F(R_ADMIN_BIND, "binds anonymous users.", "system:", sev=Severity.CRITICAL)
        if kind == "Service" and (doc.get("spec") or {}).get("type") in ("LoadBalancer", "NodePort"):
            ports = {int(p.get("port", 0)) for p in (doc["spec"].get("ports") or []) if isinstance(p, dict) and str(p.get("port", "")).isdigit()}
            if ports & DATA_PORTS:
                yield F(R_SVC_EXPOSED, f"{doc['spec']['type']} exposes {sorted(ports & DATA_PORTS)}.", "type:")
        spec = pod_spec(doc)
        if not isinstance(spec, dict):
            return
        psc = spec.get("securityContext") or {}
        for key in ("hostNetwork", "hostPID", "hostIPC"):
            if spec.get(key) is True:
                yield F(R_HOSTNS, f"{key}: true.", key)
        for vol in spec.get("volumes") or []:
            hp = (vol or {}).get("hostPath")
            if hp:
                path = str(hp.get("path", ""))
                sev = Severity.CRITICAL if path in ("/", "/var/run/docker.sock", "/run/containerd/containerd.sock", "/etc", "/root", "/var/lib/kubelet") else None
                yield F(R_HOSTPATH, f"hostPath {path}.", "hostPath", sev=sev)
        if spec.get("automountServiceAccountToken") is not False:
            yield F(R_SA_TOKEN, "automountServiceAccountToken not false.", "spec:")
        containers = list(spec.get("containers") or []) + list(spec.get("initContainers") or [])
        for c in containers:
            if not isinstance(c, dict):
                continue
            cname = str(c.get("name", "?"))
            sc = c.get("securityContext") or {}
            cw = f"container `{cname}`"
            if sc.get("privileged") is True:
                yield F(R_PRIV, f"{cw} is privileged.", "privileged")
            if sc.get("allowPrivilegeEscalation") is not False:
                yield F(R_ESC, f"{cw} allowPrivilegeEscalation not false.", f"name: {cname}")
            non_root = sc.get("runAsNonRoot", psc.get("runAsNonRoot"))
            uid = sc.get("runAsUser", psc.get("runAsUser"))
            if uid == 0:
                yield F(R_ROOT, f"{cw} runAsUser: 0.", "runAsUser", sev=Severity.HIGH)
            elif non_root is not True and not uid:
                yield F(R_ROOT, f"{cw} runAsNonRoot not set.", f"name: {cname}")
            added = {str(x).upper() for x in ((sc.get("capabilities") or {}).get("add") or [])}
            if added & DANGEROUS_CAPS:
                yield F(R_CAPS, f"{cw} adds {sorted(added & DANGEROUS_CAPS)}.", "add:")
            if sc.get("readOnlyRootFilesystem") is not True:
                yield F(R_RO_FS, f"{cw} root filesystem writable.", f"name: {cname}")
            if not ((sc.get("seccompProfile") or psc.get("seccompProfile") or {}).get("type")):
                yield F(R_SECCOMP, f"{cw} no seccompProfile.", f"name: {cname}")
            res = c.get("resources") or {}
            if not (res.get("limits") and res.get("requests")):
                yield F(R_LIMITS, f"{cw} missing requests/limits.", f"name: {cname}")
            if kind != "Job" and kind != "CronJob" and c in (spec.get("containers") or []) and not (c.get("readinessProbe") or c.get("livenessProbe")):
                yield F(R_PROBES, f"{cw} has no probes.", f"name: {cname}")
            image = str(c.get("image", ""))
            if image and "@sha256:" not in image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
                yield F(R_IMAGE, f"{cw} image `{image}` not pinned.", image)
            for e in c.get("env") or []:
                if isinstance(e, dict) and re.search(r"(?i)password|secret|token|api_?key|private_?key", str(e.get("name", ""))) and e.get("value"):
                    yield F(R_ENV_SECRET, f"{cw} env {e.get('name')} is a literal.", str(e.get("name")))
