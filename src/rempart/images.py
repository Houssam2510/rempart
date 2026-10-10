"""Container image analysis without Docker.

`rempart image python:3.9-slim` talks to the registry over HTTPS (Docker Hub,
GHCR, any OCI registry with anonymous or token auth), streams each layer, and
rebuilds only the files that matter while honouring whiteouts. It also reads
`docker save` archives and OCI layouts from disk.

From that filesystem it extracts:
* the OS and its packages (dpkg incl. distroless status.d, apk), checked
  against OSV's Debian / Ubuntu / Alpine feeds and enriched with KEV + EPSS;
* language packages (Python dist-info, node_modules, lockfiles in the app);
* end-of-life OS releases and language runtimes;
* secrets left in files, environment variables and build history;
* image configuration problems (root user, SSH, no healthcheck, age).
"""

from __future__ import annotations

import gzip
import io
import json
import os
import re
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import IO, Iterator

from rempart.models import Finding, Severity
from rempart.netcache import USER_AGENT, NetworkError
from rempart.registry import A02, A03, A06, A07, H, L, M, I, rule
from rempart.scanners.lockfiles import Package, parser_for

R_IMG_VULN = rule("IMG-VULNERABLE-PACKAGE", "Image package with a known vulnerability", H, "image", cwe="CWE-1395", owasp=A03,
                  fix="Rebuild on a patched base image (or `apt-get upgrade` / `apk upgrade` in the build) and redeploy. Prioritise KEV-listed and high-EPSS CVEs.",
                  confidence=0.95)
R_IMG_EOL = rule("IMG-OS-EOL", "Base OS release is end-of-life", H, "image", cwe=("CWE-1104", "CWE-1395"), owasp=A06,
                 fix="Move to a supported release (Debian 12/13, Ubuntu 24.04, a current Alpine branch). EOL releases stop receiving security fixes, so new CVEs stay open forever.",
                 confidence=0.95)
R_IMG_RUNTIME_EOL = rule("IMG-RUNTIME-EOL", "Language runtime in the image is end-of-life", H, "image", cwe=("CWE-1104",), owasp=A06,
                         fix="Upgrade to a supported runtime release (see python.org/downloads and nodejs.org/about/releases).", confidence=0.9)
R_IMG_ROOT = rule("IMG-RUNS-AS-ROOT", "Image runs as root by default", M, "image", cwe="CWE-250", owasp=A02,
                  fix="Set `USER` to an unprivileged UID in the image, or runAsNonRoot in the pod spec.")
R_IMG_SECRET_ENV = rule("IMG-SECRET-IN-CONFIG", "Secret in image environment or build history", H, "image", cwe=("CWE-798", "CWE-538"), owasp=A07,
                        fix="Anyone who can pull the image can read its ENV and history. Rebuild without the value, use BuildKit secrets, and rotate it.")
R_IMG_SECRET_FILE = rule("IMG-SECRET-IN-FILE", "Secret file shipped inside the image", H, "image", cwe=("CWE-798", "CWE-538"), owasp=A07,
                         fix="Exclude it with .dockerignore or a multi-stage build, rotate the credential, and rebuild.")
R_IMG_SSH = rule("IMG-SSH-EXPOSED", "Image exposes SSH", M, "image", cwe="CWE-668", owasp=A02, fix="Remove sshd and port 22.")
R_IMG_STALE = rule("IMG-STALE", "Image has not been rebuilt in over a year", M, "image", cwe="CWE-1104", owasp=A06,
                   fix="Rebuild regularly (weekly in CI) so base-image security fixes reach production.", confidence=0.8)
R_IMG_PIPE = rule("IMG-HISTORY-REMOTE-SCRIPT", "Image built by piping a remote script into a shell", M, "image", cwe="CWE-494", owasp=A03,
                  fix="Verify downloads with a pinned checksum.")
R_IMG_NO_HEALTH = rule("IMG-NO-HEALTHCHECK", "Image has no HEALTHCHECK", L, "image", cwe="CWE-1188", fix="Add a HEALTHCHECK or pod probes.", confidence=0.5)
R_IMG_UNSUPPORTED = rule("IMG-PACKAGES-NOT-ANALYSED", "Some packages could not be analysed", I, "image",
                         fix="RPM databases, Go binaries and JARs are not parsed yet; use the --sbom output of your build tool for those.", confidence=1.0)

# Release end-of-life dates (security support end), checked against today's date.
OS_EOL = {
    ("debian", "8"): "2020-06-30", ("debian", "9"): "2022-06-30", ("debian", "10"): "2024-06-30", ("debian", "11"): "2026-08-31",
    ("debian", "12"): "2028-06-30", ("debian", "13"): "2030-06-30",
    ("ubuntu", "14.04"): "2019-04-25", ("ubuntu", "16.04"): "2021-04-30", ("ubuntu", "18.04"): "2023-05-31", ("ubuntu", "20.04"): "2025-05-31",
    ("ubuntu", "22.04"): "2027-06-01", ("ubuntu", "24.04"): "2029-05-31", ("ubuntu", "26.04"): "2031-05-31",
    ("alpine", "3.15"): "2023-11-01", ("alpine", "3.16"): "2024-05-23", ("alpine", "3.17"): "2024-11-22", ("alpine", "3.18"): "2025-05-09",
    ("alpine", "3.19"): "2025-11-01", ("alpine", "3.20"): "2026-04-01", ("alpine", "3.21"): "2026-11-01", ("alpine", "3.22"): "2027-05-01",
    ("alpine", "3.23"): "2027-11-01",
}
RUNTIME_EOL = {
    ("python", "2.7"): "2020-01-01", ("python", "3.6"): "2021-12-23", ("python", "3.7"): "2023-06-27", ("python", "3.8"): "2024-10-07",
    ("python", "3.9"): "2025-10-31", ("python", "3.10"): "2026-10-31", ("python", "3.11"): "2027-10-31", ("python", "3.12"): "2028-10-31",
    ("node", "12"): "2022-04-30", ("node", "14"): "2023-04-30", ("node", "16"): "2023-09-11", ("node", "18"): "2025-04-30",
    ("node", "20"): "2026-04-30", ("node", "22"): "2027-04-30", ("node", "24"): "2028-04-30",
}

_INTERESTING = re.compile(
    r"^(?:etc/os-release|usr/lib/os-release|var/lib/dpkg/status|var/lib/dpkg/status\.d/[^/]+|lib/apk/db/installed|var/lib/rpm/(?:rpmdb\.sqlite|Packages)"
    r"|.*/(?:site|dist)-packages/[^/]+\.dist-info/METADATA"
    r"|.*node_modules/(?:@[^/]+/)?[^/@][^/]*/package\.json"
    r"|(?!usr/(?:lib|share)/).*(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|Pipfile\.lock|requirements\.txt|go\.mod|Cargo\.lock|Gemfile\.lock|composer\.lock)"
    r"|(?:app|srv|opt|home/[^/]+|root|workspace|usr/src/app|var/www|code)/.*"
    r"|.*\.env(?:\.[\w.-]+)?|.*\.(?:pem|key|p12|pfx)|.*/\.(?:npmrc|pypirc|netrc|git-credentials)|.*/\.aws/credentials|.*/\.ssh/id_[a-z0-9]+)$"
)
_SKIP_DIRS = re.compile(r"^(?:proc|sys|dev|usr/share/(?:doc|man|locale|zoneinfo)|usr/include|etc/ssl/certs|usr/lib/ssl/certs)/")
MAX_FILE = 512_000


@dataclass
class ImageRef:
    registry: str
    repository: str
    reference: str

    @property
    def label(self) -> str:
        sep = "@" if self.reference.startswith("sha256:") else ":"
        reg = "" if self.registry == "registry-1.docker.io" else self.registry + "/"
        repo = self.repository.removeprefix("library/") if not reg else self.repository
        return f"{reg}{repo}{sep}{self.reference}"


def parse_ref(ref: str) -> ImageRef:
    name, digest = (ref.split("@", 1) + [""])[:2]
    first = name.split("/", 1)[0]
    if "/" in name and ("." in first or ":" in first or first == "localhost"):
        registry, repo = name.split("/", 1)
    else:
        registry, repo = "registry-1.docker.io", name
    tag = "latest"
    if ":" in repo.rsplit("/", 1)[-1]:
        repo, tag = repo.rsplit(":", 1)
    if registry in ("docker.io", "index.docker.io"):
        registry = "registry-1.docker.io"
    if registry == "registry-1.docker.io" and "/" not in repo:
        repo = "library/" + repo
    return ImageRef(registry, repo, digest or tag)


MANIFEST_TYPES = ", ".join([
    "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json",
])


class RegistryClient:
    def __init__(self, ref: ImageRef, timeout: int = 60) -> None:
        self.ref = ref
        self.timeout = timeout
        self.token: str | None = None
        self.base = f"https://{ref.registry}/v2/{ref.repository}"

    def _open(self, url: str, accept: str) -> IO[bytes]:
        headers = {"User-Agent": USER_AGENT, "Accept": accept}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=self.timeout)  # noqa: S310
        except urllib.error.HTTPError as exc:
            if exc.code == 401 and self.token is None:
                self._authenticate(exc.headers.get("WWW-Authenticate", ""))
                return self._open(url, accept)
            raise NetworkError(f"{url}: HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise NetworkError(f"{url}: {exc}") from exc

    def _authenticate(self, challenge: str) -> None:
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = params.pop("realm", None)
        if not realm:
            raise NetworkError(f"registry {self.ref.registry} requires unsupported auth: {challenge or 'none'}")
        params.setdefault("scope", f"repository:{self.ref.repository}:pull")
        req = urllib.request.Request(realm + "?" + urllib.parse.urlencode(params), headers={"User-Agent": USER_AGENT})
        user, pwd = os.environ.get("REMPART_REGISTRY_USER"), os.environ.get("REMPART_REGISTRY_PASSWORD")
        if user and pwd:
            import base64
            req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{pwd}".encode()).decode())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                data = json.loads(resp.read())
        except (urllib.error.URLError, ValueError, OSError) as exc:
            raise NetworkError(f"token request to {realm} failed: {exc}") from exc
        self.token = data.get("token") or data.get("access_token")

    def json(self, url: str, accept: str) -> dict:
        with self._open(url, accept) as r:
            return json.loads(r.read())

    def manifest(self, platform: str = "linux/amd64") -> dict:
        m = self.json(f"{self.base}/manifests/{self.ref.reference}", MANIFEST_TYPES)
        if "manifests" in m:  # index / manifest list
            os_, arch = (platform.split("/") + ["amd64"])[:2]
            for entry in m["manifests"]:
                p = entry.get("platform") or {}
                if p.get("os") == os_ and p.get("architecture") == arch:
                    return self.json(f"{self.base}/manifests/{entry['digest']}", MANIFEST_TYPES)
            raise NetworkError(f"no {platform} image in {self.ref.label}")
        return m

    def blob(self, digest: str) -> IO[bytes]:
        return self._open(f"{self.base}/blobs/{digest}", "*/*")


@dataclass
class ImageFS:
    files: dict[str, bytes] = field(default_factory=dict)
    skipped_layers: list[str] = field(default_factory=list)

    def apply_layer(self, fileobj: IO[bytes], media_type: str = "") -> None:
        raw = fileobj
        if "zstd" in media_type:
            try:
                from compression import zstd  # type: ignore[import-not-found]  # Python 3.14+
            except ImportError:
                self.skipped_layers.append(media_type)
                return
            raw = zstd.ZstdFile(fileobj)
        mode = "r|gz" if "gzip" in media_type else "r|*"
        with tarfile.open(fileobj=raw, mode=mode) as tar:
            for member in tar:
                path = member.name.lstrip("./").lstrip("/")
                base = os.path.basename(path)
                parent = os.path.dirname(path)
                if base == ".wh..wh..opq":
                    prefix = parent + "/"
                    for k in [k for k in self.files if k.startswith(prefix)]:
                        del self.files[k]
                    continue
                if base.startswith(".wh."):
                    target = os.path.join(parent, base[4:])
                    for k in [k for k in self.files if k == target or k.startswith(target + "/")]:
                        del self.files[k]
                    continue
                if member.isfile() and not _SKIP_DIRS.match(path) and member.size <= MAX_ARTIFACT:
                    special = _special_artifact(path, member, tar)
                    if special is not None:
                        if special:
                            self.files[path + SYNTH] = special
                        else:
                            self.files.pop(path + SYNTH, None)
                        continue
                if not member.isfile() or member.size > MAX_FILE or _SKIP_DIRS.match(path) or not _INTERESTING.match(path):
                    continue
                f = tar.extractfile(member)
                if f is not None:
                    self.files[path] = f.read()

    def text(self, path: str) -> str:
        return self.files.get(path, b"").decode("utf-8", "replace")


SYNTH = "#packages"  # synthetic file: package list extracted from a binary artifact
MAX_ARTIFACT = 200_000_000
_GO_MAGIC = b"\xff Go buildinf:"
_GO_DEP = re.compile(rb"(?m)^(mod|dep|=>)\t([^\t\n]+)\t(v[^\t\n]+)")


def _special_artifact(path: str, member: tarfile.TarInfo, tar: tarfile.TarFile) -> bytes | None:
    """Binary artifacts too large to keep: read once, keep only their package list.
    Returns None when the file is not one of them, b"" when it is but holds nothing."""
    base = os.path.basename(path)
    if path.startswith("var/lib/rpm/") and base == "rpmdb.sqlite":
        data = _read(tar, member)
        return "\n".join(f"rpm\t{n}\t{v}" for n, v in rpm_sqlite_packages(data)).encode() if data else b""
    if base.endswith((".jar", ".war", ".ear")):
        data = _read(tar, member)
        return "\n".join(f"maven\t{n}\t{v}" for n, v in jar_packages(data)).encode() if data else b""
    if member.mode & 0o111 and member.size > 300_000 and not base.endswith((".so", ".a")) and ".so." not in base \
            and not path.startswith(("usr/lib/", "lib/", "usr/libexec/", "usr/share/")):
        data = _read(tar, member)
        if data and _GO_MAGIC in data:
            return "\n".join(f"go\t{n}\t{v}" for n, v in go_buildinfo(data)).encode()
        return None
    return None


def _read(tar: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    f = tar.extractfile(member)
    return f.read() if f is not None else b""


def go_buildinfo(data: bytes) -> list[tuple[str, str]]:
    """Modules compiled into a Go binary (the text `go version -m` prints), plus the toolchain as `stdlib`."""
    out: list[tuple[str, str]] = []
    i = data.find(_GO_MAGIC)
    if i >= 0 and len(data) > i + 33 and data[i + 15] & 0x2:
        n, shift, pos = 0, 0, i + 32
        while pos < len(data):
            b = data[pos]
            n |= (b & 0x7F) << shift
            pos += 1
            shift += 7
            if not b & 0x80:
                break
        version = data[pos:pos + n].decode("ascii", "replace")
        if re.fullmatch(r"go1\.\d+(?:\.\d+)?", version):
            out.append(("stdlib", "v" + version[2:]))
    replaced: dict[str, tuple[str, str]] = {}
    last = ""
    for kind, mod, ver in _GO_DEP.findall(data):
        name, version = mod.decode("utf-8", "replace"), ver.decode("utf-8", "replace")
        if kind == b"=>" and last:
            replaced[last] = (name, version)
        else:
            last = name
            if kind == b"dep":
                out.append((name, version))
    return [replaced.get(n, (n, v)) for n, v in out]


def jar_packages(data: bytes, depth: int = 0) -> list[tuple[str, str]]:
    """Maven coordinates from pom.properties, including jars nested in Spring Boot / WAR archives."""
    import io
    import zipfile

    out: list[tuple[str, str]] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError, OSError):
        return out
    with zf:
        for info in zf.infolist():
            name = info.filename
            if name.startswith("META-INF/maven/") and name.endswith("/pom.properties") and info.file_size < 100_000:
                props = dict(re.findall(r"(?m)^\s*(groupId|artifactId|version)\s*=\s*(\S+)", zf.read(info).decode("utf-8", "replace")))
                if {"groupId", "artifactId", "version"} <= props.keys():
                    out.append((f"{props['groupId']}:{props['artifactId']}", props["version"]))
            elif depth == 0 and name.endswith(".jar") and info.file_size < 60_000_000:
                out += jar_packages(zf.read(info), depth + 1)
    return out


def rpm_sqlite_packages(data: bytes) -> list[tuple[str, str]]:
    """(source package, [epoch:]version-release) from an rpmdb.sqlite (Fedora 33+, RHEL/Rocky/Alma 9, Amazon Linux 2023)."""
    import sqlite3
    import struct
    import tempfile

    out: list[tuple[str, str]] = []
    with tempfile.NamedTemporaryFile(suffix=".sqlite") as tmp:
        tmp.write(data)
        tmp.flush()
        try:
            con = sqlite3.connect(f"file:{tmp.name}?mode=ro", uri=True)
            rows = con.execute("SELECT blob FROM Packages").fetchall()
            con.close()
        except sqlite3.Error:
            return out
    for (blob,) in rows:
        try:
            il, dl = struct.unpack(">ii", blob[:8])
            store = 8 + 16 * il
            tags: dict[int, object] = {}
            for k in range(il):
                tag, typ, off, cnt = struct.unpack(">iiii", blob[8 + 16 * k: 24 + 16 * k])
                if tag in (1000, 1001, 1002, 1044) and typ == 6:
                    end = blob.index(b"\0", store + off)
                    tags[tag] = blob[store + off:end].decode("utf-8", "replace")
                elif tag == 1003 and typ == 4:
                    tags[tag] = struct.unpack(">i", blob[store + off: store + off + 4])[0]
        except (struct.error, ValueError):
            continue
        if 1000 in tags and 1001 in tags and tags[1000] != "gpg-pubkey":
            ver = f"{tags[1001]}-{tags.get(1002, '')}".rstrip("-")
            if tags.get(1003):
                ver = f"{tags[1003]}:{ver}"
            # advisories name the source package (openssl), not the binary one (openssl-libs)
            src = re.match(r"(.+)-[^-]+-[^-]+\.(?:no)?src\.rpm$", str(tags.get(1044, "")))
            name = src.group(1) if src else str(tags[1000])
            if (name, ver) not in out:
                out.append((name, ver))
    return out


def pull(ref: ImageRef, platform: str = "linux/amd64", max_bytes: int = 3_000_000_000) -> tuple[dict, ImageFS]:
    client = RegistryClient(ref)
    manifest = client.manifest(platform)
    with client.blob(manifest["config"]["digest"]) as r:
        config = json.loads(r.read())
    total = sum(int(layer.get("size", 0)) for layer in manifest.get("layers", []))
    if total > max_bytes:
        raise NetworkError(f"image layers total {total // 1_000_000} MB, above the {max_bytes // 1_000_000} MB limit (--max-mb)")
    fs = ImageFS()
    for layer in manifest.get("layers", []):
        with client.blob(layer["digest"]) as stream:
            fs.apply_layer(stream, layer.get("mediaType", ""))
    return config, fs


def load_archive(path: str) -> tuple[dict, ImageFS]:
    """`docker save` archive or OCI image layout (directory or tar)."""
    fs = ImageFS()
    with tarfile.open(path) as outer:
        names = set(outer.getnames())

        def read(name: str) -> bytes:
            f = outer.extractfile(name)
            if f is None:
                raise ValueError(f"{name} missing from {path}")
            return f.read()

        if "manifest.json" in names:
            m = json.loads(read("manifest.json"))[0]
            config = json.loads(read(m["Config"]))
            layer_names = m["Layers"]
            media = [""] * len(layer_names)
        elif "index.json" in names:
            idx = json.loads(read("index.json"))
            mdesc = idx["manifests"][0]
            manifest = json.loads(read("blobs/" + mdesc["digest"].replace(":", "/")))
            if "manifests" in manifest:
                manifest = json.loads(read("blobs/" + manifest["manifests"][0]["digest"].replace(":", "/")))
            config = json.loads(read("blobs/" + manifest["config"]["digest"].replace(":", "/")))
            layer_names = ["blobs/" + layer["digest"].replace(":", "/") for layer in manifest["layers"]]
            media = [layer.get("mediaType", "") for layer in manifest["layers"]]
        else:
            raise ValueError(f"{path} is neither a docker-save archive nor an OCI layout")
        for name, mt in zip(layer_names, media):
            data = read(name)
            if data[:2] == b"\x1f\x8b":
                mt = mt or "gzip"
            fs.apply_layer(io.BytesIO(data), mt)
    return config, fs


# ---------------------------------------------------------------- package extraction

def os_release(fs: ImageFS) -> dict[str, str]:
    text = fs.text("etc/os-release") or fs.text("usr/lib/os-release")
    return {k: v.strip('"') for k, v in re.findall(r"^([A-Z_]+)=(.*)$", text, re.M)}


def osv_ecosystem(osr: dict[str, str]) -> str | None:
    distro, ver = osr.get("ID", ""), osr.get("VERSION_ID", "")
    if distro == "debian" and ver:
        return f"Debian:{ver.split('.')[0]}"
    if distro == "ubuntu" and ver:
        return f"Ubuntu:{ver}:LTS" if ver.split(".")[0].isdigit() and int(ver.split(".")[0]) % 2 == 0 and ver.endswith(".04") else f"Ubuntu:{ver}"
    if distro == "alpine" and ver:
        return "Alpine:v" + ".".join(ver.split(".")[:2])
    if distro == "rocky" and ver:
        return f"Rocky Linux:{ver.split('.')[0]}"
    if distro == "almalinux" and ver:
        return f"AlmaLinux:{ver.split('.')[0]}"
    return None


def _dpkg_records(text: str) -> Iterator[dict[str, str]]:
    for block in text.split("\n\n"):
        rec: dict[str, str] = {}
        for line in block.splitlines():
            if ":" in line and not line.startswith(" "):
                k, _, v = line.partition(":")
                rec[k.strip()] = v.strip()
        if rec.get("Package") and rec.get("Version") and "installed" in rec.get("Status", "install ok installed"):
            yield rec


def os_packages(fs: ImageFS, label: str, eco: str | None) -> list[Package]:
    if not eco:
        return []
    pkgs: dict[tuple[str, str], Package] = {}
    if eco.startswith(("Debian", "Ubuntu")):
        texts = [("var/lib/dpkg/status", fs.text("var/lib/dpkg/status"))]
        texts += [(p, fs.text(p)) for p in fs.files if p.startswith("var/lib/dpkg/status.d/") and not p.endswith(".md5sums")]
        for path, text in texts:
            for rec in _dpkg_records(text):
                src = rec.get("Source", rec["Package"])
                m = re.match(r"(\S+)(?:\s+\((\S+)\))?", src)
                name = m.group(1) if m else rec["Package"]
                version = (m.group(2) if m and m.group(2) else rec["Version"])
                pkgs.setdefault((name, version), Package(eco, name, version, f"{label} [{path}]", 0))
    elif eco.startswith(("Rocky Linux", "AlmaLinux")):
        for line in fs.text("var/lib/rpm/rpmdb.sqlite" + SYNTH).splitlines():
            _, name, version = line.split("\t")
            pkgs.setdefault((name, version), Package(eco, name, version, f"{label} [var/lib/rpm]", 0))
    elif eco.startswith("Alpine"):
        for block in fs.text("lib/apk/db/installed").split("\n\n"):
            fields = dict(line.split(":", 1) for line in block.splitlines() if len(line) > 2 and line[1] == ":")
            name, version = fields.get("o") or fields.get("P"), fields.get("V")
            if name and version:
                pkgs.setdefault((name, version), Package(eco, name, version, f"{label} [lib/apk/db/installed]", 0))
    return list(pkgs.values())


def language_packages(fs: ImageFS, label: str) -> list[Package]:
    pkgs: dict[tuple[str, str, str], Package] = {}
    for path, data in fs.files.items():
        if path.endswith(".dist-info/METADATA"):
            text = data.decode("utf-8", "replace")
            name = re.search(r"^Name:\s*(\S+)", text, re.M)
            ver = re.search(r"^Version:\s*(\S+)", text, re.M)
            if name and ver:
                pkgs.setdefault(("PyPI", name.group(1).lower(), ver.group(1)), Package("PyPI", name.group(1), ver.group(1), f"{label} [{path}]", 0))
        elif "node_modules/" in path and path.endswith("/package.json"):
            try:
                meta = json.loads(data)
            except ValueError:
                continue
            if isinstance(meta, dict) and meta.get("name") and meta.get("version"):
                pkgs.setdefault(("npm", meta["name"], meta["version"]), Package("npm", meta["name"], meta["version"], f"{label} [{path}]", 0))
        elif path.endswith(SYNTH):
            for line in data.decode("utf-8", "replace").splitlines():
                kind, name, version = (line.split("\t") + ["", "", ""])[:3]
                eco = {"go": "Go", "maven": "Maven"}.get(kind)
                if eco and name and version:
                    pkgs.setdefault((eco, name, version), Package(eco, name, version, f"{label} [{path[:-len(SYNTH)]}]", 0))
        else:
            parser = parser_for(os.path.basename(path))
            if parser is not None and not path.startswith("usr/"):
                try:
                    for p in parser(f"{label} [{path}]", data.decode("utf-8", "replace")):
                        pkgs.setdefault((p.ecosystem, p.name, p.version), p)
                except (ValueError, KeyError, TypeError):
                    continue
    return list(pkgs.values())


def _calibrate_os_vuln(f: Finding, today: date) -> None:
    """Distributions leave some CVEs unfixed on purpose (disputed, negligible, or
    mitigated by hardening). Without the distro's own priority in OSV, the
    objective signal is: no fixed package in this release and the CVE is more
    than three years old. Those are kept but ranked LOW, unless exploited (KEV)."""
    if f.extra.get("fixed"):
        return
    f.message += " — no fixed package in this release yet"
    published = str(f.extra.get("published") or "")
    try:
        old = published and (today - date.fromisoformat(published)).days > 3 * 365
    except ValueError:
        old = False
    if old and not f.extra.get("kev"):
        f.severity = Severity.LOW
        f.confidence = 0.5
        f.message += f" (unfixed since {published[:4]}: usually disputed or minor for this distribution)"


def _eol(table: dict[tuple[str, str], str], key: tuple[str, str], today: date) -> str | None:
    d = table.get(key)
    return d if d and date.fromisoformat(d) < today else None


# ---------------------------------------------------------------- analysis

def analyze(config: dict, fs: ImageFS, label: str, *, offline: bool = False, today: date | None = None) -> tuple[list[Finding], dict[str, object]]:
    from rempart.scanners.deps import DependencyScanner
    from rempart.scanners.secrets import SecretsScanner

    today = today or datetime.now(timezone.utc).date()
    out: list[Finding] = []
    cfg = config.get("config") or {}

    def F(r, msg, snippet="", where=label, sev=None):
        f = Finding(r, where, 0, msg, snippet=snippet, extra={"anchor": f"{label}:{r.id}:{snippet[:60]}"})
        f.verification = "observed"
        if sev is not None:
            f.severity = sev
        out.append(f)
        return f

    osr = os_release(fs)
    eco = osv_ecosystem(osr)
    distro, ver = osr.get("ID", "?"), osr.get("VERSION_ID", "")
    key_ver = ".".join(ver.split(".")[:2]) if distro in ("alpine", "ubuntu") else ver.split(".")[0]
    end = _eol(OS_EOL, (distro, key_ver), today)
    if end:
        F(R_IMG_EOL, f"{osr.get('PRETTY_NAME', distro + ' ' + ver)} reached end-of-life on {end}.", snippet=f"{distro} {ver}")
    env = {e.split("=", 1)[0]: e.split("=", 1)[1] for e in cfg.get("Env") or [] if "=" in e}
    for runtime, var in (("python", "PYTHON_VERSION"), ("node", "NODE_VERSION")):
        v = env.get(var, "")
        if v:
            k = ".".join(v.split(".")[:2]) if runtime == "python" else v.split(".")[0]
            end = _eol(RUNTIME_EOL, (runtime, k), today)
            if end:
                F(R_IMG_RUNTIME_EOL, f"{runtime} {v} reached end-of-life on {end}.", snippet=f"{runtime} {v}")
    for k, v in env.items():
        if re.search(r"(?i)password|secret|token|api_?key|access_?key|private_?key", k) and v and not v.startswith("$") and len(v) >= 6 \
                and not re.search(r"(?i)_(?:file|path|url|dir|version)$", k):
            F(R_IMG_SECRET_ENV, f"ENV {k} holds a literal value.", snippet=f"ENV {k}=****")
    for h in config.get("history") or []:
        cmd = str(h.get("created_by", ""))
        if re.search(r"(?i)\b(?:password|secret|token|api_?key)\w*=[^\s$]{6,}", cmd):
            F(R_IMG_SECRET_ENV, "A build argument with a secret-like name is recorded in the image history.", snippet=re.sub(r"=\S+", "=****", cmd)[:160])
        if re.search(r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", cmd):
            F(R_IMG_PIPE, "Remote script piped into a shell during the build.", snippet=cmd[:160])
    user = str(cfg.get("User") or "")
    if user in ("", "root", "0", "0:0"):
        F(R_IMG_ROOT, "No non-root USER is configured.", snippet=f"User={user or '(empty)'}")
    if "22/tcp" in (cfg.get("ExposedPorts") or {}):
        F(R_IMG_SSH, "Port 22 is exposed.", snippet="22/tcp")
    if not cfg.get("Healthcheck"):
        F(R_IMG_NO_HEALTH, "No HEALTHCHECK in the image config.", snippet="Healthcheck (none)")
    created = str(config.get("created", ""))[:10]
    try:
        age = (today - date.fromisoformat(created)).days if created else None
    except ValueError:
        age = None
    if age is not None and age > 365 and not created.startswith("1970"):
        F(R_IMG_STALE, f"Built {age} days ago ({created}).", snippet=created)
    if any(p.startswith("var/lib/rpm/") for p in fs.files) and not (eco or "").startswith(("Rocky Linux", "AlmaLinux")):
        F(R_IMG_UNSUPPORTED, f"RPM-based image ({distro} {ver}): OS packages are listed but OSV has no advisories feed for it; "
                             "language packages and Go/Java binaries are still checked.", snippet="rpm")
    if fs.skipped_layers:
        F(R_IMG_UNSUPPORTED, f"{len(fs.skipped_layers)} zstd layer(s) skipped: needs Python 3.14+.", snippet="zstd")

    # secrets in application files
    secrets = SecretsScanner()
    for path in sorted(fs.files):
        if path.startswith(("usr/lib/", "usr/share/", "var/lib/dpkg", "lib/apk")) or "node_modules/" in path or "-packages/" in path:
            continue
        text = fs.text(path)
        base = os.path.basename(path)
        if re.fullmatch(r"\.env(?:\.(?!example|sample|template)[\w.-]+)?", base) and re.search(r"^\s*[A-Z0-9_]+\s*=\s*\S{6,}", text, re.M):
            F(R_IMG_SECRET_FILE, f"{path} with values is baked into the image.", snippet=path, where=f"{label} [{path}]")
        if re.search(r"(?:^|/)(?:id_rsa|id_ed25519|id_ecdsa|\.git-credentials|credentials|\.npmrc|\.pypirc|\.netrc)$|\.(?:pem|key|p12|pfx)$", path) and \
                ("PRIVATE KEY" in text or "_authToken" in text or "aws_secret_access_key" in text or "password" in text.lower()):
            F(R_IMG_SECRET_FILE, f"Credential file {path} is in the image.", snippet=path, where=f"{label} [{path}]")
        for f in secrets._scan_text(_FSContext(fs), path):  # noqa: SLF001 - reuse the detectors
            f.path = f"{label} [{path}]"
            f.verification = "observed"
            out.append(f)

    # packages
    packages = os_packages(fs, label, eco) + language_packages(fs, label)
    meta: dict[str, object] = {"os": osr.get("PRETTY_NAME", distro), "ecosystem": eco, "packages": len(packages)}
    if packages and not offline:
        try:
            for f in DependencyScanner().vulnerabilities(packages):
                if f.extra.get("ecosystem", "").split(":")[0] in ("Debian", "Ubuntu", "Alpine"):
                    f.rule = R_IMG_VULN
                    _calibrate_os_vuln(f, today)
                f.verification = "observed"
                out.append(f)
        except NetworkError as exc:
            F(R_IMG_UNSUPPORTED, f"Vulnerability lookup failed: {exc}", snippet="osv")
    elif packages:
        F(R_IMG_UNSUPPORTED, f"{len(packages)} packages not checked (offline mode).", snippet="offline")
    return out, meta


class _FSContext:
    """Minimal ScanContext stand-in so the secrets detectors can read image files."""

    def __init__(self, fs: ImageFS) -> None:
        self.fs = fs

    def text(self, rel: str) -> str | None:
        return self.fs.text(rel)


def scan_image(target: str, *, platform: str = "linux/amd64", offline: bool = False, max_mb: int = 3000) -> tuple[list[Finding], dict[str, object]]:
    looks_like_file = target.endswith((".tar", ".tar.gz", ".tgz", ".oci")) or target.startswith(("/", "./", "../", "~"))
    if looks_like_file and not os.path.exists(os.path.expanduser(target)):
        raise ValueError(f"{target}: no such file (for a registry image, pass a reference like python:3.12-slim)")
    if os.path.exists(os.path.expanduser(target)):
        target = os.path.expanduser(target)
        config, fs = load_archive(target)
        label = os.path.basename(target)
    else:
        ref = parse_ref(target)
        config, fs = pull(ref, platform, max_mb * 1_000_000)
        label = ref.label
    findings, meta = analyze(config, fs, label, offline=offline)
    meta.update(label=label, files_kept=len(fs.files), created=config.get("created"), user=(config.get("config") or {}).get("User") or "root")
    return findings, meta
