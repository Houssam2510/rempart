import io
import json
import tarfile
import tempfile
import unittest
from datetime import date
from pathlib import Path

from tests.helpers import FAKE_AWS_KEY

from rempart.images import ImageFS, analyze, load_archive, os_packages, osv_ecosystem, os_release, parse_ref


def _layer(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


DPKG = b"""Package: libssl3
Status: install ok installed
Source: openssl (3.0.11-1~deb11u1)
Version: 3.0.11-1~deb11u1+b1

Package: bash
Status: install ok installed
Version: 5.1-2

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0
"""


def docker_save(layers: list[dict[str, bytes]], config: dict) -> str:
    path = Path(tempfile.mkdtemp()) / "image.tar"
    with tarfile.open(path, "w") as out:
        def add(name: str, data: bytes) -> None:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            out.addfile(info, io.BytesIO(data))
        names = []
        for i, files in enumerate(layers):
            names.append(f"layer{i}/layer.tar")
            add(names[-1], _layer(files))
        add("config.json", json.dumps(config).encode())
        add("manifest.json", json.dumps([{"Config": "config.json", "Layers": names, "RepoTags": ["demo:1"]}]).encode())
    return str(path)


class ImageTest(unittest.TestCase):
    def test_archive_analysis_offline(self):
        config = {
            "created": "2023-01-01T00:00:00Z",
            "config": {"User": "", "Env": ["PYTHON_VERSION=3.8.18", "API_TOKEN=abcdef123456", "PATH=/usr/bin"], "ExposedPorts": {"22/tcp": {}}},
            "history": [{"created_by": "RUN curl -fsSL https://get.example.sh | sh"}],
        }
        layers = [
            {"etc/os-release": b'ID=debian\nVERSION_ID="11"\nPRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\n',
             "var/lib/dpkg/status": DPKG,
             "app/.env": b"DATABASE_URL=postgres://x\nSECRET=abcdefgh1234\n",
             "app/old.key": b"-----BEGIN " + b"PRIVATE KEY-----\n"},
            {"app/.wh.old.key": b"",
             "app/config.js": f'const k = "{FAKE_AWS_KEY}";\n'.encode(),
             "usr/local/lib/python3.8/site-packages/requests-2.19.0.dist-info/METADATA": b"Name: requests\nVersion: 2.19.0\n"},
        ]
        cfg, fs = load_archive(docker_save(layers, config))
        self.assertNotIn("app/old.key", fs.files)  # whiteout honoured
        findings, meta = analyze(cfg, fs, "demo:1", offline=True, today=date(2026, 10, 8))
        ids = {f.rule.id for f in findings}
        expected = {"IMG-OS-EOL", "IMG-RUNTIME-EOL", "IMG-RUNS-AS-ROOT", "IMG-SECRET-IN-CONFIG", "IMG-SSH-EXPOSED",
                    "IMG-STALE", "IMG-HISTORY-REMOTE-SCRIPT", "IMG-SECRET-IN-FILE", "SEC-AWS-ACCESS-KEY", "IMG-PACKAGES-NOT-ANALYSED"}
        self.assertTrue(expected <= ids, expected - ids)
        self.assertEqual(meta["packages"], 3)  # openssl (source) + bash + requests; removed-pkg ignored
        self.assertTrue(all(f.verification == "observed" for f in findings))

    def test_os_detection_and_packages(self):
        fs = ImageFS(files={"etc/os-release": b'ID=ubuntu\nVERSION_ID="22.04"\n', "var/lib/dpkg/status": DPKG})
        self.assertEqual(osv_ecosystem(os_release(fs)), "Ubuntu:22.04:LTS")
        pkgs = {(p.name, p.version) for p in os_packages(fs, "x", "Ubuntu:22.04:LTS")}
        self.assertIn(("openssl", "3.0.11-1~deb11u1"), pkgs)
        self.assertEqual(osv_ecosystem({"ID": "alpine", "VERSION_ID": "3.20.3"}), "Alpine:v3.20")
        self.assertEqual(osv_ecosystem({"ID": "debian", "VERSION_ID": "12"}), "Debian:12")

    def test_distroless_status_d(self):
        fs = ImageFS(files={"etc/os-release": b'ID=debian\nVERSION_ID="12"\n',
                            "var/lib/dpkg/status.d/libc6": b"Package: libc6\nSource: glibc\nVersion: 2.36-9+deb12u4\n"})
        self.assertEqual({(p.name, p.version) for p in os_packages(fs, "x", "Debian:12")}, {("glibc", "2.36-9+deb12u4")})

    def test_parse_ref(self):
        r = parse_ref("python:3.12-slim")
        self.assertEqual((r.registry, r.repository, r.reference), ("registry-1.docker.io", "library/python", "3.12-slim"))
        r = parse_ref("ghcr.io/org/app@sha256:abc")
        self.assertEqual((r.registry, r.repository, r.reference), ("ghcr.io", "org/app", "sha256:abc"))
        self.assertEqual(parse_ref("bitnami/redis").label, "bitnami/redis:latest")
        r = parse_ref("localhost:5000/team/api:v1")
        self.assertEqual((r.registry, r.repository, r.reference), ("localhost:5000", "team/api", "v1"))


if __name__ == "__main__":
    unittest.main()


class ImageCLITest(unittest.TestCase):
    def test_cli_on_archive(self):
        import contextlib
        import io as _io
        from rempart.cli import main
        path = docker_save([{"etc/os-release": b'ID=alpine\nVERSION_ID=3.18.4\n', "lib/apk/db/installed": b"P:musl\nV:1.2.4-r1\no:musl\n\n"}],
                           {"created": "2026-09-01T00:00:00Z", "config": {"User": "app"}})
        buf = _io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["image", path, "--offline", "--fail-on", "high"])
        self.assertEqual(code, 1)  # Alpine 3.18 is EOL
        self.assertIn("alpine 3.18.4 reached end-of-life", buf.getvalue())
