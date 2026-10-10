import io
import sqlite3
import struct
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from rempart.images import ImageFS, go_buildinfo, jar_packages, language_packages, os_packages, rpm_sqlite_packages


def go_binary() -> bytes:
    header = b"\xff Go buildinf:" + bytes([8, 0x2]) + b"\0" * 16
    version = b"go1.21.3"
    modinfo = (b"0w\xaf\x0c\x92t\x08\x02A\xe1\xc1\x07\xe6\xd6\x18\xe6path\texample.com/app\nmod\texample.com/app\t(devel)\t\n"
               b"dep\tgolang.org/x/net\tv0.17.0\th1:abc=\ndep\tgithub.com/old/lib\tv1.0.0\th1:def=\n=>\tgithub.com/new/lib\tv1.2.0\th1:ghi=\n")
    return b"\x7fELF" + b"\0" * 400_000 + header + bytes([len(version)]) + version + bytes([len(modinfo)]) + modinfo


def jar(nested: bool = True) -> bytes:
    def make(entries: dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for n, d in entries.items():
                z.writestr(n, d)
        return buf.getvalue()

    inner = make({"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties": b"groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n"})
    return make({"META-INF/maven/com.acme/app/pom.properties": b"groupId=com.acme\nartifactId=app\nversion=1.0.0\n",
                 **({"BOOT-INF/lib/log4j-core-2.14.1.jar": inner} if nested else {})})


def rpm_header(name: str, version: str, release: str, epoch: int | None = None, source: str = "") -> bytes:
    entries, store = [], b""
    for tag, value in ((1000, name), (1001, version), (1002, release), (1044, source or f"{name}-{version}-{release}.src.rpm")):
        entries.append(struct.pack(">iiii", tag, 6, len(store), 1))
        store += value.encode() + b"\0"
    if epoch is not None:
        while len(store) % 4:
            store += b"\0"
        entries.append(struct.pack(">iiii", 1003, 4, len(store), 1))
        store += struct.pack(">i", epoch)
    return struct.pack(">ii", len(entries), len(store)) + b"".join(entries) + store


def rpmdb() -> bytes:
    path = Path(tempfile.mkdtemp()) / "rpmdb.sqlite"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)")
    for blob in (rpm_header("openssl-libs", "3.0.7", "24.el9", 1, "openssl-3.0.7-24.el9.src.rpm"), rpm_header("bash", "5.1.8", "6.el9"), rpm_header("gpg-pubkey", "x", "y")):
        con.execute("INSERT INTO Packages (blob) VALUES (?)", (blob,))
    con.commit()
    con.close()
    return path.read_bytes()


class ArtifactTest(unittest.TestCase):
    def test_go_buildinfo(self) -> None:
        self.assertEqual(go_buildinfo(go_binary()), [("stdlib", "v1.21.3"), ("golang.org/x/net", "v0.17.0"), ("github.com/new/lib", "v1.2.0")])

    def test_nested_jars(self) -> None:
        self.assertEqual(sorted(jar_packages(jar())), [("com.acme:app", "1.0.0"), ("org.apache.logging.log4j:log4j-core", "2.14.1")])

    def test_rpmdb(self) -> None:
        self.assertEqual(rpm_sqlite_packages(rpmdb()), [("openssl", "1:3.0.7-24.el9"), ("bash", "5.1.8-6.el9")])

    def test_layer_extraction_end_to_end(self) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            for name, data, mode in (("usr/local/bin/server", go_binary(), 0o755), ("app/app.jar", jar(), 0o644),
                                     ("var/lib/rpm/rpmdb.sqlite", rpmdb(), 0o644),
                                     ("etc/os-release", b'ID="rocky"\nVERSION_ID="9.3"\n', 0o644)):
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), mode
                t.addfile(info, io.BytesIO(data))
        buf.seek(0)
        fs = ImageFS()
        fs.apply_layer(buf)
        langs = {(p.ecosystem, p.name, p.version) for p in language_packages(fs, "demo")}
        self.assertIn(("Go", "golang.org/x/net", "v0.17.0"), langs)
        self.assertIn(("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"), langs)
        osp = {(p.ecosystem, p.name, p.version) for p in os_packages(fs, "demo", "Rocky Linux:9")}
        self.assertIn(("Rocky Linux:9", "openssl", "1:3.0.7-24.el9"), osp)


if __name__ == "__main__":
    unittest.main()
