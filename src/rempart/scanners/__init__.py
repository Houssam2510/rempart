from rempart.scanners.ai import AIScanner
from rempart.scanners.cicd import CICDScanner
from rempart.scanners.code import CodeScanner
from rempart.scanners.containers import ContainerScanner
from rempart.scanners.data import DataScanner
from rempart.scanners.deps import DependencyScanner
from rempart.scanners.kubernetes import KubernetesScanner
from rempart.scanners.quality import QualityScanner
from rempart.scanners.secrets import SecretsScanner
from rempart.scanners.terraform import TerraformScanner

# Experimental scanners (phase 4 of the October 2026 audit) run only when asked for:
# `rempart scan --experimental`, or by name with --only. Live cloud, images and the web
# audit are separate options and commands, also marked experimental.
EXPERIMENTAL_SCANNERS = ("quality",)

ALL_SCANNERS = {
    s.name: s
    for s in (
        SecretsScanner(), CodeScanner(), DependencyScanner(), TerraformScanner(), ContainerScanner(),
        KubernetesScanner(), CICDScanner(), DataScanner(), AIScanner(), QualityScanner(),
    )
}


def scanner_names(only: str | None = None, skip: str | None = None, experimental: bool = False) -> list[str]:
    """The scanners a scan runs: the default profile, every scanner with `experimental`,
    or exactly those named in `only` (naming an experimental scanner asks for it)."""
    if only:
        names = [n.strip() for n in only.split(",") if n.strip()]
    else:
        names = [n for n in ALL_SCANNERS if experimental or n not in EXPERIMENTAL_SCANNERS]
    if skip:
        names = [n for n in names if n not in {s.strip() for s in skip.split(",")}]
    return names


def wants_experimental(names: list[str], experimental: bool = False) -> bool:
    return experimental or any(n in EXPERIMENTAL_SCANNERS for n in names)
