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

ALL_SCANNERS = {
    s.name: s
    for s in (
        SecretsScanner(), CodeScanner(), DependencyScanner(), TerraformScanner(), ContainerScanner(),
        KubernetesScanner(), CICDScanner(), DataScanner(), AIScanner(), QualityScanner(),
    )
}
