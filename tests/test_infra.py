import unittest

from tests.helpers import rule_ids, scan_tree

TF = '''
terraform {
  backend "s3" {
    bucket = "state"
    key    = "prod.tfstate"
  }
}

resource "aws_s3_bucket_acl" "logs" {
  bucket = aws_s3_bucket.logs.id
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{ "Effect": "Allow", "Action": "*", "Resource": "*" }]
  })
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  publicly_accessible = true
  password            = "SuperSecret123"
}

resource "aws_instance" "app" {
  ami = "ami-123"
}

resource "google_storage_bucket_iam_member" "pub" {
  member = "allUsers"
  role   = "roles/storage.objectViewer"
}

resource "azurerm_storage_account" "sa" {
  allow_nested_items_to_be_public = true
  min_tls_version                 = "TLS1_0"
}
'''

TF_SAFE = '''
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "app" {
  ami = "ami-123"
  metadata_options {
    http_tokens = "required"
  }
}
'''


class TerraformTest(unittest.TestCase):
    def test_vulnerable(self):
        ids = rule_ids(scan_tree({"main.tf": TF, "terraform.tfstate": "{}"}, ["terraform"]))
        expected = {"TF-BACKEND-UNENCRYPTED", "TF-S3-PUBLIC-ACL", "TF-NET-ADMIN-PORT-OPEN", "TF-NET-DATA-PORT-OPEN", "TF-IAM-WILDCARD",
                    "TF-DB-PUBLIC", "TF-DATA-UNENCRYPTED", "TF-HARDCODED-PASSWORD", "TF-EC2-IMDSV1", "TF-GCP-PUBLIC-MEMBER",
                    "TF-AZURE-PUBLIC-BLOB", "TF-TLS-OUTDATED", "TF-STATE-COMMITTED"}
        self.assertTrue(expected <= ids, expected - ids)

    def test_https_ingress_is_fine(self):
        ids = rule_ids(scan_tree({"main.tf": TF_SAFE}, ["terraform"]))
        self.assertFalse(ids & {"TF-NET-ADMIN-PORT-OPEN", "TF-NET-DATA-PORT-OPEN", "TF-NET-ALL-PORTS-OPEN", "TF-EC2-IMDSV1"}, ids)


class ContainerTest(unittest.TestCase):
    def test_dockerfile(self):
        ids = rule_ids(scan_tree({
            "Dockerfile": """
                FROM node:latest
                ENV API_TOKEN=abc123def456
                RUN curl -fsSL https://example.com/install.sh | bash
                RUN apt-get update && apt-get install -y git
                RUN chmod -R 777 /app
                COPY . .
                RUN npm install
                EXPOSE 22
                CMD ["node", "server.js"]
            """,
        }, ["containers"]))
        expected = {"DOCKER-UNPINNED-BASE", "DOCKER-SECRET-IN-IMAGE", "DOCKER-CURL-PIPE-SHELL", "DOCKER-IMAGE-BLOAT", "DOCKER-WORLD-WRITABLE",
                    "DOCKER-NO-DOCKERIGNORE", "DOCKER-NONREPRODUCIBLE-INSTALL", "DOCKER-SSH-EXPOSED", "DOCKER-RUNS-AS-ROOT", "DOCKER-NO-HEALTHCHECK"}
        self.assertTrue(expected <= ids, expected - ids)

    def test_good_dockerfile(self):
        res = scan_tree({
            ".dockerignore": ".git\n.env\n",
            "Dockerfile": """
                FROM node:22.11-alpine@sha256:aaaa AS build
                COPY . .
                RUN npm ci
                FROM gcr.io/distroless/nodejs22-debian12:nonroot
                COPY --from=build /app /app
                USER nonroot
                HEALTHCHECK CMD ["node", "/app/health.js"]
            """,
        }, ["containers"])
        self.assertEqual([f for f in res.findings if f.severity >= 2], [])

    def test_compose(self):
        ids = rule_ids(scan_tree({
            "docker-compose.yml": """
                services:
                  db:
                    image: mongo
                    ports: ["27017:27017"]
                    environment:
                      MONGO_INITDB_ROOT_PASSWORD: example123
                  agent:
                    image: portainer/agent:2.19.0
                    privileged: true
                    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]
                  cache:
                    image: redis:7.2
                    ports: ["127.0.0.1:6379:6379"]
            """,
        }, ["containers"]))
        self.assertTrue({"COMPOSE-DATA-PORT-PUBLISHED", "COMPOSE-SECRET-LITERAL", "COMPOSE-PRIVILEGED", "COMPOSE-DOCKER-SOCKET", "DOCKER-UNPINNED-BASE"} <= ids, ids)


class KubernetesTest(unittest.TestCase):
    def test_workload_and_rbac(self):
        ids = rule_ids(scan_tree({
            "k8s/deploy.yaml": """
                apiVersion: apps/v1
                kind: Deployment
                metadata:
                  name: api
                spec:
                  template:
                    spec:
                      hostNetwork: true
                      containers:
                        - name: api
                          image: myorg/api:latest
                          securityContext:
                            privileged: true
                            capabilities:
                              add: ["SYS_ADMIN"]
                          env:
                            - name: DB_PASSWORD
                              value: hunter2hunter2
                      volumes:
                        - name: sock
                          hostPath:
                            path: /var/run/docker.sock
                ---
                apiVersion: rbac.authorization.k8s.io/v1
                kind: ClusterRole
                metadata:
                  name: everything
                rules:
                  - apiGroups: ["*"]
                    resources: ["*"]
                    verbs: ["*"]
                ---
                apiVersion: v1
                kind: Secret
                metadata:
                  name: creds
                data:
                  password: aHVudGVyMg==
            """,
        }, ["kubernetes"]))
        expected = {"K8S-PRIVILEGED", "K8S-HOST-NAMESPACE", "K8S-HOSTPATH", "K8S-DANGEROUS-CAPS", "K8S-SECRET-IN-ENV", "K8S-UNPINNED-IMAGE",
                    "K8S-NO-RESOURCE-LIMITS", "K8S-RBAC-WILDCARD", "K8S-SECRET-COMMITTED", "K8S-RUNS-AS-ROOT"}
        self.assertTrue(expected <= ids, expected - ids)


class CICDTest(unittest.TestCase):
    def test_pwn_request_and_injection(self):
        ids = rule_ids(scan_tree({
            ".github/workflows/pr.yml": """
                on:
                  pull_request_target:
                  issues:
                permissions: write-all
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/checkout@v4
                        with:
                          ref: ${{ github.event.pull_request.head.sha }}
                      - uses: tj-actions/changed-files@v45
                      - uses: actions/cache@v4
                        with: { path: ~/.npm, key: npm }
                      - run: |
                          echo "Title: ${{ github.event.issue.title }}"
                          curl -s https://get.example.sh | bash
                      - run: echo ${{ secrets.NPM_TOKEN }} > token.txt
            """,
        }, ["cicd"]))
        expected = {"GHA-PWN-REQUEST", "GHA-WRITE-ALL", "GHA-UNPINNED-ACTION", "GHA-SCRIPT-INJECTION", "CI-CURL-PIPE-SHELL", "GHA-SECRET-ECHO", "GHA-CACHE-IN-PRIVILEGED"}
        self.assertTrue(expected <= ids, expected - ids)

    def test_hardened_workflow(self):
        res = scan_tree({
            ".github/workflows/ci.yml": """
                on: [push, pull_request]
                permissions:
                  contents: read
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
                      - env:
                          TITLE: ${{ github.event.pull_request.title }}
                        run: echo "$TITLE"
            """,
        }, ["cicd"])
        self.assertEqual(res.findings, [], [(f.rule.id, f.line) for f in res.findings])


if __name__ == "__main__":
    unittest.main()


class TerraformHclPolicyTest(unittest.TestCase):
    """Regression from dogfooding on the cspm-lite lab: jsonencode() policies use HCL keys."""

    def test_jsonencode_policies(self):
        ids = rule_ids(scan_tree({"iam.tf": '''
resource "aws_iam_policy" "wildcard" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_s3_bucket_policy" "public" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::b/*"
    }]
  })
}

resource "aws_iam_role" "scanner" {
  assume_role_policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "123456789012" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "sts:ExternalId" = "x" } }
    }]
  })
}

resource "aws_instance" "a" {
  metadata_options { http_tokens = "required" }
  root_block_device { encrypted = false }
}
'''}, ["terraform"]))
        self.assertTrue({"TF-IAM-WILDCARD", "TF-POLICY-PUBLIC-PRINCIPAL", "TF-DATA-UNENCRYPTED"} <= ids, ids)
        self.assertNotIn("TF-EC2-IMDSV1", ids)


class CICDRobustnessTest(unittest.TestCase):
    def test_invalid_yaml_still_gets_line_checks(self):
        res = scan_tree({".github/workflows/x.yml": 'on: issues\njobs:\n  a:\n    steps:\n      - uses: some/action@v1\n      - run: echo "t: ${{ github.event.issue.title }}"\n'}, ["cicd"])
        self.assertTrue({"GHA-UNPINNED-ACTION", "GHA-SCRIPT-INJECTION"} <= rule_ids(res), rule_ids(res))


class KubeLiveTest(unittest.TestCase):
    def test_live_objects_use_manifest_rules(self):
        from rempart.kube_live import audit
        items = {"items": [
            {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "api", "namespace": "prod"},
             "spec": {"template": {"spec": {"containers": [{"name": "api", "image": "org/api:latest", "securityContext": {"privileged": True}}]}}}},
            {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "api-123", "namespace": "prod", "ownerReferences": [{"kind": "ReplicaSet"}]},
             "spec": {"containers": [{"name": "api", "image": "org/api:latest"}]}},
            {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "coredns", "namespace": "kube-system"}, "spec": {"containers": [{"name": "c", "image": "x"}]}},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "ci-admin"},
             "roleRef": {"name": "cluster-admin"}, "subjects": [{"kind": "ServiceAccount", "name": "ci"}]},
        ]}
        findings = audit(items, context="prod-cluster")
        paths = {f.path for f in findings}
        self.assertIn("k8s://prod-cluster/prod/Deployment/api", paths)
        self.assertFalse(any("api-123" in p or "coredns" in p for p in paths))
        ids = {f.rule.id for f in findings}
        self.assertTrue({"K8S-PRIVILEGED", "K8S-CLUSTER-ADMIN-BINDING"} <= ids)
        self.assertTrue(all(f.verification == "observed" for f in findings))
