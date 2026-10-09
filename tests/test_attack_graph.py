import unittest

from rempart.models import Severity
from tests.helpers import scan_tree

APP = '''
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/run")
def run():
    subprocess.run("convert " + request.args["f"], shell=True)
    return "ok"
'''


def chains(result, rule_id: str) -> list:
    return [f for f in result.findings if f.rule.id == rule_id]


class AttackGraphTest(unittest.TestCase):
    def test_rce_in_service_that_mounts_docker_socket_is_linked(self) -> None:
        result = scan_tree({
            "api/app.py": APP,
            "api/Dockerfile": "FROM python:3.12-slim\nUSER app\n",
            "docker-compose.yml": '''
                services:
                  api:
                    build: ./api
                    volumes:
                      - /var/run/docker.sock:/var/run/docker.sock
            ''',
        })
        found = chains(result, "CHAIN-RCE-TO-HOST")
        self.assertTrue(found)
        self.assertEqual(found[0].verification, "linked")
        self.assertEqual(found[0].severity, Severity.CRITICAL)
        self.assertIn("api", " ".join(found[0].extra["route"]))

    def test_unrelated_services_are_only_co_occurrence(self) -> None:
        result = scan_tree({
            "api/app.py": APP,
            "api/Dockerfile": "FROM python:3.12-slim\nUSER app\n",
            "ops/docker-compose.yml": '''
                services:
                  agent:
                    image: portainer/agent:2.19.4
                    network_mode: host
                    volumes:
                      - /var/run/docker.sock:/var/run/docker.sock
            ''',
        })
        found = chains(result, "CHAIN-RCE-TO-HOST")
        self.assertTrue(found)
        self.assertEqual(found[0].verification, "co-occurrence")
        self.assertEqual(found[0].severity, Severity.HIGH)

    def test_terraform_references_link_admin_policy_to_imdsv1_instance(self) -> None:
        result = scan_tree({"main.tf": '''
            resource "aws_iam_role" "app" {
              name = "app"
              assume_role_policy = "{}"
            }

            resource "aws_iam_role_policy" "admin" {
              role = aws_iam_role.app.id
              policy = jsonencode({
                Version = "2012-10-17"
                Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
              })
            }

            resource "aws_iam_instance_profile" "app" {
              role = aws_iam_role.app.name
            }

            resource "aws_instance" "web" {
              ami                  = "ami-123"
              instance_type        = "t3.micro"
              iam_instance_profile = aws_iam_instance_profile.app.name
            }
        '''}, ["terraform"])
        found = chains(result, "CHAIN-ADMIN-CREDENTIALS-EXPOSED")
        self.assertTrue(found, [f.rule.id for f in result.findings])
        self.assertEqual(found[0].verification, "linked")
        self.assertIn("aws_instance.web", " ".join(found[0].extra["route"]))


if __name__ == "__main__":
    unittest.main()
