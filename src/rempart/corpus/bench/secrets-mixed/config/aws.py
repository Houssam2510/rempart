import os

# rempart-expect: SEC-AWS-ACCESS-KEY
AWS_ACCESS_KEY_ID = "{{FAKE_AWS_KEY}}"
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
# rempart-safe: SEC-GENERIC
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
# rempart-expect: SEC-GENERIC
api_secret = "{{FAKE_GENERIC_SECRET}}"
# rempart-safe: SEC-GENERIC
api_secret_name = "payments/api-secret"
# rempart-safe: SEC-GENERIC
password = "changeme"
