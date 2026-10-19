# rempart-expect: DOCKER-RUNS-AS-ROOT, DOCKER-UNPINNED-BASE
FROM python:3.12-slim
WORKDIR /app
# rempart-expect: DOCKER-CURL-PIPE-SHELL
RUN curl -fsSL https://install.example.sh | sh
# rempart-expect: DOCKER-SECRET-IN-IMAGE
ENV API_SECRET={{FAKE_GENERIC_SECRET}}
# rempart-safe: DOCKER-SECRET-IN-IMAGE
ENV API_SECRET_FILE=/run/secrets/api
COPY . .
CMD ["python", "app.py"]
