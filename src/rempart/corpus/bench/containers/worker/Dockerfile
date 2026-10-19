# rempart-safe: DOCKER-RUNS-AS-ROOT, DOCKER-UNPINNED-BASE
FROM python:3.12-slim@sha256:0f2ad11cf6d7a7a2b8e4d4b1f6d3d0c0a2f7e1d4c3b2a19087f6e5d4c3b2a190
RUN useradd --create-home app
USER app
COPY --chown=app:app . /home/app
CMD ["python", "/home/app/worker.py"]
