# Base image pinned by the digest of its multi-arch index (Python 3.12.16), so
# rebuilds are reproducible. Keep both stages on the same digest. To update:
#   docker buildx imagetools inspect python:3.12-slim-bookworm
# then replace the digest below and in the runtime stage.
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS builder
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN pip wheel --no-cache-dir --wheel-dir /wheels '.[web,postgres]'

FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CYBER_RSS_DATA_DIR=/runtime
RUN --mount=type=bind,from=builder,source=/wheels,target=/wheels \
    pip install --no-cache-dir --no-index --find-links=/wheels 'cyber-rss-reader[web,postgres]'
RUN groupadd --gid 10001 rss
RUN useradd --uid 10001 --gid rss --no-create-home --shell /usr/sbin/nologin rss
RUN mkdir -p /runtime/data/backups /runtime/cache /runtime/logs
RUN chown -R rss:rss /runtime
WORKDIR /runtime
USER rss
EXPOSE 8000
# Listen inside the container; Compose publishes the port only on host loopback.
CMD ["python", "-m", "uvicorn", "web_api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers", "--limit-concurrency", "32", "--timeout-keep-alive", "5"]
