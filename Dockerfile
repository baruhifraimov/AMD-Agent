# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS wheels

WORKDIR /build

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev

COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip wheel --wheel-dir /wheels -r requirements.txt

FROM python:3.12-slim

WORKDIR /app

COPY --from=wheels /wheels /wheels
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    iptables \
    libgomp1

COPY src/ ./src/
COPY scripts/ ./scripts/
COPY docker/ ./docker/
RUN sed -i 's/\r$//' /app/docker/*.sh \
    && chmod +x /app/docker/*.sh \
    && mkdir -p /tmp/sandbox /data/models /data/benign \
    && chmod 700 /tmp/sandbox

ENV PYTHONPATH=/app
ENV AMD_AGENT_CONTAINER=1

VOLUME ["/data"]
ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["python", "-m", "src.graph"]
