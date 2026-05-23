# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS wheels

WORKDIR /build

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev

COPY requirements.base.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip wheel --wheel-dir /wheels -r requirements.base.txt

FROM python:3.12-slim AS extra-wheels

WORKDIR /build

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev

COPY requirements.txt requirements.base.txt ./
RUN --mount=type=cache,target=/root/.cache/pip \
    mkdir -p /extra-wheels \
    && awk 'NF && $1 !~ /^#/ && $1 != "-r" && $1 != "--requirement" {print}' requirements.txt > /tmp/requirements.extra.txt \
    && if [ -s /tmp/requirements.extra.txt ]; then pip wheel --wheel-dir /extra-wheels -r /tmp/requirements.extra.txt; fi

FROM python:3.12-slim AS capa-rules

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git

RUN git clone --depth 1 --branch v9.4.0 https://github.com/mandiant/capa-rules.git /opt/capa-rules \
    && rm -rf /opt/capa-rules/.git \
    && mkdir -p /opt/capa-sigs

FROM python:3.12-slim

WORKDIR /app

COPY --from=wheels /wheels /wheels
COPY requirements.base.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-index --find-links=/wheels -r requirements.base.txt \
    && rm -rf /wheels

COPY --from=extra-wheels /extra-wheels /extra-wheels
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    awk 'NF && $1 !~ /^#/ && $1 != "-r" && $1 != "--requirement" {print}' requirements.txt > /tmp/requirements.extra.txt \
    && if [ -s /tmp/requirements.extra.txt ]; then pip install --no-index --find-links=/extra-wheels -r /tmp/requirements.extra.txt; fi \
    && rm -rf /extra-wheels /tmp/requirements.extra.txt

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    iptables \
    libgomp1

COPY --from=capa-rules /opt/capa-rules /opt/capa-rules
COPY --from=capa-rules /opt/capa-sigs /opt/capa-sigs
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY docker/ ./docker/
RUN sed -i 's/\r$//' /app/docker/*.sh \
    && chmod +x /app/docker/*.sh \
    && mkdir -p /tmp/sandbox /data/models /data/benign \
    && chmod 700 /tmp/sandbox

ENV PYTHONPATH=/app
ENV AMD_AGENT_CONTAINER=1
ENV AMD_CAPA_RULES_DIR=/opt/capa-rules

VOLUME ["/data"]
ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["python", "-m", "src.graph"]
