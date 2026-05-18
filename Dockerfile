FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    git \
    iptables \
    python3-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove build-essential python3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/mandiant/capa-rules.git /opt/capa-rules \
    && rm -rf /opt/capa-rules/.git

COPY src/ ./src/
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /tmp/sandbox /data/models /data/benign \
    && chmod 700 /tmp/sandbox

ENV PYTHONPATH=/app
ENV AMD_AGENT_CONTAINER=1
ENV AMD_CAPA_RULES_DIR=/opt/capa-rules

VOLUME ["/data"]
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-m", "src.graph"]
