FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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
