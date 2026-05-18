FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /tmp/sandbox /data/models /data/benign \
    && chmod 700 /tmp/sandbox

ENV PYTHONPATH=/app
ENV AMD_AGENT_CONTAINER=1

VOLUME ["/data"]
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-m", "src.graph"]
