FROM python:3.14-slim@sha256:cd89c30eda26ee911a4611b18680086e0ea42e6f5f8cbe653d07fa7958c9cec8

# Pick up Debian security fixes newer than the pinned base image.
RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -rf /var/lib/apt/lists/*

# Trivy scans ECR images when Inspector isn't on. Versions 0.69.4 to 0.69.6 were compromised
# (CVE-2026-33634), so this pins a later release and checks it against the published checksum.
ARG TRIVY_VERSION=0.76.1
ARG TRIVY_SHA256=c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0
ADD --checksum=sha256:${TRIVY_SHA256} \
    https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
    /tmp/trivy.tar.gz
RUN tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && rm /tmp/trivy.tar.gz

WORKDIR /app
COPY requirements.lock pyproject.toml README.md ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY src ./src
RUN pip install --no-cache-dir --no-deps .

RUN useradd --create-home --uid 1000 scanner && mkdir -p /app/data && chown scanner /app/data
USER scanner
ENV DATABASE_PATH=/app/data/agent_identity.sqlite3 TRIVY_CACHE_DIR=/app/data/trivy

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD ["python", "-c", "import urllib.request as u; u.urlopen(u.Request('http://127.0.0.1:8080/', headers={'Host':'localhost'}), timeout=2)"]
CMD ["uvicorn", "agent_identity.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
