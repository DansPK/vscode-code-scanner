FROM python:3.12-slim

ARG GITLEAKS_VERSION=8.30.1
ARG SONAR_SCANNER_VERSION=8.1.0.6389
ARG SEMGREP_VERSION=1.179.0
ARG NODE_VERSION=24.21.0
ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl unzip ca-certificates xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Node.js LTS: SonarQube's JavaScript/TypeScript/CSS analysis runs on Node and refuses old versions.
RUN case "$TARGETARCH" in arm64) A=arm64;; *) A=x64;; esac \
 && curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${A}.tar.xz" \
    | tar -xJ -C /opt \
 && ln -s /opt/node-v${NODE_VERSION}-linux-${A}/bin/node /usr/local/bin/node

# Gitleaks (binary)
RUN case "$TARGETARCH" in arm64) A=arm64;; *) A=x64;; esac \
 && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${A}.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

# SonarScanner CLI (bundles its own Java)
RUN case "$TARGETARCH" in arm64) A=linux-aarch64;; *) A=linux-x64;; esac \
 && curl -fsSL -o /tmp/ss.zip "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-${A}.zip" \
 && unzip -q /tmp/ss.zip -d /opt && rm /tmp/ss.zip \
 && ln -s /opt/sonar-scanner-${SONAR_SCANNER_VERSION}-${A}/bin/sonar-scanner /usr/local/bin/sonar-scanner

# Semgrep in its own venv (its pins clash with the app's). Rules for every language are baked in,
# merged into one file so overlapping packs don't report the same problem twice; scans work offline.
COPY scripts/fetch_semgrep_rules.py /tmp/build/scripts/fetch_semgrep_rules.py
COPY rules /tmp/build/rules
RUN python -m venv /opt/semgrep && /opt/semgrep/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" pyyaml \
 && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep \
 && mkdir -p /opt/semgrep-rules \
 && /opt/semgrep/bin/python /tmp/build/scripts/fetch_semgrep_rules.py /opt/semgrep-rules/rules.yml

COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev

RUN useradd --create-home --uid 10001 harness && mkdir -p /data && chown harness /data
USER harness
ENV PATH="/app/.venv/bin:$PATH" HARNESS_DATA_DIR=/data SEMGREP_SEND_METRICS=off SEMGREP_CONFIGS=/opt/semgrep-rules/rules.yml
EXPOSE 8080
HEALTHCHECK CMD curl -fsk https://localhost:8080/health || curl -fs http://localhost:8080/health || exit 1
CMD ["harness"]
