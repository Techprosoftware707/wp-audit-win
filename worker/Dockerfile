# wp-audit-win scanner worker image.
#
# Build context is ./backend (see docker-compose.yml) so it ships the same app
# code as the API, plus the open-source scanner tooling layered on top:
#   nmap, nuclei, wp-cli, wpscan.
#
# Tool installs are RESILIENT: if a download/build fails at image-build time the
# layer still succeeds, and the corresponding scan step degrades gracefully at
# runtime (it reports the tool is unavailable rather than crashing a scan).
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    NUCLEI_VERSION=3.3.8

WORKDIR /app

# System packages: nmap (small), php-cli (for wp-cli), ruby + build chain (wpscan).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl ca-certificates unzip git \
      nmap \
      php-cli \
      ruby ruby-dev build-essential libcurl4-openssl-dev zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

# nuclei (single Go binary from the official release).
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) n_arch=amd64;; arm64) n_arch=arm64;; *) n_arch=amd64;; esac; \
    url="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${n_arch}.zip"; \
    ( curl -fsSL "$url" -o /tmp/nuclei.zip \
      && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
      && chmod +x /usr/local/bin/nuclei \
      && rm -f /tmp/nuclei.zip \
      && echo "nuclei installed" ) \
    || echo "WARN: nuclei install failed; nuclei step will report unavailable at runtime"

# wp-cli (phar).
RUN ( curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
        -o /usr/local/bin/wp \
      && chmod +x /usr/local/bin/wp \
      && echo "wp-cli installed" ) \
    || echo "WARN: wp-cli install failed; wpcli step will report unavailable at runtime"

# wpscan (ruby gem). Slow to build; failure is non-fatal.
RUN ( gem install wpscan --no-document && echo "wpscan installed" ) \
    || echo "WARN: wpscan install failed; wpscan step will report unavailable at runtime"

# whatweb (ruby gem). Technology/server fingerprinting.
RUN ( gem install whatweb --no-document && echo "whatweb installed" ) \
    || echo "WARN: whatweb install failed; whatweb step will report unavailable at runtime"

# nikto (from source; Debian's packaged 2.1.5 emits a legacy JSON schema).
RUN ( git clone --depth 1 https://github.com/sullo/nikto /opt/nikto \
      && printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto \
      && chmod +x /usr/local/bin/nikto \
      && echo "nikto installed" ) \
    || echo "WARN: nikto install failed; nikto step will report unavailable at runtime"

# ffuf (single Go binary from the official release).
RUN set -eux; \
    ffuf_ver=2.1.0; arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) a=amd64;; arm64) a=arm64;; *) a=amd64;; esac; \
    ( curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${ffuf_ver}/ffuf_${ffuf_ver}_linux_${a}.tar.gz" -o /tmp/ffuf.tgz \
      && tar -xzf /tmp/ffuf.tgz -C /usr/local/bin ffuf \
      && chmod +x /usr/local/bin/ffuf && rm -f /tmp/ffuf.tgz \
      && echo "ffuf installed" ) \
    || echo "WARN: ffuf install failed; ffuf step will report unavailable at runtime"

# semgrep (static analysis of PHP/plugin/theme source).
RUN ( pip install --no-cache-dir semgrep && echo "semgrep installed" ) \
    || echo "WARN: semgrep install failed; semgrep step will report unavailable at runtime"

# gitleaks (secret scanning of source / git history; single Go binary).
RUN set -eux; \
    gl_ver=8.21.2; arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) a=x64;; arm64) a=arm64;; *) a=x64;; esac; \
    ( curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${gl_ver}/gitleaks_${gl_ver}_linux_${a}.tar.gz" -o /tmp/gl.tgz \
      && tar -xzf /tmp/gl.tgz -C /usr/local/bin gitleaks \
      && chmod +x /usr/local/bin/gitleaks && rm -f /tmp/gl.tgz \
      && echo "gitleaks installed" ) \
    || echo "WARN: gitleaks install failed; gitleaks step will report unavailable at runtime"

# Python app + deps.
COPY pyproject.toml ./
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./
RUN pip install -e .

COPY docker-entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint \
 && useradd -m -u 10002 wpworker \
 && mkdir -p /home/wpworker/.cache \
 && chown -R wpworker:wpworker /app /home/wpworker

USER wpworker
ENV HOME=/home/wpworker \
    SEMGREP_SEND_METRICS=off

# Pre-cache scanner DATA so the image is ready to run offline on Ubuntu 24 (no
# first-use download). Both are resilient: if the build host has no network the
# layer still succeeds and the tool fetches/degrades at runtime as before.
#
# nuclei templates -> $HOME/nuclei-templates (the default location the step uses).
RUN ( nuclei -update-templates -disable-update-check \
      && echo "nuclei templates pre-cached" ) \
    || echo "WARN: nuclei template pre-cache failed; fetched on first use at runtime"

# semgrep p/php + p/wordpress registry rulesets -> $HOME/.semgrep cache, so the
# source-analysis step's primary config works without reaching the registry.
RUN set -eux; \
    d="$(mktemp -d)"; printf '<?php echo $_GET["x"]; ?>\n' > "$d/probe.php"; \
    ( semgrep --config p/php --config p/wordpress --quiet --no-error \
        --metrics=off --timeout=60 "$d" >/dev/null 2>&1 || true ); \
    rm -rf "$d"; \
    echo "semgrep rulesets pre-cached (best-effort)"

ENTRYPOINT ["entrypoint"]
CMD ["worker"]
