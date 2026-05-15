FROM python:3.12-slim

# System tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git build-essential libpq-dev unzip \
    nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Security tools — same as API image
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.4/nuclei_3.2.4_linux_amd64.zip \
    -O /tmp/nuclei.zip \
    && unzip -j /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

RUN wget -q https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
    -O /tmp/ffuf.tar.gz && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf && rm /tmp/ffuf.tar.gz

RUN wget -q https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip \
    -O /tmp/katana.zip \
    && unzip -j /tmp/katana.zip katana -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/katana \
    && rm /tmp/katana.zip

# Semgrep
RUN pip install --no-cache-dir semgrep

# TruffleHog
RUN wget -q https://github.com/trufflesecurity/trufflehog/releases/download/v3.79.0/trufflehog_3.79.0_linux_amd64.tar.gz \
    -O /tmp/trufflehog.tar.gz && tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin/ trufflehog && rm /tmp/trufflehog.tar.gz

# pip-audit
RUN pip install --no-cache-dir pip-audit

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

CMD ["celery", "-A", "core.celery_app", "worker", "--loglevel=info"]
