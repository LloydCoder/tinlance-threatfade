# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
ARG PYTHON_BASE_TAG=3.12.14-slim-trixie
ARG PYTHON_BASE_DIGEST
FROM python:${PYTHON_BASE_TAG}@${PYTHON_BASE_DIGEST}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

LABEL org.opencontainers.image.source="https://github.com/LloydCoder/tinlance-threatfade" \
      org.opencontainers.image.title="ThreatFade" \
      org.opencontainers.image.description="Open-core network threat detection oracle" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update \
    && apt-get dist-upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup --system threatfade && adduser --system --ingroup threatfade threatfade
WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --disable-pip-version-check --upgrade pip \
    && python -m pip install --no-cache-dir --disable-pip-version-check -r requirements.txt
COPY . .

RUN mkdir -p /app/reports /app/tmp && chown -R threatfade:threatfade /app
USER threatfade

EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).read()"

CMD ["uvicorn", "enterprise_app:app", "--host", "0.0.0.0", "--port", "8080", "--timeout-graceful-shutdown", "25"]
