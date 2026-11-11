# BinaryStudio, public mode.
#
#   docker build -t binarystudio .
#   docker run --rm -p 127.0.0.1:8421:8421 --read-only --cap-drop ALL \
#       --security-opt no-new-privileges --memory 2g --pids-limit 512 \
#       -e BINARYSTUDIO_ALLOWED_HOSTS=binarystudio.example.com \
#       -e BINARYSTUDIO_TRUST_PROXY=1 binarystudio
#
# The container speaks plain HTTP on 8421 and expects a TLS reverse proxy in
# front of it (deploy/Caddyfile, deploy/nginx.conf, deploy/docker-compose.yml).
# Nothing is installed: the application is standard-library Python and the
# sample binaries under fixtures/ are shipped prebuilt, so the image has no
# compiler, no pip packages and no shell scripts of its own.
#
# The code is developed and tested on Python 3.9; the tag below is a currently
# supported release. To check an image before trusting it:
#   docker run --rm --user 0 -v "$PWD/tests:/app/tests:ro" --entrypoint python3 \
#       binarystudio -m unittest tests.test_api_security

ARG PYTHON_IMAGE=python:3.13-slim
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BINARYSTUDIO_MODE=public \
    BINARYSTUDIO_HOST=0.0.0.0 \
    BINARYSTUDIO_PORT=8421

# A fixed, unprivileged uid with no home directory and no login shell.
RUN groupadd --system --gid 10001 binarystudio \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin binarystudio

WORKDIR /app

# Owned by root and read-only to the service user: the process can read its
# code and assets but cannot change them, with or without --read-only.
COPY --chown=root:root binary_viewer.py macho_viewer.py ./
COPY --chown=root:root backend/ ./backend/
COPY --chown=root:root static/ ./static/
# The public-site layer: learning pages, robots.txt, sitemap, and the ads policy (tools/site_pages.py).
COPY --chown=root:root tools/site_pages.py ./tools/
COPY --chown=root:root fixtures/ ./fixtures/
RUN find /app -name '__pycache__' -prune -exec rm -rf {} + \
 && chmod -R a+rX,go-w /app

USER 10001:10001
EXPOSE 8421

# /healthz answers "ok" for any Host and is exempt from rate limiting.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python3", "-c", "import os, sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('BINARYSTUDIO_PORT', '8421') + '/healthz', timeout=3).status == 200 else 1)"]

# Mode, host and port come from the environment above; flags may be appended:
#   docker run ... binarystudio --max-upload-mb 16 --allowed-host example.com
ENTRYPOINT ["python3", "/app/binary_viewer.py"]
