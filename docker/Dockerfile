# BTAudit Docker Image
# Made by Monish Paramasivam
#
# Build: docker build -t btaudit .
# Run:   docker run --rm --net=host --privileged btaudit scan --help
#
# NOTE: Bluetooth scanning requires host network access and Bluetooth hardware.
# The --privileged flag grants access to Bluetooth hardware.
# IMPORTANT: Only run in authorized environments.

FROM python:3.12-slim-bookworm

LABEL maintainer="Monish Paramasivam"
LABEL description="BTAudit — Bluetooth Security Auditing and Inventory Tool"
LABEL version="1.0.0"

# Install system Bluetooth dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    bluez \
    bluetooth \
    libbluetooth-dev \
    libglib2.0-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for running the tool
RUN groupadd -r btaudit && useradd -r -g btaudit -s /bin/bash btaudit

WORKDIR /app

# Copy and install Python package
COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir -e ".[dashboard]"

# Create output directory
RUN mkdir -p /app/reports && chown btaudit:btaudit /app/reports
VOLUME ["/app/reports"]

# Expose dashboard port
EXPOSE 8080

# Switch to non-root user
# Note: Bluetooth hardware access may still require --privileged or --cap-add=NET_ADMIN
USER btaudit

ENTRYPOINT ["btaudit"]
CMD ["--help"]

# ── Usage examples ──────────────────────────────────────────────────────
# Passive BLE scan (15s), save reports to ./reports:
#   docker run --rm --net=host --privileged \
#     -v $(pwd)/reports:/app/reports \
#     -e BTAUDIT_AUTHORIZED=1 \
#     -e BTAUDIT_AUTHORIZED_BY="Your Name" \
#     -e BTAUDIT_ENVIRONMENT="Lab Network" \
#     btaudit scan --non-interactive --duration 15 --output /app/reports
#
# Launch web dashboard:
#   docker run --rm --net=host --privileged -p 8080:8080 btaudit dashboard
