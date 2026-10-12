# Pwn4C firmware builder image (reproducible path, no host Linux needed).
# Usage (from the repo root):
#   docker build -f firmware/Dockerfile -t pwn4c-builder .
#   docker run --rm -v "%cd%/firmware/output:/output" pwn4c-builder
#
# NOTE: this path builds the dev variant WITHOUT the pwn4cd daemon baked in
# (cross-compiling the daemon needs the OpenWrt SDK; CI does that natively
# and passes PWN4C_BIN). For the full drone image use CI artifacts/releases.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
ENV OUT_DIR=/output
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl file gawk gettext git libncurses-dev libssl-dev \
    python3 rsync unzip wget zlib1g-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY firmware /src/firmware
COPY daemon /src/daemon
WORKDIR /src/firmware
CMD ["sh", "build.sh"]
