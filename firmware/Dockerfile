# Pwn4C firmware builder image (alternative to running build.sh natively).
# Usage (from the repo root):
#   docker build -t pwn4c-builder ./firmware
#   docker run --rm -v "%cd%/firmware/output:/output" pwn4c-builder
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl file gawk gettext git libncurses-dev libssl-dev \
    python3 rsync unzip wget zlib1g-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY . /src
WORKDIR /src
CMD ["sh", "/src/build.sh"]
