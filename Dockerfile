FROM python:3.14-slim

# Install runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    iproute2 \
    iputils-ping \
    sudo \
    libcap2-bin \
    procps \
    gpg \
    && rm -rf /var/lib/apt/lists/* \
    && chmod 1777 /tmp

WORKDIR /app

# Install uv for fast dependency resolution
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# COPY . .

# NET_ADMIN + NET_RAW are required for iptables; set them as defaults so
# docker run --cap-add is not strictly needed, but the runtime must not drop them.
# Use a non-root user for everything except iptables operations.
# RUN groupadd -r appgroup && useradd -r -g appgroup -m appuser \
#     && chown -R appuser:appgroup /app

# Give the python binary the capabilities it needs so iptables works as non-root.
# This is preferred over running the whole container as root.
RUN setcap cap_net_admin,cap_net_raw+eip $(readlink -f $(which python3))

USER root

EXPOSE 8000

CMD ["uv", "run", "python", "app.py"]
