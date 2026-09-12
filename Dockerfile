# SHADOWSCOPE OSINT Framework Dockerfile
# ============================================

# Build stage
FROM python:3.11-slim AS builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/shadowscope/venv
ENV PATH="/opt/shadowscope/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/shadowscope/venv/bin:$PATH"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io \
    git \
    curl \
    wget \
    net-tools \
    dnsutils \
    tor \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/shadowscope/venv /opt/shadowscope/venv

# Create non-root user/group BEFORE chown (GID 1000 does not exist by default
# in python:3.11-slim; useradd -g 1000 exits with code 6 if the group is missing)
RUN groupadd -g 1000 shadowscope && \
    useradd -m -u 1000 -g shadowscope shadowscope

# Create application and data directories
RUN mkdir -p /opt/shadowscope/app \
    /opt/shadowscope/data \
    /opt/shadowscope/config \
    /opt/shadowscope/logs \
    /opt/shadowscope/modules \
    /opt/shadowscope/cache

WORKDIR /opt/shadowscope/app

# Copy application code (README.md is required by pyproject.toml)
COPY shadowscope/ ./shadowscope/
COPY requirements.txt .
COPY pyproject.toml .
COPY README.md .
COPY LICENSE .

# Install application (non-editable — more suitable for container images)
RUN pip install --no-cache-dir .

# Set ownership for non-root user
RUN chown -R shadowscope:shadowscope /opt/shadowscope

USER shadowscope
WORKDIR /opt/shadowscope/app

# Expose ports
EXPOSE 8080
EXPOSE 8443

# Set default command
ENTRYPOINT ["shadowscope"]
CMD ["--help"]

# Alternative: Run with TUI
# ENTRYPOINT ["shadowscope", "tui", "start"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import shadowscope; print('OK')" || exit 1
