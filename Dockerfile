# SHADOWSCOPE OSINT Framework Dockerfile
# ============================================

# Build stage
FROM python:3.11-slim as builder

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

# Create application directory
RUN mkdir -p /opt/shadowscope/app
WORKDIR /opt/shadowscope/app

# Copy application code
COPY shadowscope/ ./shadowscope/
COPY requirements.txt .
COPY pyproject.toml .

# Install application in development mode
RUN pip install --no-cache-dir -e .

# Create data directories
RUN mkdir -p /opt/shadowscope/data \
    /opt/shadowscope/config \
    /opt/shadowscope/logs \
    /opt/shadowscope/modules \
    /opt/shadowscope/cache

# Set permissions
RUN chown -R 1000:1000 /opt/shadowscope

# Create non-root user
RUN useradd -m -u 1000 -g 1000 shadowscope
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
