# TinyCTI Docker Image
FROM python:3.11-slim

LABEL maintainer="TinyCTI Team"
LABEL description="TinyCTI - Lightweight Threat Intelligence Collection Framework"
LABEL version="1.0.0"

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        wget \
        ca-certificates \
        gnupg \
        && rm -rf /var/lib/apt/lists/*

# Create tinycti user
RUN groupadd -r tinycti && \
    useradd -r -g tinycti -d /opt/tinycti -s /bin/bash tinycti

# Create directories
RUN mkdir -p /opt/tinycti/{iocs,ngfw,logs} && \
    chown -R tinycti:tinycti /opt/tinycti

# Set working directory
WORKDIR /opt/tinycti

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Ensure proper ownership
RUN chown -R tinycti:tinycti /opt/tinycti

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Initialize directories if they dont exist\n\
mkdir -p /opt/tinycti/{iocs,ngfw}/{active,critical,watch,archive}\n\
\n\
# Default command\n\
if [ "$#" -eq 0 ]; then\n\
    exec python tinycti.py -d --api\n\
else\n\
    exec "$@"\n\
fi' > /opt/tinycti/docker-entrypoint.sh && \
    chmod +x /opt/tinycti/docker-entrypoint.sh

# Switch to tinycti user
USER tinycti

# Expose ports
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Set entrypoint
ENTRYPOINT ["/opt/tinycti/docker-entrypoint.sh"]