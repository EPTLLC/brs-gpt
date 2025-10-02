# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-10-03 01:41:52 MSK
# Status: Modified
# Telegram: https://t.me/easyprotech

FROM python:3.10-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    BRS_GPT_CONFIG_DIR=/app/.config/brs-gpt

# Install system dependencies including optional tools
RUN apt-get update && apt-get install -y \
    dnsutils \
    curl \
    wget \
    git \
    ca-certificates \
    gnupg \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Optional: Install Amass (if you want it in Docker)
# RUN wget -qO- https://github.com/OWASP/Amass/releases/download/v3.23.3/amass_Linux_amd64.zip | \
#     busybox unzip - && mv amass_Linux_amd64/amass /usr/local/bin/ && rm -rf amass_Linux_amd64

# Optional: Install Subfinder (if you want it in Docker)
# RUN wget -qO- https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip | \
#     busybox unzip - && mv subfinder /usr/local/bin/

# Create non-root user
RUN useradd --create-home --shell /bin/bash brsgpt

# Set work directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY brsgpt/ ./brsgpt/
COPY setup.py .

# Install the package
RUN pip install -e .

# Create directories
RUN mkdir -p /app/output /app/.config/brs-gpt /app/results && \
    chown -R brsgpt:brsgpt /app

# Switch to non-root user
USER brsgpt

# Create volumes
VOLUME ["/app/output", "/app/results", "/app/.config/brs-gpt"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD brs-gpt version || exit 1

# Set default command
ENTRYPOINT ["brs-gpt"]

# Default arguments
CMD ["--help"]
