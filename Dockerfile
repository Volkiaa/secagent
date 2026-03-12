# secagent - All-in-One Security Scanner
# Includes: secagent + osv-scanner + gitleaks + semgrep + trivy + checkov

FROM golang:1.25-bookworm

LABEL maintainer="secagent-team"
LABEL description="Developer-First Security Scanner - 5-in-1 unified security scanning"
LABEL version="0.4.2"

# Install Python and pip for semgrep/checkov
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install secagent
COPY secagent /usr/local/bin/secagent
RUN chmod +x /usr/local/bin/secagent

# Install osv-scanner
RUN curl -sSL https://raw.githubusercontent.com/google/osv-scanner/main/install.sh | bash

# Install gitleaks
RUN curl -sSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks-linux-amd64 \
    -o /usr/local/bin/gitleaks && chmod +x /usr/local/bin/gitleaks

# Install semgrep
RUN pip3 install --no-cache-dir semgrep

# Install trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install checkov
RUN pip3 install --no-cache-dir checkov

# Create cache directory and set permissions
RUN mkdir -p /root/.secagent/cache && \
    chmod -R 755 /root/.secagent

# Create non-root user for security
RUN useradd -r -s /bin/false secagent && \
    chown -R secagent:secagent /root/.secagent

# Switch to non-root user
USER secagent

# Default command
ENTRYPOINT ["secagent"]
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD secagent doctor || exit 1
