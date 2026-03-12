# secagent Docker Image - Build & Test Guide

## Quick Start

### Build the Image

```bash
cd ~/projects/secagent
docker build -t secagent:latest .
```

### Test the Image

```bash
# Show help
docker run --rm secagent:latest --help

# Scan a project (mount your code)
docker run --rm -v $(pwd)/my-project:/app/project secagent:latest scan --all .

# Scan with specific scanners
docker run --rm -v $(pwd)/my-project:/app/project secagent:latest scan --scanners semgrep,gitleaks .

# Output as JSON
docker run --rm -v $(pwd)/my-project:/app/project secagent:latest scan --all . --format json

# Use with diff scanning
docker run --rm -v $(pwd)/my-project:/app/project secagent:latest scan --diff HEAD .
```

### Using Docker Compose

```bash
# Create a project directory
mkdir project-to-scan
cd project-to-scan
# Add your code here

# Run scan
docker-compose up
```

### Pre-built Image

Not available. Build locally from the repository:

```bash
git clone https://github.com/secagent/secagent.git
cd secagent
docker build -t secagent:latest .
```

This keeps the project private and gives you full control over the image.

## Test Scenarios

### 1. Test All Scanners

```bash
# Clone a vulnerable test repo
git clone https://github.com/snyk-labs/nodejs-goof
cd nodejs-goof

# Run secagent
docker run --rm -v $(pwd):/app/project secagent:latest scan --all .
```

Expected output: 400+ findings (dependencies, secrets, code issues)

### 2. Test Diff Scanning

```bash
# Make a change
echo "test" > newfile.txt

# Scan only changes
docker run --rm -v $(pwd):/app/project secagent:latest scan --diff HEAD .
```

### 3. Test with Config

```bash
# Create config
cat > config.yaml << 'EOF'
scanners:
  gitleaks: true
  semgrep: true
ignore:
  severities:
    - "low"
    - "info"
EOF

# Run with config
docker run --rm -v $(pwd):/app/project -v $(pwd)/config.yaml:/root/.secagent/config.yaml secagent:latest scan --all .
```

### 4. Test CI/CD Integration

```bash
# GitHub Actions style
docker run --rm \
  -v $(pwd):/app/project \
  secagent:latest scan --all . --format json --output results.json

# Check exit code (0 = no critical/high findings)
echo "Exit code: $?"
```

## Image Size

Expected size: ~500-800MB (includes all scanners + dependencies)

## Optimization Tips

### Multi-stage Build (Smaller Image)

```dockerfile
# Build stage
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o secagent ./cmd/secagent

# Runtime stage
FROM debian:bookworm-slim
# Install only runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install scanners and copy secagent from builder
# ... (rest of Dockerfile)
```

### Use Distroless (Minimal)

For production, consider distroless images for better security.

## Troubleshooting

### Permission Issues

```bash
# Run as current user
docker run --rm -u $(id -u):$(id -g) -v $(pwd):/app/project secagent:latest scan .
```

### Cache Persistence

```bash
# Create named volume
docker volume create secagent-cache

# Use volume
docker run --rm -v secagent-cache:/root/.secagent/cache secagent:latest scan .
```

### Out of Memory

```bash
# Limit memory usage
docker run --rm -m 2g secagent:latest scan --all .
```

## Building the Image

```bash
# Clone repository
git clone https://github.com/secagent/secagent.git
cd secagent

# Build image
docker build -t secagent:latest .

# Verify it works
docker run --rm secagent:latest doctor
```

The image is built locally and stays on your machine. No need to push to any registry.

## Security Best Practices

1. **Don't run as root** - Add USER directive
2. **Scan the image** - Use secagent on itself!
3. **Use specific tags** - Don't use `:latest` in production
4. **Minimize layers** - Combine RUN commands
5. **Remove unnecessary tools** - Keep only what's needed
