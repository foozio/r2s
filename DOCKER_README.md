# React2Shell Vulnerability Checker - Docker Documentation

## Overview

The React2Shell Vulnerability Checker can be run using Docker for easy deployment and isolation. This approach ensures consistent execution across different environments without requiring Python or dependency installation on the host system.

## Prerequisites

- Docker installed and running
- At least 512MB available RAM
- Internet access for image download and URL scanning

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/foozio/r2s.git
cd react2shell-checker
```

### 2. Build the Docker Image

```bash
# Using the provided script
./docker-run.sh build

# Or manually
docker build -t react2shell-scanner:latest .
```

### 3. Test the Image

```bash
./docker-run.sh test
```

## Usage

### Scanning a Local Project

```bash
# Using the script
./docker-run.sh scan-path /path/to/your/react/project

# Or using Docker directly
docker run --rm \
  -v /path/to/project:/app/target-project:ro \
  -v $(pwd)/scans:/app/scans \
  -v $(pwd)/logs:/app/logs \
  react2shell-scanner:latest \
  --path /app/target-project \
  --json
```

### Scanning a URL

```bash
# Using the script
./docker-run.sh scan-url https://your-app.com

# Or using Docker directly
docker run --rm \
  -v $(pwd)/logs:/app/logs \
  react2shell-scanner:latest \
  --url https://your-app.com \
  --json \
  --verbose
```

### Using Docker Compose

```bash
# Scan a project
docker-compose --profile scan run --rm scan-project

# Scan a URL
docker-compose --profile url-scan run --rm scan-url

# CI/CD integration
docker-compose --profile ci run --rm ci-scan
```

## Output

### Scan Results

Results are saved to the `./scans/` directory in JSON format:

```json
{
  "vulnerabilities_found": true,
  "vulnerabilities": [
    {
      "package": "react-server-dom-webpack",
      "version": "19.0.0"
    }
  ],
  "recommendations": {
    "react-server-dom-packages": "Upgrade to versions 19.0.1, 19.1.2, or 19.2.1",
    "react": "Upgrade to a patched version >= 19.x.x if needed"
  }
}
```

### Logs

Detailed logs are saved to the `./logs/` directory with timestamps and debug information.

## Configuration

### Environment Variables

- `PYTHONUNBUFFERED=1`: Ensures unbuffered output for real-time logging
- `CI=true`: Enables CI mode (can be used for different behaviors)

### Volumes

- `/app/scans`: Output directory for scan results
- `/app/logs`: Output directory for log files
- `/app/target-project`: Input directory for project scanning (read-only)

## Security Considerations

### Container Security

- Runs as non-root user (`scanner`)
- Uses slim Python base image for minimal attack surface
- Read-only volumes where possible
- No privileged access

### Network Security

- URL validation prevents SSRF attacks
- No outbound connections except for specified URL scanning
- Timeout limits prevent hanging requests

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Scan for React2Shell vulnerabilities
  run: |
    docker run --rm \
      -v ${{ github.workspace }}:/app/workspace:ro \
      -v ./security-scans:/app/scans \
      react2shell-scanner:latest \
      --path /app/workspace \
      --json \
      --quiet > scan-results.json
```

### Jenkins Pipeline Example

```groovy
stage('Security Scan') {
    steps {
        sh '''
            docker run --rm \
              -v ${WORKSPACE}:/app/workspace:ro \
              -v ${WORKSPACE}/security-scans:/app/scans \
              react2shell-scanner:latest \
              --path /app/workspace \
              --json > security-scan-results.json
        '''
    }
}
```

## Troubleshooting

### Common Issues

#### Permission Denied

```
docker: Got permission denied while trying to connect to the Docker daemon socket
```

**Solution:** Add your user to the docker group or run with sudo.

#### No Space Left on Device

```
ERROR: No space left on device
```

**Solution:** Clean up Docker images and containers:

```bash
docker system prune -a
```

#### Mount Issues on Windows

```
ERROR: Invalid mount path
```

**Solution:** Use proper Windows path format or Docker Desktop settings.

#### Scan Results Empty

**Check:**

- Ensure the path/URL is accessible
- Verify the project contains package.json or React files
- Check logs for detailed error messages

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
docker run --rm \
  -v $(pwd)/logs:/app/logs \
  react2shell-scanner:latest \
  --url https://example.com \
  --verbose \
  --log-file /app/logs/debug.log
```

## Performance

### Resource Usage

- **Base Image Size:** ~150MB (Python 3.9 slim)
- **Memory Usage:** 50-200MB depending on scan size
- **CPU Usage:** Minimal for small projects, scales with parallel workers

### Optimization Tips

- Use `--quiet` flag to reduce output overhead
- Limit `--workers` based on available CPU cores
- Mount only necessary directories as read-only

## Building Custom Images

### Multi-stage Build

```dockerfile
# Build stage
FROM python:3.9-slim as builder
# ... build dependencies ...

# Production stage
FROM python:3.9-slim
COPY --from=builder /app/dependencies /app/
# ... final image ...
```

### Custom Configuration

```dockerfile
FROM react2shell-scanner:latest
# Add custom security policies, additional tools, etc.
```

## Support

- **Documentation:** See README.md and API.md
- **Issues:** Report bugs on GitHub
- **Security:** For security issues, contact security@example.com

## License

This Docker setup is part of the React2Shell Vulnerability Checker, licensed under MIT.
