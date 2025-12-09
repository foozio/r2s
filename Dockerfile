# React2Shell Vulnerability Checker Docker Image

# Use Python 3.9 slim image for smaller size
FROM python:3.9-slim

# Set metadata
LABEL maintainer="Security Team <security@example.com>"
LABEL description="React2Shell (CVE-2025-55182) Vulnerability Detector"
LABEL version="2.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONHASHSEED=random

# Create non-root user for security
RUN groupadd -r scanner && useradd -r -g scanner scanner

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt requirements-dev.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY react2shell_checker_unified.py ./
COPY API.md TROUBLESHOOTING.md README.md ./

# Create directory for logs and scans
RUN mkdir -p /app/logs /app/scans \
    && chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python react2shell_checker_unified.py --help > /dev/null || exit 1

# Default command
ENTRYPOINT ["python", "react2shell_checker_unified.py"]

# Default arguments (can be overridden)
CMD ["--help"]