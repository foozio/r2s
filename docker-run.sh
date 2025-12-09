#!/bin/bash
# Docker build and run script for React2Shell Vulnerability Checker

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running. Please start Docker."
        exit 1
    fi

    print_success "Docker is available"
}

# Build Docker image
build_image() {
    print_info "Building React2Shell scanner Docker image..."
    docker build -t react2shell-scanner:latest .
    print_success "Docker image built successfully"
}

# Run basic help command
test_image() {
    print_info "Testing Docker image..."
    docker run --rm react2shell-scanner:latest --help > /dev/null
    print_success "Docker image test passed"
}

# Scan a local path
scan_path() {
    local path="$1"
    if [ -z "$path" ]; then
        print_error "Please provide a path to scan"
        echo "Usage: $0 scan-path /path/to/project"
        exit 1
    fi

    if [ ! -d "$path" ]; then
        print_error "Path does not exist: $path"
        exit 1
    fi

    print_info "Scanning path: $path"

    # Create output directories
    mkdir -p scans logs

    # Run scan
    docker run --rm \
        -v "$(pwd)/scans:/app/scans" \
        -v "$(pwd)/logs:/app/logs" \
        -v "$path:/app/target-project:ro" \
        react2shell-scanner:latest \
        --path /app/target-project \
        --json \
        --log-file /app/logs/scan_$(date +%Y%m%d_%H%M%S).log
}

# Scan a URL
scan_url() {
    local url="$1"
    if [ -z "$url" ]; then
        print_error "Please provide a URL to scan"
        echo "Usage: $0 scan-url https://example.com"
        exit 1
    fi

    print_info "Scanning URL: $url"

    # Create output directories
    mkdir -p logs

    # Run URL scan
    docker run --rm \
        -v "$(pwd)/logs:/app/logs" \
        react2shell-scanner:latest \
        --url "$url" \
        --json \
        --verbose \
        --log-file /app/logs/url_scan_$(date +%Y%m%d_%H%M%S).log
}

# Show usage
usage() {
    echo "React2Shell Vulnerability Checker - Docker Runner"
    echo ""
    echo "Usage:"
    echo "  $0 build          Build Docker image"
    echo "  $0 test           Test Docker image"
    echo "  $0 scan-path <path>    Scan a local project path"
    echo "  $0 scan-url <url>      Scan a URL"
    echo "  $0 help           Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 build"
    echo "  $0 scan-path ./my-react-project"
    echo "  $0 scan-url https://my-app.com"
    echo ""
    echo "Output will be saved to ./scans/ and ./logs/ directories"
}

# Main script logic
case "${1:-help}" in
    build)
        check_docker
        build_image
        test_image
        ;;
    test)
        check_docker
        test_image
        ;;
    scan-path)
        check_docker
        scan_path "$2"
        ;;
    scan-url)
        check_docker
        scan_url "$2"
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        print_error "Unknown command: $1"
        echo ""
        usage
        exit 1
        ;;
esac