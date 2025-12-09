#!/usr/bin/env python3
"""
React2Shell Vulnerability Detector
Platform: Cross-platform (Ubuntu Linux, Windows 10/11)
CVE-2025-55182 Detection Tool

This script detects potential React2Shell vulnerabilities by checking:
- package.json and lock files for vulnerable packages
- node_modules for vulnerable dependencies
- Remote URLs for passive detection
"""

import json
import os
import sys
import argparse
from pathlib import Path
import glob
import platform
from typing import List, Tuple, Optional, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from packaging import version
import time

# Import requests for URL checking
try:
    import requests
except ImportError:
    print("[ERROR] 'requests' module not found. Please install it using 'pip install requests'")
    sys.exit(1)


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """Validate URL to prevent SSRF attacks"""
    from urllib.parse import urlparse
    import ipaddress
    import socket

    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False, "Invalid URL format"

        # Prevent localhost and private IP access
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid hostname"

        if hostname in ['localhost', '127.0.0.1', '::1']:
            return False, "Localhost access not allowed"

        try:
            # Resolve hostname to IP
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)

            # Block private IPs
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return False, "Private IP access not allowed"

        except (socket.gaierror, ValueError):
            # If we can't resolve, allow but log warning
            pass

        return True, None
    except Exception as e:
        return False, f"URL validation error: {str(e)}"


def validate_path(path: Union[str, Path]) -> Tuple[bool, Union[str, Path]]:
    """Validate path to prevent directory traversal attacks"""
    try:
        # Resolve the path to handle relative paths and symlinks
        resolved_path = Path(path).resolve()

        # Check for directory traversal attempts
        if ".." in str(resolved_path):
            return False, "Directory traversal attempt detected"

        # Ensure the path exists
        if not resolved_path.exists():
            return False, "Path does not exist"

        return True, resolved_path
    except Exception as e:
        return False, f"Path validation error: {str(e)}"


def check_package_json(package_json_path: Union[str, Path]) -> List[Tuple[str, str]]:
    """Check package.json for vulnerable dependencies"""
    with open(package_json_path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"[ERROR] Invalid JSON in {package_json_path}")
            return []

    vulnerable_packages = [
        "react-server-dom-webpack",
        "react-server-dom-parcel",
        "react-server-dom-turbopack"
    ]

    detected_vulnerabilities: List[Tuple[str, str]] = []

    # Check dependencies
    for dep_section in ['dependencies', 'devDependencies']:
        if dep_section in data:
            deps = data[dep_section]
            for pkg in vulnerable_packages:
                if pkg in deps:
                    ver = deps[pkg]
                    detected_vulnerabilities.append((pkg, ver))

    # Check for React v19
    if 'react' in data.get('dependencies', {}) or 'react' in data.get('devDependencies', {}):
        react_ver = data.get('dependencies', {}).get('react') or data.get('devDependencies', {}).get('react')
        if react_ver and is_react_v19(react_ver):
            detected_vulnerabilities.append(('react', react_ver))

    return detected_vulnerabilities


def is_react_v19(version_str: str) -> bool:
    """Check if React version is 19.x.x"""
    try:
        # Handle version ranges like "^19.0.0", "~19.1.2", etc.
        version_clean = version_str.replace('^', '').replace('~', '').replace('>=', '').replace('<=', '').strip()

        # Extract just the version numbers
        if version_clean.startswith('v'):
            version_clean = version_clean[1:]

        parsed_version = version.parse(version_clean.split('.')[0])
        return parsed_version == 19
    except Exception:
        # If parsing fails, check if it contains '19'
        return '19.' in version_str or version_str.strip() == '19'


def check_lock_file(file_path: Union[str, Path]) -> List[Tuple[str, str]]:
    """Check lock files (package-lock.json, yarn.lock, pnpm-lock.yaml) for vulnerable packages"""
    vulnerabilities: List[Tuple[str, str]] = []

    if str(file_path).endswith('.json'):  # package-lock.json
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                print(f"[ERROR] Invalid JSON in {file_path}")
                return []

        # Recursively search for vulnerable packages
        def find_vulnerable_deps(obj: Union[dict, list], path: str = "") -> List[Tuple[str, str]]:
            found: List[Tuple[str, str]] = []
            vulnerable_packages = [
                "react-server-dom-webpack",
                "react-server-dom-parcel",
                "react-server-dom-turbopack"
            ]

            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key

                    # Check if this is a vulnerable package
                    if key in vulnerable_packages and 'version' in value:
                        found.append((key, value['version']))

                    # Check for React v19
                    if key == 'react' and 'version' in value:
                        if is_react_v19(value['version']):
                            found.append(('react', value['version']))

                    # Recursively search deeper
                    found.extend(find_vulnerable_deps(value, current_path))
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    current_path = f"{path}[{i}]"
                    found.extend(find_vulnerable_deps(item, current_path))

            return found

        vulnerabilities = find_vulnerable_deps(data)

    elif str(file_path).endswith('.lock') or str(file_path).endswith('.yaml'):  # yarn.lock or pnpm-lock.yaml
        # Simple text-based search for vulnerable packages
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        vulnerable_packages = [
            "react-server-dom-webpack",
            "react-server-dom-parcel",
            "react-server-dom-turbopack"
        ]

        for pkg in vulnerable_packages:
            if pkg in content:
                # Find version information near the package name
                import re
                pattern = rf'{pkg}[^a-zA-Z0-9].*?version.*?"([^"]+)"'
                matches = re.findall(pattern, content)
                for match in matches:
                    vulnerabilities.append((pkg, match))

    return vulnerabilities


def check_node_modules(node_modules_path: Union[str, Path]) -> List[Tuple[str, str]]:
    """Check node_modules for vulnerable packages"""
    vulnerabilities: List[Tuple[str, str]] = []
    vulnerable_packages = [
        "react-server-dom-webpack",
        "react-server-dom-parcel",
        "react-server-dom-turbopack"
    ]

    for pkg in vulnerable_packages:
        pkg_path = os.path.join(str(node_modules_path), pkg)
        if os.path.exists(pkg_path):
            # Look for package.json inside the package folder to get version
            package_json_path = os.path.join(pkg_path, 'package.json')
            if os.path.exists(package_json_path):
                with open(package_json_path, 'r', encoding='utf-8') as f:
                    try:
                        data = json.load(f)
                        ver = data.get('version', 'unknown')
                        vulnerabilities.append((pkg, ver))
                    except json.JSONDecodeError:
                        vulnerabilities.append((pkg, 'unknown'))
            else:
                vulnerabilities.append((pkg, 'found'))

    # Check for React v19
    react_path = os.path.join(str(node_modules_path), 'react')
    if os.path.exists(react_path):
        package_json_path = os.path.join(react_path, 'package.json')
        if os.path.exists(package_json_path):
            with open(package_json_path, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                    ver = data.get('version', 'unknown')
                    if is_react_v19(ver):
                        vulnerabilities.append(('react', ver))
                except json.JSONDecodeError:
                    pass

    return vulnerabilities


def passive_check_url(url: str) -> bool:
    """Perform passive check on a URL"""
    # Validate URL first
    is_valid, error_msg = validate_url(url)
    if not is_valid:
        print(f"[ERROR] URL validation failed: {error_msg}")
        return False

    try:
        # Set appropriate User-Agent based on platform
        if platform.system() == "Windows":
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        else:
            user_agent = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0'

        headers = {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
        }

        # Additional security: disable redirects to prevent SSRF through redirects
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=False)

        # Check for indicators of React usage
        content_type = response.headers.get('content-type', '').lower()
        body_lower = response.text.lower()

        # Look for signs of React usage
        has_react_indicators = (
            'react' in body_lower or
            'react' in content_type or
            'react' in response.headers.get('server', '').lower()
        )

        if has_react_indicators:
            print(f"[INFO] Potential React application detected at: {url}")
            return True
        else:
            print(f"[INFO] No clear React indicators found at: {url}")
            return False

    except requests.RequestException as e:
        print(f"[ERROR] Could not reach URL {url}: {str(e)}")
        return False


def find_project_root(start_path: Union[str, Path]) -> Optional[Path]:
    """Find the project root by looking for package.json"""
    path = Path(start_path).resolve()

    while path.parent != path:  # Stop at root directory
        if (path / 'package.json').exists():
            return path
        path = path.parent

    return None


def scan_path(path: Union[str, Path], max_workers: int = 4, show_progress: bool = True) -> List[Tuple[str, str]]:
    """Scan a path for React2Shell vulnerabilities"""
    start_time = time.time()

    # Validate path first
    is_valid, result = validate_path(path)
    if not is_valid:
        print(f"[ERROR] Path validation failed: {result}")
        return []

    abs_path = Path(result)  # Ensure it's a Path object
    print(f"[INFO] Scanning path: {abs_path}")

    vulnerabilities: List[Tuple[str, str]] = []

    # Collect all files to scan
    files_to_scan = []

    # Check for package.json
    pkg_json = abs_path / 'package.json'
    if pkg_json.exists():
        if show_progress:
            print(f"[INFO] Found package.json: {pkg_json}")
        files_to_scan.append(('package_json', str(pkg_json)))

    # Check for lock files
    lock_files = [
        ('package-lock.json', abs_path / 'package-lock.json'),
        ('yarn.lock', abs_path / 'yarn.lock'),
        ('pnpm-lock.yaml', abs_path / 'pnpm-lock.yaml')
    ]

    for file_type, file_path in lock_files:
        if file_path.exists():
            if show_progress:
                print(f"[INFO] Found {file_type}: {file_path}")
            files_to_scan.append((file_type, str(file_path)))

    # Check for node_modules
    node_modules = abs_path / 'node_modules'
    if node_modules.exists():
        if show_progress:
            print(f"[INFO] Found node_modules: {node_modules}")
        files_to_scan.append(('node_modules', str(node_modules)))

    # Also search in subdirectories for additional package.json files
    if show_progress:
        print("[INFO] Searching for additional package.json files...")

    for package_json_path in abs_path.rglob('package.json'):
        if package_json_path != pkg_json:  # Don't double count
            if show_progress:
                print(f"[INFO] Found additional package.json: {package_json_path}")
            files_to_scan.append(('package_json', str(package_json_path)))

    total_files = len(files_to_scan)
    if show_progress and total_files > 0:
        print(f"[INFO] Scanning {total_files} files with {max_workers} workers...")

    # Scan files in parallel
    def scan_file(file_info):
        file_type, file_path = file_info
        if file_type == 'package_json':
            return check_package_json(file_path)
        elif file_type in ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']:
            return check_lock_file(file_path)
        elif file_type == 'node_modules':
            return check_node_modules(file_path)
        return []

    completed = 0
    # Use ThreadPoolExecutor for parallel scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {executor.submit(scan_file, file_info): file_info for file_info in files_to_scan}

        for future in as_completed(future_to_file):
            try:
                vulns = future.result()
                vulnerabilities.extend(vulns)
                completed += 1
                if show_progress and total_files > 1:
                    progress = (completed / total_files) * 100
                    print(f"[INFO] Progress: {progress:.1f}% ({completed}/{total_files} files)")
            except Exception as e:
                file_info = future_to_file[future]
                print(f"[ERROR] Failed to scan {file_info[1]}: {str(e)}")

    # Remove duplicates while preserving order
    seen = set()
    unique_vulnerabilities = []
    for vuln in vulnerabilities:
        if vuln not in seen:
            seen.add(vuln)
            unique_vulnerabilities.append(vuln)

    elapsed_time = time.time() - start_time
    if show_progress:
        print(f"[INFO] Scan completed in {elapsed_time:.2f} seconds")

    return unique_vulnerabilities
    return unique_vulnerabilities


def print_vulnerabilities(vulnerabilities: List[Tuple[str, str]], json_output: bool = False) -> None:
    """Print vulnerabilities in a formatted way or JSON"""
    if json_output:
        import json
        result = {
            "vulnerabilities_found": len(vulnerabilities) > 0,
            "vulnerabilities": [{"package": pkg, "version": ver} for pkg, ver in vulnerabilities],
            "recommendations": {
                "react-server-dom-packages": "Upgrade to versions 19.0.1, 19.1.2, or 19.2.1",
                "react": "Upgrade to a patched version >= 19.x.x if needed"
            }
        }
        print(json.dumps(result, indent=2))
        return

    if not vulnerabilities:
        print("\n[SAFE] No vulnerabilities detected!")
        return

    print("\n[WARNING] Found potential vulnerabilities:")
    for pkg, ver in vulnerabilities:
        print(f"  - {pkg}@{ver}")

    print("\n[RECOMMENDATION] If any vulnerabilities are found, upgrade to patched versions:")
    print("  - For react-server-dom-* packages: 19.0.1, 19.1.2, or 19.2.1")
    print("  - For react: Upgrade to a patched version >= 19.x.x if needed")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="React2Shell (CVE-2025-55182) Vulnerability Detector for Cross-Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --path /path/to/your/project
  %(prog)s --url https://your-site.example
        """
    )

    parser.add_argument('--path', type=str, help='Path to scan for vulnerabilities')
    parser.add_argument('--url', type=str, help='URL to perform passive check on')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('--quiet', action='store_true', help='Suppress progress messages')
    parser.add_argument('--workers', type=int, default=4, help='Number of parallel workers (default: 4)')

    args = parser.parse_args()

    if not args.path and not args.url:
        parser.print_help()
        sys.exit(1)

    if args.path:
        try:
            show_progress = not args.quiet
            vulnerabilities = scan_path(args.path, max_workers=args.workers, show_progress=show_progress)
            print_vulnerabilities(vulnerabilities, args.json)
        except Exception as e:
            if args.json:
                import json
                error_result = {
                    "error": True,
                    "message": f"An error occurred during path scanning: {str(e)}"
                }
                print(json.dumps(error_result, indent=2))
            else:
                print(f"[ERROR] An error occurred during path scanning: {str(e)}")
            sys.exit(1)

    if args.url:
        try:
            result = passive_check_url(args.url)
            if args.json:
                import json
                url_result = {
                    "url_checked": args.url,
                    "react_indicators_found": result,
                    "recommendation": "Manual verification recommended" if result else "Appears unaffected"
                }
                print(json.dumps(url_result, indent=2))
            else:
                if result:
                    print(f"[INFO] URL {args.url} may be vulnerable. Manual verification recommended.")
                else:
                    print(f"[INFO] URL {args.url} appears to be unaffected based on initial check.")
        except Exception as e:
            if args.json:
                import json
                error_result = {
                    "error": True,
                    "message": f"An error occurred during URL scanning: {str(e)}"
                }
                print(json.dumps(error_result, indent=2))
            else:
                print(f"[ERROR] An error occurred during URL scanning: {str(e)}")
            sys.exit(1)


if __name__ == "__main__":
    main()