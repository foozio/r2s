#!/usr/bin/env python3
"""
React2Shell Vulnerability Detector
Platform: Windows 10/11
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
from packaging import version

# Import requests for URL checking
try:
    import requests
except ImportError:
    print("[ERROR] 'requests' module not found. Please install it using 'pip install requests'")
    sys.exit(1)


def check_package_json(package_json_path):
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
    
    detected_vulnerabilities = []
    
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


def is_react_v19(version_str):
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


def check_lock_file(file_path):
    """Check lock files (package-lock.json, yarn.lock, pnpm-lock.yaml) for vulnerable packages"""
    vulnerabilities = []
    
    if file_path.endswith('.json'):  # package-lock.json
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                print(f"[ERROR] Invalid JSON in {file_path}")
                return []
        
        # Recursively search for vulnerable packages
        def find_vulnerable_deps(obj, path=""):
            found = []
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
    
    elif file_path.endswith('.lock') or file_path.endswith('.yaml'):  # yarn.lock or pnpm-lock.yaml
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


def check_node_modules(node_modules_path):
    """Check node_modules for vulnerable packages"""
    vulnerabilities = []
    vulnerable_packages = [
        "react-server-dom-webpack",
        "react-server-dom-parcel", 
        "react-server-dom-turbopack"
    ]
    
    for pkg in vulnerable_packages:
        pkg_path = os.path.join(node_modules_path, pkg)
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
    react_path = os.path.join(node_modules_path, 'react')
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


def validate_url(url):
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


def passive_check_url(url):
    """Perform passive check on a URL"""
    # Validate URL first
    is_valid, error_msg = validate_url(url)
    if not is_valid:
        print(f"[ERROR] URL validation failed: {error_msg}")
        return False

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
            'Connection': 'close'
        }

        response = requests.get(url, headers=headers, timeout=10)
        
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


def find_project_root(start_path):
    """Find the project root by looking for package.json"""
    path = Path(start_path).resolve()
    
    while path.parent != path:  # Stop at root directory
        if (path / 'package.json').exists():
            return path
        path = path.parent
    
    return None


def validate_path(path):
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


def scan_path(path):
    """Scan a path for React2Shell vulnerabilities"""
    # Validate path first
    is_valid, result = validate_path(path)
    if not is_valid:
        print(f"[ERROR] Path validation failed: {result}")
        return []

    abs_path = Path(result)  # Ensure it's a Path object
    print(f"[INFO] Scanning path: {abs_path}")

    vulnerabilities = []
    
    # Check for package.json
    pkg_json = abs_path / 'package.json'
    if pkg_json.exists():
        print(f"[INFO] Found package.json: {pkg_json}")
        vulns = check_package_json(str(pkg_json))
        vulnerabilities.extend(vulns)
    
    # Check for package-lock.json
    pkg_lock_json = abs_path / 'package-lock.json'
    if pkg_lock_json.exists():
        print(f"[INFO] Found package-lock.json: {pkg_lock_json}")
        vulns = check_lock_file(str(pkg_lock_json))
        vulnerabilities.extend(vulns)
    
    # Check for yarn.lock
    yarn_lock = abs_path / 'yarn.lock'
    if yarn_lock.exists():
        print(f"[INFO] Found yarn.lock: {yarn_lock}")
        vulns = check_lock_file(str(yarn_lock))
        vulnerabilities.extend(vulns)
    
    # Check for pnpm-lock.yaml
    pnpm_lock = abs_path / 'pnpm-lock.yaml'
    if pnpm_lock.exists():
        print(f"[INFO] Found pnpm-lock.yaml: {pnpm_lock}")
        vulns = check_lock_file(str(pnpm_lock))
        vulnerabilities.extend(vulns)
    
    # Check for node_modules
    node_modules = abs_path / 'node_modules'
    if node_modules.exists():
        print(f"[INFO] Found node_modules: {node_modules}")
        vulns = check_node_modules(str(node_modules))
        vulnerabilities.extend(vulns)
    
    # Also search in subdirectories for additional package.json files
    for package_json_path in abs_path.rglob('package.json'):
        if package_json_path != pkg_json:  # Don't double count
            print(f"[INFO] Found additional package.json: {package_json_path}")
            vulns = check_package_json(str(package_json_path))
            # Filter out duplicates
            for vuln in vulns:
                if vuln not in vulnerabilities:
                    vulnerabilities.append(vuln)
    
    return vulnerabilities


def print_vulnerabilities(vulnerabilities):
    """Print vulnerabilities in a formatted way"""
    if not vulnerabilities:
        print("\n[SAFE] No vulnerabilities detected!")
        return
    
    print("\n[WARNING] Found potential vulnerabilities:")
    for pkg, ver in vulnerabilities:
        print(f"  - {pkg}@{ver}")
    
    print("\n[RECOMMENDATION] If any vulnerabilities are found, upgrade to patched versions:")
    print("  - For react-server-dom-* packages: 19.0.1, 19.1.2, or 19.2.1")
    print("  - For react: Upgrade to a patched version >= 19.x.x if needed")


def main():
    parser = argparse.ArgumentParser(
        description="React2Shell (CVE-2025-55182) Vulnerability Detector for Windows 10/11",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --path /path/to/your/project
  %(prog)s --url https://your-site.example
        """
    )
    
    parser.add_argument('--path', type=str, help='Path to scan for vulnerabilities')
    parser.add_argument('--url', type=str, help='URL to perform passive check on')
    
    args = parser.parse_args()
    
    if not args.path and not args.url:
        parser.print_help()
        sys.exit(1)
    
    if args.path:
        try:
            vulnerabilities = scan_path(args.path)
            print_vulnerabilities(vulnerabilities)
        except Exception as e:
            print(f"[ERROR] An error occurred during path scanning: {str(e)}")
            sys.exit(1)
    
    if args.url:
        try:
            result = passive_check_url(args.url)
            if result:
                print(f"[INFO] URL {args.url} may be vulnerable. Manual verification recommended.")
            else:
                print(f"[INFO] URL {args.url} appears to be unaffected based on initial check.")
        except Exception as e:
            print(f"[ERROR] An error occurred during URL scanning: {str(e)}")
            sys.exit(1)


if __name__ == "__main__":
    main()