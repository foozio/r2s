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
import logging
from pathlib import Path
import glob
import platform
from typing import List, Tuple, Optional, Union, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from packaging import version
import time
import hashlib
import pickle

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Import requests for URL checking
try:
    import requests
except ImportError:
    print("[ERROR] 'requests' module not found. Please install it using 'pip install requests'")
    sys.exit(1)


# Configure logging
def setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> logging.Logger:
    """Set up structured logging for the application"""
    logger = logging.getLogger('react2shell')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Remove any existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


# Global logger instance
logger = setup_logging()


def load_config(config_file: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from YAML file"""
    default_config = {
        'vulnerable_packages': {
            'react-server-dom-webpack': ['<19.0.1'],
            'react-server-dom-parcel': ['<19.1.2'],
            'react-server-dom-turbopack': ['<19.2.1'],
            'react': ['^19.0.0']
        },
        'custom_vulnerable_packages': {},
        'scan': {
            'max_workers': 4,
            'timeout': 300,
            'max_files': 1000,
            'file_types': ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'node_modules'],
            'exclude_dirs': ['node_modules', '.git', '.svn', '__pycache__', '.pytest_cache']
        },
        'logging': {
            'level': 'INFO',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            'file': None
        },
        'url_scan': {
            'timeout': 10,
            'user_agents': {
                'windows': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'linux': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
                'macos': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        },
        'output': {
            'format': 'text',
            'show_recommendations': True,
            'show_metadata': True
        }
    }

    if config_file and YAML_AVAILABLE:
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                user_config = yaml.safe_load(f) or {}
            # Merge user config with defaults
            def merge_dicts(default: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
                result = default.copy()
                for key, value in user.items():
                    if isinstance(value, dict) and key in result and isinstance(result[key], dict):
                        result[key] = merge_dicts(result[key], value)
                    else:
                        result[key] = value
                return result
            return merge_dicts(default_config, user_config)
        except Exception as e:
            logger.warning(f"Could not load config file {config_file}: {e}")
            logger.info("Using default configuration")

    return default_config


# Global configuration
config = load_config()


class ScanCache:
    """Simple file-based cache for scan results"""

    def __init__(self, cache_dir: Optional[str] = None, max_age: int = 3600):
        """Initialize cache

        Args:
            cache_dir: Directory to store cache files (default: ~/.react2shell/cache)
            max_age: Maximum age of cache entries in seconds (default: 1 hour)
        """
        if cache_dir is None:
            home = os.path.expanduser("~")
            cache_dir = os.path.join(home, ".react2shell", "cache")

        self.cache_dir = Path(cache_dir)
        self.max_age = max_age
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_key(self, path: Union[str, Path], config_hash: str) -> str:
        """Generate cache key from path and configuration"""
        path_str = str(Path(path).resolve())
        key_data = f"{path_str}:{config_hash}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _get_cache_file(self, cache_key: str) -> Path:
        """Get cache file path for key"""
        return self.cache_dir / f"{cache_key}.cache"

    def _is_cache_valid(self, cache_file: Path) -> bool:
        """Check if cache file is still valid"""
        if not cache_file.exists():
            return False

        # Check file age
        mtime = cache_file.stat().st_mtime
        age = time.time() - mtime
        return age < self.max_age

    def get(self, path: Union[str, Path], config_hash: str) -> Optional[List[Tuple[str, str]]]:
        """Get cached scan results"""
        cache_key = self._get_cache_key(path, config_hash)
        cache_file = self._get_cache_file(cache_key)

        if not self._is_cache_valid(cache_file):
            return None

        try:
            with open(cache_file, 'rb') as f:
                cached_data = pickle.load(f)
                logger.debug(f"Cache hit for {path}")
                return cached_data
        except Exception as e:
            logger.debug(f"Cache read error for {path}: {e}")
            return None

    def set(self, path: Union[str, Path], config_hash: str, results: List[Tuple[str, str]]) -> None:
        """Cache scan results"""
        cache_key = self._get_cache_key(path, config_hash)
        cache_file = self._get_cache_file(cache_key)

        try:
            with open(cache_file, 'wb') as f:
                pickle.dump(results, f)
            logger.debug(f"Cached results for {path}")
        except Exception as e:
            logger.debug(f"Cache write error for {path}: {e}")

    def clear(self) -> None:
        """Clear all cache files"""
        for cache_file in self.cache_dir.glob("*.cache"):
            try:
                cache_file.unlink()
            except Exception:
                pass
        logger.info("Cache cleared")


# Global cache instance
scan_cache = ScanCache()


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """Validate URL to prevent SSRF attacks"""
    from urllib.parse import urlparse
    import ipaddress
    import socket

    logger.debug(f"Validating URL: {url}")

    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            logger.warning(f"Invalid URL format: {url}")
            return False, "Invalid URL format"

        # Prevent localhost and private IP access
        hostname = parsed.hostname
        if not hostname:
            logger.warning(f"Invalid hostname in URL: {url}")
            return False, "Invalid hostname"

        if hostname in ['localhost', '127.0.0.1', '::1']:
            logger.warning(f"Blocked localhost access attempt: {url}")
            return False, "Localhost access not allowed"

        try:
            # Resolve hostname to IP
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)

            # Block private IPs
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                logger.warning(f"Blocked private IP access: {hostname} ({ip})")
                return False, "Private IP access not allowed"

            logger.debug(f"URL validation passed for {hostname} ({ip})")

        except (socket.gaierror, ValueError) as e:
            # If we can't resolve, allow but log warning
            logger.warning(f"Could not resolve hostname {hostname}: {e}")
            pass

        return True, None
    except Exception as e:
        logger.error(f"URL validation error for {url}: {str(e)}")
        return False, f"URL validation error: {str(e)}"


def validate_path(path: Union[str, Path]) -> Tuple[bool, Union[str, Path]]:
    """Validate path to prevent directory traversal attacks"""
    logger.debug(f"Validating path: {path}")

    try:
        # Resolve the path to handle relative paths and symlinks
        resolved_path = Path(path).resolve()

        # Check for directory traversal attempts
        if ".." in str(resolved_path):
            logger.warning(f"Directory traversal attempt detected in path: {path}")
            return False, "Directory traversal attempt detected"

        # Ensure the path exists
        if not resolved_path.exists():
            logger.warning(f"Path does not exist: {resolved_path}")
            return False, "Path does not exist"

        logger.debug(f"Path validation passed: {resolved_path}")
        return True, resolved_path
    except Exception as e:
        logger.error(f"Path validation error for {path}: {str(e)}")
        return False, f"Path validation error: {str(e)}"


def check_package_json(package_json_path: Union[str, Path]) -> List[Tuple[str, str]]:
    """Check package.json for vulnerable dependencies"""
    logger.debug(f"Checking package.json: {package_json_path}")

    try:
        with open(package_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {package_json_path}: {e}")
        return []
    except Exception as e:
        logger.error(f"Error reading {package_json_path}: {e}")
        return []

    # Get vulnerable packages from config
    vulnerable_packages = config['vulnerable_packages'].copy()
    vulnerable_packages.update(config['custom_vulnerable_packages'])

    detected_vulnerabilities: List[Tuple[str, str]] = []

    # Check dependencies
    for dep_section in ['dependencies', 'devDependencies']:
        if dep_section in data:
            deps = data[dep_section]
            for pkg, vuln_ranges in vulnerable_packages.items():
                if pkg in deps:
                    ver = deps[pkg]
                    # Use enhanced version checking
                    if pkg == "react":
                        if is_react_v19(ver):
                            logger.info(f"Found React v19: {ver} in {package_json_path}")
                            detected_vulnerabilities.append((pkg, ver))
                    else:
                        # For other packages, check against vulnerable ranges
                        if check_version_vulnerable(pkg, ver, vuln_ranges):
                            logger.info(f"Found vulnerable package: {pkg}@{ver} in {package_json_path}")
                            detected_vulnerabilities.append((pkg, ver))

    logger.debug(f"Found {len(detected_vulnerabilities)} vulnerabilities in {package_json_path}")
    return detected_vulnerabilities


def parse_version_range(version_str: str) -> Optional[Tuple[version.Version, version.Version]]:
    """Parse version range specifications and return min/max version bounds"""
    version_str = version_str.strip()

    # Handle common version range patterns
    if version_str.startswith('^'):
        # ^19.0.0 means >=19.0.0 <20.0.0
        base_version = version_str[1:]
        try:
            min_ver = version.parse(base_version)
            max_ver = version.parse(f"{min_ver.major + 1}.0.0")
            return min_ver, max_ver
        except:
            return None

    elif version_str.startswith('~'):
        # ~19.1.0 means >=19.1.0 <19.2.0
        base_version = version_str[1:]
        try:
            min_ver = version.parse(base_version)
            max_ver = version.parse(f"{min_ver.major}.{min_ver.minor + 1}.0")
            return min_ver, max_ver
        except:
            return None

    elif '>=' in version_str:
        # >=19.0.0
        parts = version_str.split('>=', 1)
        if len(parts) == 2:
            try:
                min_ver = version.parse(parts[1].strip())
                return min_ver, None  # No upper bound
            except:
                return None

    elif '<=' in version_str:
        # <=19.2.0
        parts = version_str.split('<=', 1)
        if len(parts) == 2:
            try:
                max_ver = version.parse(parts[1].strip())
                return None, max_ver  # No lower bound
            except:
                return None

    elif ' - ' in version_str:
        # 19.0.0 - 19.2.0
        parts = version_str.split(' - ', 1)
        if len(parts) == 2:
            try:
                min_ver = version.parse(parts[0].strip())
                max_ver = version.parse(parts[1].strip())
                return min_ver, max_ver
            except:
                return None

    # Try to parse as exact version
    try:
        exact_ver = version.parse(version_str)
        return exact_ver, exact_ver
    except:
        return None


def is_react_v19(version_str: str) -> bool:
    """Check if React version is 19.x.x using semantic versioning"""
    logger.debug(f"Checking if version is React v19: {version_str}")

    try:
        # Parse version range
        version_range = parse_version_range(version_str)

        if version_range is None:
            logger.warning(f"Could not parse version range: {version_str}")
            # Fallback to simple string check
            return '19.' in version_str or version_str.strip() == '19'

        min_ver, max_ver = version_range

        # Check if the range overlaps with React 19.x.x
        react_19_min = version.parse("19.0.0")
        react_19_max = version.parse("20.0.0")

        # If we have a minimum version >= 19.0.0, it's React 19
        if min_ver and min_ver >= react_19_min:
            logger.debug(f"Version {version_str} matches React v19 (min: {min_ver})")
            return True

        # If we have a range that includes React 19 versions
        if min_ver and max_ver:
            # Check if ranges overlap: [min_ver, max_ver) overlaps with [19.0.0, 20.0.0)
            if min_ver < react_19_max and max_ver > react_19_min:
                logger.debug(f"Version range {version_str} overlaps with React v19")
                return True

        # If only max version is specified and it's >= 20.0.0, could include v19
        if max_ver and max_ver >= react_19_max and (min_ver is None or min_ver <= react_19_min):
            logger.debug(f"Version range {version_str} could include React v19")
            return True

        logger.debug(f"Version {version_str} does not match React v19")
        return False

    except Exception as e:
        logger.warning(f"Error parsing version {version_str}: {e}")
        # Fallback to simple string check
        return '19.' in version_str or version_str.strip() == '19'


def check_version_vulnerable(package_name: str, version_str: str, vulnerable_ranges: List[str]) -> bool:
    """Check if a package version is vulnerable based on version ranges"""
    logger.debug(f"Checking if {package_name}@{version_str} is vulnerable")

    try:
        package_version = parse_version_range(version_str)
        if package_version is None:
            logger.warning(f"Could not parse package version: {version_str}")
            return False

        pkg_min, pkg_max = package_version

        for vuln_range_str in vulnerable_ranges:
            vuln_range = parse_version_range(vuln_range_str)
            if vuln_range is None:
                continue

            vuln_min, vuln_max = vuln_range

            # Check if package version range overlaps with vulnerable range
            # This is a simplified overlap check
            overlap = False

            if pkg_min and vuln_min and pkg_min <= vuln_max and pkg_max >= vuln_min:
                overlap = True
            elif pkg_min and vuln_min is None and pkg_min <= vuln_max:
                overlap = True
            elif pkg_max and vuln_max is None and pkg_max >= vuln_min:
                overlap = True

            if overlap:
                logger.info(f"Package {package_name}@{version_str} is vulnerable (matches range {vuln_range_str})")
                return True

        logger.debug(f"Package {package_name}@{version_str} is not vulnerable")
        return False

    except Exception as e:
        logger.error(f"Error checking version vulnerability for {package_name}@{version_str}: {e}")
        return False


def check_lock_file(file_path: Union[str, Path]) -> List[Tuple[str, str]]:
    """Check lock files (package-lock.json, yarn.lock, pnpm-lock.yaml) for vulnerable packages"""
    vulnerabilities: List[Tuple[str, str]] = []

    if str(file_path).endswith('.json'):  # package-lock.json
        try:
            # Use streaming JSON parsing for large files to reduce memory usage
            with open(file_path, 'r', encoding='utf-8') as f:
                # Read file size to determine parsing strategy
                f.seek(0, 2)
                file_size = f.tell()
                f.seek(0)

                if file_size > 50 * 1024 * 1024:  # 50MB threshold
                    logger.warning(f"Large lockfile detected ({file_size} bytes), using streaming approach")
                    # For very large files, use a more memory-efficient approach
                    content = f.read()
                    # Simple string search instead of full JSON parsing for large files
                    vulnerable_packages = config['vulnerable_packages'].copy()
                    vulnerable_packages.update(config['custom_vulnerable_packages'])

                    for pkg, vuln_ranges in vulnerable_packages.items():
                        if f'"{pkg}"' in content:
                            # Extract version using regex patterns
                            import re
                            version_patterns = [
                                rf'"{pkg}":\s*{{\s*"version":\s*"([^"]+)"',
                                rf'"{pkg}":\s*"([^"]+)"',
                            ]
                            for pattern in version_patterns:
                                matches = re.findall(pattern, content)
                                for ver in matches:
                                    if pkg == "react":
                                        if is_react_v19(ver):
                                            vulnerabilities.append((pkg, ver))
                                    else:
                                        if check_version_vulnerable(pkg, ver, vuln_ranges):
                                            vulnerabilities.append((pkg, ver))
                    return vulnerabilities

                # Standard JSON parsing for normal-sized files
                data = json.load(f)
        except json.JSONDecodeError:
            print(f"[ERROR] Invalid JSON in {file_path}")
            return []

        # Recursively search for vulnerable packages
        def find_vulnerable_deps(obj: Union[dict, list], path: str = "") -> List[Tuple[str, str]]:
            found: List[Tuple[str, str]] = []
            vulnerable_packages = config['vulnerable_packages'].copy()
            vulnerable_packages.update(config['custom_vulnerable_packages'])

            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key

                    # Check if this is a vulnerable package
                    if key in vulnerable_packages and 'version' in value:
                        ver = value['version']
                        vuln_ranges = vulnerable_packages[key]
                        if key == "react":
                            if is_react_v19(ver):
                                logger.info(f"Found React v19 in lockfile: {key}@{ver}")
                                found.append((key, ver))
                        else:
                            if check_version_vulnerable(key, ver, vuln_ranges):
                                logger.info(f"Found vulnerable package in lockfile: {key}@{ver}")
                                found.append((key, ver))

                    # Recursively search deeper (limit depth for memory efficiency)
                    if len(current_path.split('.')) < 10:  # Prevent excessive recursion
                        found.extend(find_vulnerable_deps(value, current_path))
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    current_path = f"{path}[{i}]"
                    if i < 100:  # Limit array processing for memory efficiency
                        found.extend(find_vulnerable_deps(item, current_path))

            return found

        vulnerabilities = find_vulnerable_deps(data)

    elif str(file_path).endswith('.lock') or str(file_path).endswith('.yaml'):  # yarn.lock or pnpm-lock.yaml
        # Memory-efficient text-based search for vulnerable packages
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Read file in chunks for large files to manage memory
                chunk_size = 8192
                vulnerable_packages = config['vulnerable_packages'].copy()
                vulnerable_packages.update(config['custom_vulnerable_packages'])

                found_packages = set()

                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    for pkg, vuln_ranges in vulnerable_packages.items():
                        if pkg in chunk and pkg not in found_packages:
                            found_packages.add(pkg)
                            # Find version information near the package name
                            import re
                            pattern = rf'{pkg}[^a-zA-Z0-9].*?version.*?"([^"]+)"'
                            matches = re.findall(pattern, chunk)
                            for match in matches:
                                # Use enhanced version checking
                                if pkg == "react":
                                    if is_react_v19(match):
                                        logger.info(f"Found React v19 in lockfile: {pkg}@{match}")
                                        vulnerabilities.append((pkg, match))
                                else:
                                    if check_version_vulnerable(pkg, match, vuln_ranges):
                                        logger.info(f"Found vulnerable package in lockfile: {pkg}@{match}")
                                        vulnerabilities.append((pkg, match))
        except Exception as e:
            logger.error(f"Error reading lockfile {file_path}: {e}")

    elif str(file_path).endswith('.lockb'):  # bun.lockb (binary format)
        # Memory-efficient processing of Bun's binary lockfile format
        try:
            # Check file size first
            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024:  # 100MB limit for binary files
                logger.warning(f"Bun lockfile too large ({file_size} bytes), skipping")
                return []

            with open(file_path, 'rb') as f:
                # Read in chunks to manage memory
                chunk_size = 16384  # 16KB chunks
                vulnerable_packages = config['vulnerable_packages'].copy()
                vulnerable_packages.update(config['custom_vulnerable_packages'])

                found_versions = {}

                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    # Convert to string for pattern matching (ignore decode errors)
                    try:
                        text_chunk = chunk.decode('utf-8', errors='ignore')
                    except:
                        continue

                    for pkg, vuln_ranges in vulnerable_packages.items():
                        if pkg in text_chunk:
                            # Try to find version patterns in the content
                            import re
                            patterns = [
                                rf'{pkg}[^a-zA-Z0-9]*([0-9]+\.[0-9]+\.[0-9]+)',  # x.y.z format
                                rf'{pkg}[^a-zA-Z0-9]*v?([0-9]+\.[0-9]+\.[0-9]+)', # vx.y.z format
                                rf'{pkg}[^a-zA-Z0-9]*"([^"]+)"',  # quoted versions
                            ]

                            for pattern in patterns:
                                matches = re.findall(pattern, text_chunk)
                                for version in matches:
                                    if pkg not in found_versions:
                                        found_versions[pkg] = set()
                                    found_versions[pkg].add(version)

                # Process found versions
                for pkg, versions in found_versions.items():
                    vuln_ranges = vulnerable_packages[pkg]
                    for version in versions:
                        # Use enhanced version checking
                        if pkg == "react":
                            if is_react_v19(version):
                                vulnerabilities.append((pkg, version))
                        else:
                            if check_version_vulnerable(pkg, version, vuln_ranges):
                                vulnerabilities.append((pkg, version))

            logger.debug(f"Processed bun.lockb file: {file_path}")

        except Exception as e:
            logger.warning(f"Could not process bun.lockb file {file_path}: {e}")
            # Don't add to vulnerabilities, just log the issue

    return vulnerabilities


def check_node_modules(node_modules_path: Union[str, Path]) -> List[Tuple[str, str]]:
    """Check node_modules for vulnerable packages"""
    vulnerabilities: List[Tuple[str, str]] = []
    vulnerable_packages = config['vulnerable_packages'].copy()
    vulnerable_packages.update(config['custom_vulnerable_packages'])

    for pkg, vuln_ranges in vulnerable_packages.items():
        pkg_path = os.path.join(str(node_modules_path), pkg)
        if os.path.exists(pkg_path):
            # Look for package.json inside the package folder to get version
            package_json_path = os.path.join(pkg_path, 'package.json')
            if os.path.exists(package_json_path):
                with open(package_json_path, 'r', encoding='utf-8') as f:
                    try:
                        data = json.load(f)
                        ver = data.get('version', 'unknown')
                        # Use enhanced version checking
                        if pkg == "react":
                            if is_react_v19(ver):
                                logger.info(f"Found React v19 in node_modules: {pkg}@{ver}")
                                vulnerabilities.append((pkg, ver))
                        else:
                            if check_version_vulnerable(pkg, ver, vuln_ranges):
                                logger.info(f"Found vulnerable package in node_modules: {pkg}@{ver}")
                                vulnerabilities.append((pkg, ver))
                    except json.JSONDecodeError:
                        logger.warning(f"Could not parse package.json for {pkg}")
            else:
                logger.debug(f"No package.json found for {pkg}, marking as found")
                vulnerabilities.append((pkg, 'found'))

    return vulnerabilities


def passive_check_url(url: str) -> bool:
    """Perform passive check on a URL"""
    logger.debug(f"Starting passive URL check: {url}")

    # Validate URL first
    is_valid, error_msg = validate_url(url)
    if not is_valid:
        logger.error(f"URL validation failed for {url}: {error_msg}")
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

        logger.debug(f"Making HTTP request to {url}")
        response = requests.get(url, headers=headers, timeout=10)

        # Enhanced React detection in response
        content_type = response.headers.get('content-type', '').lower()
        body_lower = response.text.lower()
        server_header = response.headers.get('server', '').lower()

        # Comprehensive React detection patterns
        react_indicators = {
            'body_contains_react': 'react' in body_lower,
            'content_type_react': 'react' in content_type,
            'server_header_react': 'react' in server_header,
            'body_contains_nextjs': 'next.js' in body_lower or '_next' in body_lower,
            'body_contains_gatsby': 'gatsby' in body_lower,
            'body_contains_create_react_app': 'react-app' in body_lower,
            'body_contains_react_scripts': 'react-scripts' in body_lower,
            'body_contains_react_dom': 'react-dom' in body_lower,
            'body_contains_jsx': 'jsx' in body_lower or 'tsx' in body_lower,
            'body_contains_react_hook': 'useState' in body_lower or 'useEffect' in body_lower,
            'body_contains_react_component': 'componentDidMount' in body_lower or 'render()' in body_lower,
            'headers_react_dev': 'x-react' in str(response.headers).lower(),
            'body_contains_react_error': 'react error' in body_lower or 'react warning' in body_lower,
            'body_contains_react_devtools': 'react_devtools' in body_lower,
            'url_contains_react': 'react' in url.lower(),
            'body_contains_react_version': 'react@' in body_lower or 'react/' in body_lower
        }

        # Check if any React indicators are found
        found_indicators = [key for key, found in react_indicators.items() if found]
        has_react_indicators = len(found_indicators) > 0

        logger.debug(f"React detection for {url}: found {len(found_indicators)} indicators: {found_indicators}")

        if has_react_indicators:
            logger.info(f"Potential React application detected at: {url}")
            logger.debug(f"React indicators found - body: {'react' in body_lower}, content-type: {'react' in content_type}, server: {'react' in server_header}")
            return True
        else:
            logger.info(f"No clear React indicators found at: {url}")
            return False

    except requests.RequestException as e:
        logger.error(f"Could not reach URL {url}: {str(e)}")
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


def scan_path(path: Union[str, Path], max_workers: Optional[int] = None, show_progress: bool = True, use_cache: bool = True) -> List[Tuple[str, str]]:
    """Scan a path for React2Shell vulnerabilities"""
    start_time = time.time()
    logger.info(f"Starting scan of path: {path}")

    # Validate path first
    is_valid, result = validate_path(path)
    if not is_valid:
        logger.error(f"Path validation failed: {result}")
        return []

    abs_path = Path(result)  # Ensure it's a Path object
    logger.info(f"Scanning path: {abs_path}")

    # Use config values if not specified
    if max_workers is None:
        max_workers = config['scan']['max_workers']

    # Check cache first
    config_hash = hashlib.md5(str(config).encode()).hexdigest()
    if use_cache:
        cached_results = scan_cache.get(abs_path, config_hash)
        if cached_results is not None:
            logger.info(f"Using cached results for {abs_path}")
            if show_progress:
                print(f"[INFO] Scan completed in {time.time() - start_time:.2f} seconds (from cache)")
            return cached_results

    vulnerabilities: List[Tuple[str, str]] = []

    # Collect all files to scan
    files_to_scan = []

    # Check for package.json
    pkg_json = abs_path / 'package.json'
    if pkg_json.exists():
        logger.debug(f"Found package.json: {pkg_json}")
        if show_progress:
            print(f"[INFO] Found package.json: {pkg_json}")
        files_to_scan.append(('package_json', str(pkg_json)))

    # Check for lock files
    lock_files = [
        ('package-lock.json', abs_path / 'package-lock.json'),
        ('yarn.lock', abs_path / 'yarn.lock'),
        ('pnpm-lock.yaml', abs_path / 'pnpm-lock.yaml'),
        ('bun.lockb', abs_path / 'bun.lockb')
    ]

    for file_type, file_path in lock_files:
        if file_path.exists():
            logger.debug(f"Found {file_type}: {file_path}")
            if show_progress:
                print(f"[INFO] Found {file_type}: {file_path}")
            files_to_scan.append((file_type, str(file_path)))

    # Check for node_modules
    node_modules = abs_path / 'node_modules'
    if node_modules.exists():
        logger.debug(f"Found node_modules: {node_modules}")
        if show_progress:
            print(f"[INFO] Found node_modules: {node_modules}")
        files_to_scan.append(('node_modules', str(node_modules)))

    # Also search in subdirectories for additional package.json files
    logger.debug("Searching for additional package.json and lock files...")
    if show_progress:
        print("[INFO] Searching for additional package.json and lock files...")

    for package_json_path in abs_path.rglob('package.json'):
        if package_json_path != pkg_json:  # Don't double count
            logger.debug(f"Found additional package.json: {package_json_path}")
            if show_progress:
                print(f"[INFO] Found additional package.json: {package_json_path}")
            files_to_scan.append(('package_json', str(package_json_path)))

    # Search for additional lock files in subdirectories
    for lock_file_path in abs_path.rglob('*.lock'):
        if lock_file_path.name not in ['package-lock.json', 'yarn.lock']:
            logger.debug(f"Found additional lock file: {lock_file_path}")
            if show_progress:
                print(f"[INFO] Found additional lock file: {lock_file_path}")
            files_to_scan.append(('lock_file', str(lock_file_path)))

    for lockb_file_path in abs_path.rglob('*.lockb'):
        logger.debug(f"Found bun lock file: {lockb_file_path}")
        if show_progress:
            print(f"[INFO] Found bun lock file: {lockb_file_path}")
        files_to_scan.append(('bun.lockb', str(lockb_file_path)))

    total_files = len(files_to_scan)
    logger.info(f"Found {total_files} files to scan")
    if show_progress and total_files > 0:
        print(f"[INFO] Scanning {total_files} files with {max_workers} workers...")

    # Scan files in parallel with memory optimization
    def scan_file(file_info):
        file_type, file_path = file_info
        try:
            if file_type == 'package_json':
                return check_package_json(file_path)
            elif file_type in ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'lock_file']:
                return check_lock_file(file_path)
            elif file_type == 'bun.lockb':
                return check_lock_file(file_path)  # Reuse the same logic
            elif file_type == 'node_modules':
                return check_node_modules(file_path)
            return []
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
            return []

    # Use ThreadPoolExecutor for parallel scanning with memory management
    completed = 0
    batch_size = min(50, max_workers * 2)  # Process in batches to manage memory

    # Process files in batches to optimize memory usage
    for i in range(0, len(files_to_scan), batch_size):
        batch = files_to_scan[i:i + batch_size]

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {executor.submit(scan_file, file_info): file_info for file_info in batch}

            for future in as_completed(future_to_file):
                try:
                    vulns = future.result()
                    vulnerabilities.extend(vulns)
                    completed += 1
                    if show_progress and total_files > 1:
                        progress = (completed / total_files) * 100
                        print(f"[INFO] Progress: {progress:.1f}% ({completed}/{total_files} files)")
                        logger.debug(f"Completed {completed}/{total_files} files")
                except Exception as e:
                    file_info = future_to_file[future]
                    error_msg = f"Failed to scan {file_info[1]}: {str(e)}"
                    logger.error(error_msg)
                    if show_progress:
                        print(f"[ERROR] {error_msg}")

        # Force garbage collection between batches for large scans
        if len(files_to_scan) > 100:
            import gc
            gc.collect()
            logger.debug("Garbage collection performed between batches")

    # Remove duplicates while preserving order (memory efficient)
    seen = set()
    unique_vulnerabilities = []
    for vuln in vulnerabilities:
        vuln_tuple = tuple(vuln)  # Ensure hashable
        if vuln_tuple not in seen:
            seen.add(vuln_tuple)
            unique_vulnerabilities.append(vuln)

    # Clear intermediate data structures to free memory
    del vulnerabilities
    del seen

    elapsed_time = time.time() - start_time
    logger.info(f"Scan completed in {elapsed_time:.2f} seconds, found {len(unique_vulnerabilities)} vulnerabilities")
    if show_progress:
        print(f"[INFO] Scan completed in {elapsed_time:.2f} seconds")

    # Cache results
    if use_cache:
        scan_cache.set(abs_path, config_hash, unique_vulnerabilities)

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
  %(prog)s --path /project --verbose --log-file scan.log
        """
    )

    parser.add_argument('--path', type=str, help='Path to scan for vulnerabilities')
    parser.add_argument('--url', type=str, help='URL to perform passive check on')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('--quiet', action='store_true', help='Suppress progress messages')
    parser.add_argument('--workers', type=int, help='Number of parallel workers (default: from config)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--log-file', type=str, help='Log to specified file')
    parser.add_argument('--config', type=str, help='Path to configuration file')
    parser.add_argument('--no-cache', action='store_true', help='Disable caching of scan results')
    parser.add_argument('--clear-cache', action='store_true', help='Clear scan cache and exit')

    args = parser.parse_args()

    # Handle special commands
    if args.clear_cache:
        scan_cache.clear()
        print("[INFO] Cache cleared")
        sys.exit(0)

    if not args.path and not args.url:
        parser.print_help()
        sys.exit(1)

    # Load configuration
    global config
    config = load_config(args.config)

    # Setup logging based on arguments and config
    log_level = 'DEBUG' if args.verbose else config['logging']['level']
    log_file = args.log_file or config['logging']['file']

    global logger
    logger = setup_logging(verbose=(log_level == 'DEBUG'), log_file=log_file)

    logger.info("React2Shell Vulnerability Checker started")
    logger.debug(f"Arguments: {vars(args)}")

    show_progress = not args.quiet

    if args.path:
        try:
            logger.info(f"Starting path scan: {args.path}")
            workers = args.workers if args.workers is not None else None
            use_cache = not args.no_cache
            vulnerabilities = scan_path(args.path, max_workers=workers, show_progress=show_progress, use_cache=use_cache)
            print_vulnerabilities(vulnerabilities, args.json)
            logger.info(f"Path scan completed, found {len(vulnerabilities)} vulnerabilities")
        except Exception as e:
            logger.error(f"An error occurred during path scanning: {str(e)}")
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
            logger.info(f"Starting URL check: {args.url}")
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
            logger.info(f"URL check completed for {args.url}")
        except Exception as e:
            logger.error(f"An error occurred during URL scanning: {str(e)}")
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

    logger.info("React2Shell Vulnerability Checker finished")

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