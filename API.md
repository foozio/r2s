# React2Shell Vulnerability Checker API Documentation

## Overview

The React2Shell Vulnerability Checker provides a comprehensive API for detecting CVE-2025-55182 vulnerabilities in React applications. This document describes the public API functions and their usage.

## Core Functions

### `validate_url(url: str) -> Tuple[bool, Optional[str]]`

Validates a URL to prevent Server-Side Request Forgery (SSRF) attacks.

**Parameters:**
- `url` (str): The URL to validate

**Returns:**
- `Tuple[bool, Optional[str]]`: (is_valid, error_message)
  - `is_valid` (bool): True if URL is safe to access
  - `error_message` (Optional[str]): Error message if validation fails, None if valid

**Security Features:**
- Blocks localhost and private IP access
- Validates URL format
- Prevents access to internal networks

**Example:**
```python
from react2shell_checker_unified import validate_url

is_valid, error = validate_url("https://example.com")
if not is_valid:
    print(f"URL blocked: {error}")
```

### `validate_path(path: Union[str, Path]) -> Tuple[bool, Union[str, Path]]`

Validates file system paths to prevent directory traversal attacks.

**Parameters:**
- `path` (Union[str, Path]): The path to validate

**Returns:**
- `Tuple[bool, Union[str, Path]]`: (is_valid, result)
  - `is_valid` (bool): True if path is safe
  - `result` (Union[str, Path]): Resolved path if valid, error message if invalid

**Security Features:**
- Resolves symbolic links and relative paths
- Detects ".." traversal attempts
- Ensures path exists

**Example:**
```python
from react2shell_checker_unified import validate_path

is_valid, result = validate_path("/path/to/project")
if is_valid:
    print(f"Resolved path: {result}")
else:
    print(f"Path validation failed: {result}")
```

### `check_package_json(package_json_path: Union[str, Path]) -> List[Tuple[str, str]]`

Scans a package.json file for vulnerable React dependencies.

**Parameters:**
- `package_json_path` (Union[str, Path]): Path to package.json file

**Returns:**
- `List[Tuple[str, str]]`: List of (package_name, version) tuples for vulnerable packages

**Scanned Dependencies:**
- `react-server-dom-webpack`
- `react-server-dom-parcel`
- `react-server-dom-turbopack`
- `react` (version 19.x.x)

**Example:**
```python
from react2shell_checker_unified import check_package_json

vulnerabilities = check_package_json("package.json")
for pkg, version in vulnerabilities:
    print(f"Vulnerable: {pkg}@{version}")
```

### `check_lock_file(file_path: Union[str, Path]) -> List[Tuple[str, str]]`

Scans lock files for vulnerable package versions.

**Parameters:**
- `file_path` (Union[str, Path]): Path to lock file (package-lock.json, yarn.lock, pnpm-lock.yaml)

**Returns:**
- `List[Tuple[str, str]]`: List of (package_name, version) tuples for vulnerable packages

**Supported Formats:**
- package-lock.json (JSON)
- yarn.lock (text-based)
- pnpm-lock.yaml (text-based)

**Example:**
```python
from react2shell_checker_unified import check_lock_file

vulnerabilities = check_lock_file("package-lock.json")
print(f"Found {len(vulnerabilities)} vulnerabilities")
```

### `check_node_modules(node_modules_path: Union[str, Path]) -> List[Tuple[str, str]]`

Scans installed node_modules for vulnerable packages.

**Parameters:**
- `node_modules_path` (Union[str, Path]): Path to node_modules directory

**Returns:**
- `List[Tuple[str, str]]`: List of (package_name, version) tuples for vulnerable packages

**Example:**
```python
from react2shell_checker_unified import check_node_modules

vulnerabilities = check_node_modules("node_modules")
for pkg, version in vulnerabilities:
    print(f"Installed vulnerable package: {pkg}@{version}")
```

### `passive_check_url(url: str) -> bool`

Performs passive security check on a URL for React usage indicators.

**Parameters:**
- `url` (str): URL to check

**Returns:**
- `bool`: True if React indicators detected, False otherwise

**Detection Methods:**
- Searches for "react" in response body
- Checks Content-Type header
- Examines Server header

**Security Notes:**
- Uses GET requests only
- Includes platform-specific User-Agent
- 10-second timeout
- No redirects followed

**Example:**
```python
from react2shell_checker_unified import passive_check_url

has_react = passive_check_url("https://example.com")
if has_react:
    print("Potential React application detected")
```

### `scan_path(path: Union[str, Path]) -> List[Tuple[str, str]]`

Comprehensive scan of a project directory for React2Shell vulnerabilities.

**Parameters:**
- `path` (Union[str, Path]): Root path to scan

**Returns:**
- `List[Tuple[str, str]]`: List of all detected vulnerabilities

**Scan Scope:**
1. package.json files (root and subdirectories)
2. Lock files (package-lock.json, yarn.lock, pnpm-lock.yaml)
3. node_modules directory
4. Recursive subdirectory scanning

**Example:**
```python
from react2shell_checker_unified import scan_path

vulnerabilities = scan_path("/path/to/react/project")
if vulnerabilities:
    print(f"Found {len(vulnerabilities)} vulnerabilities")
    for pkg, version in vulnerabilities:
        print(f"  - {pkg}@{version}")
else:
    print("No vulnerabilities detected")
```

### `print_vulnerabilities(vulnerabilities: List[Tuple[str, str]]) -> None`

Formats and prints vulnerability results to console.

**Parameters:**
- `vulnerabilities` (List[Tuple[str, str]]): List of (package, version) tuples

**Output Format:**
- SAFE: No vulnerabilities found
- WARNING: Lists all detected vulnerabilities
- RECOMMENDATION: Upgrade guidance

**Example:**
```python
from react2shell_checker_unified import scan_path, print_vulnerabilities

vulnerabilities = scan_path(".")
print_vulnerabilities(vulnerabilities)
```

## Utility Functions

### `is_react_v19(version_str: str) -> bool`

Checks if a React version string represents version 19.x.x.

**Parameters:**
- `version_str` (str): Version string to check

**Returns:**
- `bool`: True if version is 19.x.x

**Supported Formats:**
- "19.0.0", "^19.0.0", "~19.1.2", "19"

### `find_project_root(start_path: Union[str, Path]) -> Optional[Path]`

Finds the project root by locating package.json.

**Parameters:**
- `start_path` (Union[str, Path]): Starting path for search

**Returns:**
- `Optional[Path]`: Path to directory containing package.json, or None

## Error Handling

All functions include comprehensive error handling:

- File I/O errors
- JSON parsing errors
- Network timeouts
- Invalid input validation

Functions return appropriate default values (empty lists, False) on errors rather than raising exceptions.

## Security Considerations

- **Input Validation**: All user inputs are validated
- **Path Security**: Directory traversal protection
- **Network Security**: SSRF prevention for URL checks
- **Safe Defaults**: Conservative approach to vulnerability detection

## Performance Notes

- File scanning is optimized for typical project sizes
- Network checks include timeouts
- Recursive scanning may be slow on very large directory trees
- Memory usage scales with project size

## Version Compatibility

- Python 3.6+
- Compatible with all major package managers (npm, yarn, pnpm)
- Supports all React project structures