# Entity Relationship Diagram (ERD) for React2Shell Vulnerability Checker

## System Components Overview

```
+-------------------+     +-------------------+     +-------------------+
|   CLI Interface   | --> |   Scan Engine     | --> |   Output Handler  |
|   (main.py)       |     |   (scanner.py)    |     |   (output.py)     |
+-------------------+     +-------------------+     +-------------------+
         |                         |                         |
         v                         v                         v
+-------------------+     +-------------------+     +-------------------+
|   Argument Parser |     |   File Checkers   |     |   Formatters      |
|   (argparse)      |     |   (check_*.py)    |     |   (print_*.py)    |
+-------------------+     +-------------------+     +-------------------+
```

## Data Flow Diagram

```
User Input
    |
    +--> Path Mode
    |       |
    |       +--> scan_path()
    |       |       |
    |       |       +--> check_package_json() --> package.json
    |       |       +--> check_lock_file() --> lock files
    |       |       +--> check_node_modules() --> node_modules/
    |       |       +--> recursive scan --> subdirs
    |       |
    |       +--> collect vulnerabilities --> List[(pkg, version)]
    |       |
    |       +--> print_vulnerabilities() --> Console Output
    |
    +--> URL Mode
            |
            +--> passive_check_url()
            |       |
            |       +--> HTTP GET --> Response
            |       +--> check indicators --> Boolean
            |
            +--> print results --> Console Output
```

## Component Relationships

### Core Components
- **CLI Interface**: Entry point, argument parsing, mode selection
- **Scan Engine**: Orchestrates scanning operations
- **Detection Modules**: Specialized checkers for different file types
- **Output Handler**: Formats and displays results

### Data Entities

#### Vulnerability Entity
```
Vulnerability {
    package_name: string
    version: string
    source: string (package.json|lock_file|node_modules)
    confidence: enum (high|medium|low)
}
```

#### Scan Result Entity
```
ScanResult {
    target: string (path|url)
    timestamp: datetime
    vulnerabilities: List[Vulnerability]
    scan_duration: float
    status: enum (safe|vulnerable|error)
}
```

#### Configuration Entity
```
Config {
    vulnerable_packages: List[string]
    patched_versions: Dict[string, string]
    scan_depth: int
    timeout: int
    user_agent: string
}
```

## File System Relationships

```
Project Root/
├── package.json (primary config)
├── package-lock.json (dependency lock)
├── yarn.lock (alternative lock)
├── pnpm-lock.yaml (alternative lock)
└── node_modules/ (installed packages)
    ├── react/
    ├── react-server-dom-webpack/
    ├── react-server-dom-parcel/
    └── react-server-dom-turbopack/
```

## Platform-Specific Components

### Linux Implementation
```
react2shell_checker_linux.py
├── main() --> argparse
├── scan_path() --> pathlib
├── passive_check_url() --> requests
└── check_*() --> json/os operations
```

### Windows Implementation
```
react2shell_checker_windows.py
├── main() --> argparse
├── scan_path() --> pathlib
├── passive_check_url() --> requests
└── check_*() --> json/os operations
```

### Cross-Platform Implementation
```
react2shell_checker.py
├── main() --> argparse
├── scan_path() --> pathlib
├── passive_check_url() --> requests
└── check_*() --> json/os operations
```

## Dependency Relationships

```
requirements.txt
├── requests (>=2.25.1)
│   └── HTTP client for URL checking
└── packaging (built-in Python 3.8+)
    └── Version parsing utilities
```

## Installation Script Relationships

```
install_cross_platform.py
├── platform detection
├── pip dependency installation
└── executable permissions

install_linux.sh
├── apt package management
├── pip installation
└── chmod permissions

install_windows.bat
├── python availability check
├── pip installation
└── path configuration
```

## Error Handling Flow

```
Exception Occurs
    |
    +--> Try/Catch Block
    |       |
    |       +--> Log Error Message
    |       +--> Return Default Value
    |       +--> Continue Execution
    |
    +--> System Exit (critical errors)
```

## Security Boundaries

```
User Input --> Validation --> Sanitization --> Processing --> Output
    |             |             |             |             |
    |--paths-----|--safe-------|--pathlib----|--read-only--|--console--
    |--urls------|--URL--------|--requests---|--passive----|--info---
    |             |             |             |             |
    +-------------+-------------+-------------+-------------+
```