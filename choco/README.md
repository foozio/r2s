# React2Shell Vulnerability Checker - Chocolatey Package

This directory contains the Chocolatey package for installing the React2Shell Vulnerability Checker on Windows.

## Installation

### Option 1: Chocolatey Package (Recommended)

```powershell
# Install the package
choco install react2shell-checker

# Upgrade to latest version
choco upgrade react2shell-checker
```

### Option 2: Local Package Installation for Development

```powershell
# Clone the repository
git clone https://github.com/your-org/react2shell-checker.git
cd react2shell-checker

# Pack the chocolatey package
choco pack choco/react2shell-checker.nuspec

# Install locally
choco install react2shell-checker --source .
```

## Usage

After installation, the tool is available via:

**Batch file (simplest):**
```cmd
react2shell-checker --path C:\path\to\react\project
```

**PowerShell script (advanced):**
```powershell
# Using parameters
react2shell-checker -Path "C:\path\to\project" -Json -Verbose

# Check URL
react2shell-checker -Url "https://your-app.com"
```

## Package Contents

The Chocolatey package includes:
- `react2shell_checker_unified.py` - Main Python script
- `react2shell.yaml` - Default configuration file
- `react2shell-checker.bat` - Windows batch file wrapper
- `react2shell-checker.ps1` - PowerShell script wrapper
- Python dependencies (requests, packaging, pyyaml)

## Configuration

The package installs a default configuration file. You can override it:

```cmd
react2shell-checker --path C:\project --config C:\path\to\custom-config.yaml
```

## Updating

```powershell
# Check for updates
choco outdated

# Update the package
choco upgrade react2shell-checker
```

## Development

### Building the Package

1. Update version in `choco/react2shell-checker.nuspec`
2. Update SHA256 checksum in `choco/tools/chocolateyinstall.ps1`
3. Test locally:
   ```powershell
   choco pack choco/react2shell-checker.nuspec
   choco install react2shell-checker --source .
   ```
4. Push to Chocolatey repository

### Testing

```powershell
# Test the installation script
powershell -ExecutionPolicy Bypass -File choco/tools/chocolateyinstall.ps1

# Test the package
choco install react2shell-checker --source .
react2shell-checker --help
```

## Dependencies

The package automatically installs:
- Python 3.9+ (if not present)
- `requests` - HTTP client library
- `packaging` - Version parsing utilities
- `pyyaml` - YAML configuration support (optional)

## Compatibility

- Windows 10/11
- Windows Server 2016+
- PowerShell 5.1+
- Chocolatey 0.10.15+

## Troubleshooting

### Installation Issues

**Chocolatey not found:**
```powershell
# Install Chocolatey first
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

**Python installation fails:**
```powershell
# Install Python manually
choco install python --version 3.9.13
refreshenv
```

### Runtime Issues

**Command not found:**
```powershell
# Refresh environment
refreshenv

# Or restart PowerShell/Command Prompt
```

**Permission denied:**
```powershell
# Run as Administrator
# Or check execution policy
Get-ExecutionPolicy
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Memory issues:**
```cmd
# Limit workers for large projects
react2shell-checker --path C:\large\project --workers 2
```

### Uninstallation

```powershell
# Uninstall the package
choco uninstall react2shell-checker

# Remove Python dependencies (optional)
pip uninstall requests packaging pyyaml
```

## Contributing

To contribute to the Chocolatey package:

1. Fork the repository
2. Make changes to files in the `choco/` directory
3. Test locally using the instructions above
4. Submit a pull request

## Publishing

### To Chocolatey Community Repository

1. Create account at https://chocolatey.org/
2. Get API key from https://chocolatey.org/account
3. Push package:
   ```powershell
   choco push react2shell-checker.2.0.0.nupkg --source https://push.chocolatey.org/ --api-key YOUR_API_KEY
   ```

### Internal Repository

For internal use, host your own Chocolatey repository and push to it.

## License

This Chocolatey package is part of the React2Shell Vulnerability Checker project, licensed under MIT.