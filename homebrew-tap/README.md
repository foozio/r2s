# Homebrew Tap for React2Shell Vulnerability Checker

This directory contains the Homebrew formula for installing the React2Shell Vulnerability Checker on macOS.

## Installation

### Option 1: Direct Formula Installation (Recommended)

```bash
# Add the tap (if hosted on GitHub)
brew tap your-org/react2shell-checker

# Install the tool
brew install react2shell-checker
```

### Option 2: Local Installation for Development

```bash
# Clone the repository
git clone https://github.com/foozio/r2s.git
cd react2shell-checker

# Install using local formula
brew install --formula ./homebrew-tap/react2shell-checker.rb
```

## Usage

After installation, the tool is available as `react2shell-checker`:

```bash
# Check a project
react2shell-checker --path /path/to/react/project

# Check with custom config
react2shell-checker --path /project --config /path/to/config.yaml

# Get help
react2shell-checker --help
```

## Configuration

The formula installs a default configuration file at:

```
/usr/local/etc/react2shell.yaml (Intel Macs)
/opt/homebrew/etc/react2shell.yaml (Apple Silicon Macs)
```

You can override this with the `--config` option.

## Updating

```bash
# Update the tap
brew update

# Upgrade the tool
brew upgrade react2shell-checker
```

## Development

### Testing the Formula

```bash
# Test the formula locally
brew test react2shell-checker

# Audit the formula
brew audit --formula ./homebrew-tap/react2shell-checker.rb
```

### Publishing Updates

1. Update the version and SHA256 in the formula
2. Test the formula locally
3. Commit and push changes
4. Users can update with `brew upgrade react2shell-checker`

## Dependencies

The formula includes these Python dependencies:

- `requests` - HTTP client for URL checking
- `packaging` - Version parsing utilities
- `pyyaml` - YAML configuration support

## Compatibility

- macOS Monterey (12.0+) and later
- Intel and Apple Silicon Macs
- Python 3.9+

## Troubleshooting

### Installation Issues

**Permission Denied:**

```bash
sudo chown -R $(whoami) /usr/local/Homebrew
```

**Python Version Conflicts:**

```bash
brew install python@3.9
brew link python@3.9
```

### Runtime Issues

**Config File Not Found:**

```bash
# Check if config exists
ls -la /usr/local/etc/react2shell.yaml

# Create custom config
react2shell-checker --config ./my-config.yaml
```

**Memory Issues:**

```bash
# Limit workers for large projects
react2shell-checker --path /large/project --workers 2
```

## Contributing

To contribute to the Homebrew formula:

1. Fork the repository
2. Make changes to `homebrew-tap/react2shell-checker.rb`
3. Test locally: `brew install --formula ./homebrew-tap/react2shell-checker.rb`
4. Submit a pull request

## License

This Homebrew formula is part of the React2Shell Vulnerability Checker project, licensed under MIT.
