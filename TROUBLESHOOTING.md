# Troubleshooting Guide for React2Shell Vulnerability Checker

## Common Issues and Solutions

### Installation Issues

#### "Module 'packaging' not found"
**Symptoms:**
```
ImportError: No module named 'packaging'
```

**Solutions:**
1. Install the missing dependency:
   ```bash
   pip install packaging
   ```

2. For Python < 3.8, install from requirements:
   ```bash
   pip install -r requirements.txt
   ```

3. Check Python version compatibility (requires Python 3.6+)

#### "Module 'requests' not found"
**Symptoms:**
```
ImportError: No module named 'requests'
```

**Solutions:**
1. Install requests library:
   ```bash
   pip install requests>=2.25.1
   ```

2. Verify installation:
   ```bash
   python -c "import requests; print('Requests installed successfully')"
   ```

#### Permission denied during installation
**Symptoms:**
```
PermissionError: [Errno 13] Permission denied
```

**Solutions:**
1. Use user installation:
   ```bash
   pip install --user -r requirements.txt
   ```

2. Use virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   pip install -r requirements.txt
   ```

3. Use sudo (not recommended):
   ```bash
   sudo pip install -r requirements.txt
   ```

### Runtime Issues

#### "Path validation failed: Path does not exist"
**Symptoms:**
```
[ERROR] Path validation failed: Path does not exist
```

**Solutions:**
1. Verify the path exists:
   ```bash
   ls -la /path/to/project
   ```

2. Use absolute paths:
   ```bash
   python react2shell_checker_unified.py --path /full/path/to/project
   ```

3. Check permissions:
   ```bash
   ls -ld /path/to/project
   ```

#### "URL validation failed: Localhost access not allowed"
**Symptoms:**
```
[ERROR] URL validation failed: Localhost access not allowed
```

**Cause:** Attempting to scan localhost or private IP addresses.

**Solutions:**
1. Use public URLs only
2. For local development testing, use hostnames that resolve to public IPs
3. The tool blocks localhost access for security reasons

#### "Could not reach URL: Connection timed out"
**Symptoms:**
```
[ERROR] Could not reach URL https://example.com: Connection timed out
```

**Solutions:**
1. Check network connectivity:
   ```bash
   ping example.com
   ```

2. Verify URL is accessible:
   ```bash
   curl -I https://example.com
   ```

3. Check firewall/proxy settings
4. The tool uses a 10-second timeout for security

#### "Invalid JSON in package.json"
**Symptoms:**
```
[ERROR] Invalid JSON in /path/to/package.json
```

**Solutions:**
1. Validate JSON syntax:
   ```bash
   python -m json.tool /path/to/package.json
   ```

2. Check for syntax errors (missing commas, quotes, etc.)
3. Ensure file encoding is UTF-8

### Scanning Issues

#### No vulnerabilities detected in known vulnerable project
**Symptoms:** Tool reports "No vulnerabilities detected" but you know the project is vulnerable.

**Possible Causes:**
1. **Version parsing issues:** Check if version format is supported
2. **File location:** Ensure package.json is in the scanned directory
3. **Dependencies location:** Check if vulnerable packages are in dependencies/devDependencies

**Debugging Steps:**
1. Run with verbose output (if available)
2. Manually check package.json:
   ```bash
   grep "react-server-dom" package.json
   ```
3. Verify version numbers match known vulnerable ranges

#### False positives
**Symptoms:** Tool reports vulnerabilities that don't exist.

**Possible Causes:**
1. **Version parsing errors:** Complex version ranges may be misinterpreted
2. **Lock file parsing:** Text-based parsing of yarn.lock may have false matches

**Solutions:**
1. Verify actual installed versions:
   ```bash
   npm list react-server-dom-webpack
   ```
2. Check if versions are actually vulnerable according to CVE-2025-55182

#### Performance issues with large projects
**Symptoms:** Scanning takes very long or uses excessive memory.

**Solutions:**
1. **Limit scan scope:** Scan specific directories instead of entire monorepos
2. **Exclude node_modules:** If not needed, avoid scanning large node_modules
3. **Use faster storage:** SSD storage improves file scanning performance

### Platform-Specific Issues

#### Windows path issues
**Symptoms:**
```
[ERROR] Path validation failed: Directory traversal attempt detected
```

**Solutions:**
1. Use forward slashes or properly escaped backslashes:
   ```cmd
   python react2shell_checker_unified.py --path "C:/path/to/project"
   ```

2. Avoid paths with spaces (use quotes):
   ```cmd
   python react2shell_checker_unified.py --path "C:\Program Files\project"
   ```

#### Linux permission issues
**Symptoms:**
```
[ERROR] Path validation failed: Path does not exist
```

**Solutions:**
1. Check file permissions:
   ```bash
   ls -la /path/to/project
   ```

2. Ensure execute permissions on directories:
   ```bash
   chmod +x /path/to/project
   ```

3. Run with appropriate user:
   ```bash
   sudo -u username python react2shell_checker_unified.py --path /path/to/project
   ```

#### macOS compatibility issues
**Symptoms:** Various import or path issues.

**Solutions:**
1. Ensure Python is installed via Homebrew:
   ```bash
   brew install python
   ```

2. Update pip and setuptools:
   ```bash
   pip install --upgrade pip setuptools
   ```

### Testing Issues

#### Tests failing due to missing dependencies
**Symptoms:**
```
ImportError: No module named 'pytest'
```

**Solutions:**
1. Install test dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```

2. Install pytest specifically:
   ```bash
   pip install pytest pytest-mock
   ```

#### Coverage reporting fails
**Symptoms:**
```
pytest: error: unrecognized arguments: --cov
```

**Solutions:**
1. Install coverage plugin:
   ```bash
   pip install pytest-cov
   ```

2. Run without coverage:
   ```bash
   pytest tests/
   ```

### CI/CD Issues

#### GitHub Actions failing
**Symptoms:** CI pipeline fails with various errors.

**Common Issues:**
1. **Python version mismatch:** Ensure CI uses supported Python version
2. **Dependency conflicts:** Check requirements.txt compatibility
3. **Path issues:** CI runners may have different file systems

**Solutions:**
1. Check CI logs for specific error messages
2. Test locally with same Python version as CI
3. Update CI configuration if needed

#### PyPI publishing fails
**Symptoms:**
```
HTTPError: 403 Forbidden
```

**Solutions:**
1. Verify PyPI API token is correct
2. Check token has upload permissions
3. Ensure package version is unique
4. Check package metadata (name, version, etc.)

### Security-Related Issues

#### Tool blocked by security software
**Symptoms:** Antivirus or firewall blocks the tool.

**Solutions:**
1. Add exception for the Python executable
2. Whitelist the tool's directory
3. Run in isolated environment (virtual machine)

#### False security warnings
**Symptoms:** Security tools flag the tool as suspicious.

**Explanation:** The tool performs network requests and file system scanning, which may trigger security alerts.

**Solutions:**
1. This is expected behavior for security scanning tools
2. Add exceptions in security software
3. Run in development environment

### Getting Help

If you encounter issues not covered here:

1. **Check the README.md** for usage examples
2. **Review API.md** for function documentation
3. **Run tests** to verify installation:
   ```bash
   pytest tests/ -v
   ```
4. **Check GitHub Issues** for similar problems
5. **Create a new issue** with:
   - Full error message
   - Python version (`python --version`)
   - Operating system
   - Steps to reproduce

### Debug Mode

For additional debugging information:

1. Run Python with verbose output:
   ```bash
   python -v react2shell_checker_unified.py --path /project
   ```

2. Check Python path:
   ```bash
   python -c "import sys; print(sys.path)"
   ```

3. Verify imports manually:
   ```bash
   python -c "from react2shell_checker_unified import validate_path; print('Import successful')"
   ```

### Performance Tuning

For better performance:

1. **Use SSD storage** for faster file scanning
2. **Limit scan depth** for large projects
3. **Exclude unnecessary directories** (build artifacts, etc.)
4. **Run during off-peak hours** for CI/CD pipelines

### Version Compatibility

Ensure you're using compatible versions:

- **Python:** 3.6+ (3.8+ recommended)
- **requests:** 2.25.1+
- **packaging:** Latest version
- **pytest:** 6.2.0+ (for testing)

Check versions:
```bash
python --version
pip list | grep -E "(requests|packaging|pytest)"
```