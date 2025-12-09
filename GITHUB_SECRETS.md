# GitHub Secrets Configuration Guide

## Overview
This guide outlines the necessary GitHub secrets and environment variables required for integrating the React2Shell Vulnerability Checker into CI/CD pipelines and automated workflows.

## Required Secrets

### Repository Secrets

#### `PYPI_API_TOKEN`
- **Purpose**: Authentication for publishing to PyPI
- **Type**: Personal API Token
- **How to Obtain**:
  1. Go to https://pypi.org/manage/account/
  2. Generate a new API token
  3. Copy the token value
- **Usage**: Automated package publishing in release workflows

#### `CODECOV_TOKEN`
- **Purpose**: Upload test coverage reports to Codecov
- **Type**: Repository-specific token
- **How to Obtain**:
  1. Visit https://codecov.io/gh/{username}/{repository}
  2. Copy the token from repository settings
- **Usage**: Coverage reporting in CI pipelines

#### `DOCKER_HUB_TOKEN`
- **Purpose**: Push Docker images to Docker Hub
- **Type**: Access Token
- **How to Obtain**:
  1. Go to https://hub.docker.com/settings/security
  2. Generate a new access token
- **Usage**: Container image publishing workflows

### Organization Secrets (if applicable)

#### `SLACK_WEBHOOK_URL`
- **Purpose**: Send notifications to Slack channels
- **Type**: Incoming Webhook URL
- **How to Obtain**:
  1. Create a Slack app or use existing webhook
  2. Copy the webhook URL
- **Usage**: Security scan result notifications

#### `DISCORD_WEBHOOK_URL`
- **Purpose**: Send notifications to Discord channels
- **Type**: Webhook URL
- **How to Obtain**:
  1. Create a webhook in Discord server settings
  2. Copy the webhook URL
- **Usage**: Build status and vulnerability alerts

## Environment Variables

### Build Environment

#### `PYTHON_VERSION`
- **Default**: `3.9`
- **Purpose**: Specify Python version for builds
- **Usage**: Matrix builds across Python versions

#### `NODE_VERSION`
- **Default**: `18`
- **Purpose**: Node.js version for testing React projects
- **Usage**: Integration testing with real React applications

### Testing Environment

#### `TEST_REACT_PROJECT_URL`
- **Purpose**: URL of a test React application for integration testing
- **Usage**: Automated testing against known vulnerable/safe applications

#### `COVERAGE_THRESHOLD`
- **Default**: `85`
- **Purpose**: Minimum test coverage percentage
- **Usage**: Quality gate in CI pipelines

## GitHub Actions Workflow Configuration

### Example: Security Scanning Workflow

```yaml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    
    - name: Run vulnerability scan
      run: python react2shell_checker.py --path .
    
    - name: Upload scan results
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: scan-results
        path: scan-output.log
```

### Example: Release Workflow with Secrets

```yaml
name: Release

on:
  release:
    types: [published]

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install build twine
    
    - name: Build package
      run: python -m build
    
    - name: Publish to PyPI
      env:
        TWINE_USERNAME: __token__
        TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
      run: |
        twine upload dist/*
```

## Security Best Practices

### Secret Management
1. **Never commit secrets** to version control
2. **Rotate tokens regularly** (recommended: quarterly)
3. **Use repository-specific tokens** when possible
4. **Limit secret scope** to necessary workflows only

### Access Control
1. **Use branch protection rules** to require CI checks
2. **Implement CODEOWNERS** for sensitive workflow files
3. **Regular audit** of repository secrets and permissions

### Monitoring
1. **Enable security alerts** for the repository
2. **Monitor workflow runs** for unauthorized access attempts
3. **Set up notifications** for failed security scans

## Troubleshooting

### Common Issues

#### "Secret not found" error
- Verify secret name matches exactly (case-sensitive)
- Check if secret is set at repository level (not organization)
- Ensure workflow has permission to access secrets

#### "Token expired" error
- Regenerate the token from the service provider
- Update the GitHub secret with the new token
- Check token expiration policies

#### Permission denied errors
- Verify token has necessary scopes/permissions
- Check if token is for the correct repository/organization
- Ensure the workflow actor has appropriate access

## Additional Resources
- [GitHub Secrets Documentation](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [PyPI API Tokens](https://pypi.org/help/#apitoken)
- [Docker Hub Access Tokens](https://docs.docker.com/docker-hub/access-tokens/)