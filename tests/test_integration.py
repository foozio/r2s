#!/usr/bin/env python3
"""
Integration tests for React2Shell Vulnerability Checker
Tests end-to-end functionality with real file operations
"""

import pytest
import json
import tempfile
import os
from pathlib import Path
from react2shell_checker_unified import scan_path, check_package_json


@pytest.fixture
def temp_project_dir():
    """Fixture for temporary project directory"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def safe_package_json():
    """Fixture for safe package.json content"""
    return {
        "name": "safe-app",
        "version": "1.0.0",
        "dependencies": {
            "react": "18.2.0",
            "lodash": "4.17.21"
        }
    }


@pytest.fixture
def vulnerable_package_json():
    """Fixture for vulnerable package.json content"""
    return {
        "name": "vulnerable-app",
        "version": "1.0.0",
        "dependencies": {
            "react-server-dom-webpack": "19.0.0",
            "react": "19.1.0"
        },
        "devDependencies": {
            "react-server-dom-parcel": "19.1.0"
        }
    }


@pytest.fixture
def monorepo_structure(temp_project_dir, safe_package_json, vulnerable_package_json):
    """Fixture for monorepo with multiple packages"""
    # Root package.json (safe)
    root_pkg = temp_project_dir / "package.json"
    with open(root_pkg, 'w') as f:
        json.dump(safe_package_json, f)

    # Sub-package with vulnerabilities
    sub_dir = temp_project_dir / "packages" / "vulnerable-app"
    sub_dir.mkdir(parents=True)
    sub_pkg = sub_dir / "package.json"
    with open(sub_pkg, 'w') as f:
        json.dump(vulnerable_package_json, f)

    # Another safe sub-package
    safe_sub_dir = temp_project_dir / "packages" / "safe-app"
    safe_sub_dir.mkdir(parents=True)
    safe_sub_pkg = safe_sub_dir / "package.json"
    with open(safe_sub_pkg, 'w') as f:
        json.dump(safe_package_json, f)

    return temp_project_dir


@pytest.fixture
def node_modules_structure(temp_project_dir):
    """Fixture for project with node_modules"""
    # Create package.json
    pkg_json = temp_project_dir / "package.json"
    with open(pkg_json, 'w') as f:
        json.dump({"name": "test-app", "dependencies": {}}, f)

    # Create node_modules structure
    node_modules = temp_project_dir / "node_modules"
    node_modules.mkdir()

    # Create vulnerable package
    vuln_pkg_dir = node_modules / "react-server-dom-webpack"
    vuln_pkg_dir.mkdir()
    vuln_pkg_json = vuln_pkg_dir / "package.json"
    with open(vuln_pkg_json, 'w') as f:
        json.dump({"name": "react-server-dom-webpack", "version": "19.0.0"}, f)

    # Create safe React package
    react_dir = node_modules / "react"
    react_dir.mkdir()
    react_pkg_json = react_dir / "package.json"
    with open(react_pkg_json, 'w') as f:
        json.dump({"name": "react", "version": "18.2.0"}, f)

    return temp_project_dir


@pytest.fixture
def lockfile_structure(temp_project_dir):
    """Fixture for project with various lock files"""
    # Create package.json
    pkg_json = temp_project_dir / "package.json"
    with open(pkg_json, 'w') as f:
        json.dump({"name": "test-app", "dependencies": {"react": "19.1.0"}}, f)

    # Create package-lock.json
    pkg_lock = temp_project_dir / "package-lock.json"
    lock_data = {
        "dependencies": {
            "react": {"version": "19.1.0"},
            "react-server-dom-webpack": {"version": "19.0.0"}
        }
    }
    with open(pkg_lock, 'w') as f:
        json.dump(lock_data, f)

    # Create yarn.lock
    yarn_lock = temp_project_dir / "yarn.lock"
    yarn_content = '''
react@^19.1.0:
  version "19.1.0"
  resolved "https://registry.yarnpkg.com/react/-/react-19.1.0.tgz"

react-server-dom-webpack@^19.0.0:
  version "19.0.0"
  resolved "https://registry.yarnpkg.com/react-server-dom-webpack/-/react-server-dom-webpack-19.0.0.tgz"
'''
    with open(yarn_lock, 'w') as f:
        f.write(yarn_content)

    return temp_project_dir


class TestIntegration:
    """Integration tests for complete functionality"""

    def test_scan_path_with_vulnerable_package_json(self, temp_project_dir, vulnerable_package_json):
        """Test scanning a directory with vulnerable package.json"""
        pkg_path = temp_project_dir / "package.json"
        with open(pkg_path, 'w') as f:
            json.dump(vulnerable_package_json, f)

        # Scan the directory
        vulnerabilities = scan_path(temp_project_dir)

        # Should detect the vulnerabilities
        assert len(vulnerabilities) >= 2
        assert ("react-server-dom-webpack", "19.0.0") in vulnerabilities
        assert ("react", "19.1.0") in vulnerabilities

    def test_scan_path_clean_project(self, temp_project_dir, safe_package_json):
        """Test scanning a clean project"""
        pkg_path = temp_project_dir / "package.json"
        with open(pkg_path, 'w') as f:
            json.dump(safe_package_json, f)

        # Scan the directory
        vulnerabilities = scan_path(temp_project_dir)

        # Should be clean
        assert len(vulnerabilities) == 0

    def test_scan_path_monorepo(self, monorepo_structure):
        """Test scanning monorepo with multiple packages"""
        vulnerabilities = scan_path(monorepo_structure)

        # Should detect vulnerabilities from sub-package
        assert ("react-server-dom-webpack", "19.0.0") in vulnerabilities
        assert ("react-server-dom-parcel", "19.1.0") in vulnerabilities
        assert ("react", "19.1.0") in vulnerabilities

    def test_scan_path_with_node_modules(self, node_modules_structure):
        """Test scanning project with node_modules"""
        vulnerabilities = scan_path(node_modules_structure)

        # Should detect vulnerability in node_modules
        assert ("react-server-dom-webpack", "19.0.0") in vulnerabilities
        # React 18.2.0 should not be flagged
        assert ("react", "18.2.0") not in vulnerabilities

    def test_scan_path_with_lockfiles(self, lockfile_structure):
        """Test scanning project with various lock files"""
        vulnerabilities = scan_path(lockfile_structure)

        # Should detect vulnerabilities from lock files
        assert ("react-server-dom-webpack", "19.0.0") in vulnerabilities
        assert ("react", "19.1.0") in vulnerabilities

    def test_scan_path_invalid_path(self):
        """Test scanning invalid/non-existent path"""
        vulnerabilities = scan_path("/nonexistent/path/that/does/not/exist")
        assert vulnerabilities == []

    def test_check_package_json_with_devdependencies(self, vulnerable_package_json):
        """Test checking package.json with devDependencies"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(vulnerable_package_json, f)
            temp_file = f.name

        try:
            vulnerabilities = check_package_json(temp_file)
            assert ("react-server-dom-parcel", "19.1.0") in vulnerabilities
        finally:
            os.unlink(temp_file)