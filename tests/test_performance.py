#!/usr/bin/env python3
"""
Performance tests for React2Shell Vulnerability Checker
"""

import pytest
import tempfile
import json
import time
from pathlib import Path
from react2shell_checker_unified import scan_path


class TestPerformance:
    """Performance tests to ensure scanning is efficient"""

    def test_scan_performance_small_project(self):
        """Test scanning performance on small project"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a small package.json
            package_json = {
                "name": "small-app",
                "dependencies": {"react": "18.2.0"}
            }

            pkg_path = Path(temp_dir) / "package.json"
            with open(pkg_path, 'w') as f:
                json.dump(package_json, f)

            # Time the scan
            start_time = time.time()
            vulnerabilities = scan_path(temp_dir)
            end_time = time.time()

            scan_time = end_time - start_time
            # Should complete in under 1 second for small project
            assert scan_time < 1.0
            assert len(vulnerabilities) == 0

    def test_scan_performance_with_node_modules(self):
        """Test scanning performance with node_modules"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create package.json
            package_json = {"name": "test-app", "dependencies": {}}
            with open(temp_path / "package.json", 'w') as f:
                json.dump(package_json, f)

            # Create minimal node_modules structure
            node_modules = temp_path / "node_modules"
            node_modules.mkdir()

            # Create a few package directories
            for pkg_name in ["react", "lodash", "express"]:
                pkg_dir = node_modules / pkg_name
                pkg_dir.mkdir()
                pkg_json = {"name": pkg_name, "version": "1.0.0"}
                with open(pkg_dir / "package.json", 'w') as f:
                    json.dump(pkg_json, f)

            # Time the scan
            start_time = time.time()
            vulnerabilities = scan_path(temp_dir)
            end_time = time.time()

            scan_time = end_time - start_time
            # Should complete in under 5 seconds
            assert scan_time < 5.0

    @pytest.mark.slow
    def test_scan_performance_large_nested_structure(self):
        """Test scanning performance on larger nested structure"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create root package.json
            root_pkg = {"name": "root", "dependencies": {}}
            with open(temp_path / "package.json", 'w') as f:
                json.dump(root_pkg, f)

            # Create nested structure with multiple package.json files
            for i in range(10):
                sub_dir = temp_path / f"subdir_{i}"
                sub_dir.mkdir()

                sub_pkg = {
                    "name": f"sub-app-{i}",
                    "dependencies": {"react": "18.2.0"}
                }
                with open(sub_dir / "package.json", 'w') as f:
                    json.dump(sub_pkg, f)

            # Time the scan
            start_time = time.time()
            vulnerabilities = scan_path(temp_dir)
            end_time = time.time()

            scan_time = end_time - start_time
            # Should complete in under 10 seconds for this structure
            assert scan_time < 10.0
            assert len(vulnerabilities) == 0  # All should be safe