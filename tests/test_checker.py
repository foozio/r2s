import pytest
import json
import os
from pathlib import Path
from unittest.mock import mock_open, patch

# Import the unified checker
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from react2shell_checker_unified import (
    check_package_json,
    is_react_v19,
    validate_url,
    validate_path,
    passive_check_url,
    check_lock_file,
    check_node_modules,
    find_project_root
)


class TestVersionChecking:
    """Test version parsing and validation functions"""

    def test_is_react_v19_valid_versions(self):
        """Test detection of React 19.x.x versions"""
        assert is_react_v19("19.0.0") == True
        assert is_react_v19("^19.0.0") == True
        assert is_react_v19("~19.1.2") == True
        assert is_react_v19("19.2.1") == True

    def test_is_react_v19_invalid_versions(self):
        """Test non-React 19 versions"""
        assert is_react_v19("18.2.0") == False
        assert is_react_v19("20.0.0") == False
        assert is_react_v19("1.0.0") == False

    def test_is_react_v19_edge_cases(self):
        """Test edge cases in version parsing"""
        assert is_react_v19("19") == True
        assert is_react_v19("19.") == False  # Invalid format
        assert is_react_v19("v19.0.0") == True


class TestPackageJsonChecking:
    """Test package.json vulnerability detection"""

    @patch('builtins.open', new_callable=mock_open)
    def test_check_package_json_vulnerable(self, mock_file):
        """Test detection of vulnerable packages in package.json"""
        mock_data = {
            "dependencies": {
                "react-server-dom-webpack": "19.0.0",
                "react": "19.1.0"
            }
        }
        mock_file.return_value.read.return_value = json.dumps(mock_data)

        result = check_package_json("fake_path")
        expected = [("react-server-dom-webpack", "19.0.0"), ("react", "19.1.0")]
        assert result == expected

    @patch('builtins.open', new_callable=mock_open)
    def test_check_package_json_safe(self, mock_file):
        """Test clean package.json"""
        mock_data = {
            "dependencies": {
                "react": "18.2.0",
                "lodash": "4.17.21"
            }
        }
        mock_file.return_value.read.return_value = json.dumps(mock_data)

        result = check_package_json("fake_path")
        assert result == []

    @patch('builtins.open', new_callable=mock_open)
    @patch('json.load', side_effect=json.JSONDecodeError("Invalid JSON", "", 0))
    def test_check_package_json_invalid_json(self, mock_json, mock_file):
        """Test handling of invalid JSON"""
        result = check_package_json("fake_path")
        assert result == []


class TestURLValidation:
    """Test URL validation for SSRF prevention"""

    def test_validate_url_valid(self):
        """Test valid URLs"""
        assert validate_url("https://example.com") == (True, None)
        assert validate_url("http://test.com/path") == (True, None)

    def test_validate_url_localhost_blocked(self):
        """Test localhost blocking"""
        assert validate_url("http://localhost") == (False, "Localhost access not allowed")
        assert validate_url("http://127.0.0.1") == (False, "Localhost access not allowed")

    def test_validate_url_invalid_format(self):
        """Test invalid URL formats"""
        assert validate_url("not-a-url") == (False, "Invalid URL format")
        assert validate_url("") == (False, "Invalid URL format")


class TestPathValidation:
    """Test path validation for traversal prevention"""

    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.resolve')
    def test_validate_path_valid(self, mock_resolve, mock_exists):
        """Test valid paths"""
        mock_path = Path("/valid/path")
        mock_resolve.return_value = mock_path
        mock_exists.return_value = True

        result = validate_path("/valid/path")
        assert result[0] == True

    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.resolve')
    def test_validate_path_traversal(self, mock_resolve, mock_exists):
        """Test directory traversal detection"""
        mock_path = Path("/some/../path")
        mock_resolve.return_value = mock_path
        mock_exists.return_value = True

        result = validate_path("/malicious/../../../path")
        assert result == (False, "Directory traversal attempt detected")

    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.resolve')
    def test_validate_path_not_exists(self, mock_resolve, mock_exists):
        """Test non-existent paths"""
        mock_path = Path("/nonexistent")
        mock_resolve.return_value = mock_path
        mock_exists.return_value = False

        result = validate_path("/nonexistent")
        assert result == (False, "Path does not exist")


class TestPassiveURLChecking:
    """Test passive URL checking functionality"""

    @patch('react2shell_checker_unified.requests.get')
    @patch('react2shell_checker_unified.validate_url')
    def test_passive_check_url_react_detected_in_body(self, mock_validate, mock_get):
        """Test detection of React in response body"""
        mock_validate.return_value = (True, None)

        mock_response = mock_get.return_value
        mock_response.text = "<html><body>React application content</body></html>"
        mock_response.headers = {'content-type': 'text/html'}

        result = passive_check_url("https://example.com")
        assert result == True

    @patch('react2shell_checker_unified.requests.get')
    @patch('react2shell_checker_unified.validate_url')
    def test_passive_check_url_react_detected_in_headers(self, mock_validate, mock_get):
        """Test detection of React in response headers"""
        mock_validate.return_value = (True, None)

        mock_response = mock_get.return_value
        mock_response.text = "<html>Normal app</html>"
        mock_response.headers = {'content-type': 'text/html', 'server': 'React-Server'}

        result = passive_check_url("https://example.com")
        assert result == True

    @patch('react2shell_checker_unified.requests.get')
    @patch('react2shell_checker_unified.validate_url')
    def test_passive_check_url_no_react(self, mock_validate, mock_get):
        """Test when no React indicators found"""
        mock_validate.return_value = (True, None)

        mock_response = mock_get.return_value
        mock_response.text = "<html><body>Vanilla JavaScript application</body></html>"
        mock_response.headers = {'content-type': 'text/html', 'server': 'nginx'}

        result = passive_check_url("https://example.com")
        assert result == False

    @patch('react2shell_checker_unified.requests.get')
    @patch('react2shell_checker_unified.validate_url')
    def test_passive_check_url_request_exception(self, mock_validate, mock_get):
        """Test handling of network errors"""
        mock_validate.return_value = (True, None)

        from requests.exceptions import RequestException
        mock_get.side_effect = RequestException("Connection failed")

        result = passive_check_url("https://example.com")
        assert result == False

    @patch('react2shell_checker_unified.validate_url')
    def test_passive_check_url_invalid_url(self, mock_validate):
        """Test handling of invalid URLs"""
        mock_validate.return_value = (False, "Invalid URL")

        result = passive_check_url("invalid-url")
        assert result == False


class TestLockFileChecking:
    """Test lock file vulnerability detection"""

    @patch('builtins.open', new_callable=mock_open)
    def test_check_lock_file_package_lock_json(self, mock_file):
        """Test checking package-lock.json"""
        mock_data = {
            "dependencies": {
                "react-server-dom-webpack": {
                    "version": "19.0.0"
                },
                "react": {
                    "version": "19.1.0"
                }
            }
        }
        mock_file.return_value.read.return_value = json.dumps(mock_data)

        result = check_lock_file("package-lock.json")
        expected = [("react-server-dom-webpack", "19.0.0"), ("react", "19.1.0")]
        assert result == expected

    @patch('builtins.open', new_callable=mock_open)
    def test_check_lock_file_yarn_lock(self, mock_file):
        """Test checking yarn.lock with text search"""
        mock_content = '''
react-server-dom-webpack@^19.0.0:
  version "19.0.0"
  resolved "https://registry.yarnpkg.com/react-server-dom-webpack/-/react-server-dom-webpack-19.0.0.tgz"
        '''
        mock_file.return_value.read.return_value = mock_content

        result = check_lock_file("yarn.lock")
        assert ("react-server-dom-webpack", "19.0.0") in result

    @patch('builtins.open', new_callable=mock_open)
    @patch('json.load', side_effect=json.JSONDecodeError("Invalid JSON", "", 0))
    def test_check_lock_file_invalid_json(self, mock_json, mock_file):
        """Test handling of invalid JSON in lock files"""
        result = check_lock_file("package-lock.json")
        assert result == []


class TestNodeModulesChecking:
    """Test node_modules vulnerability detection"""

    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    def test_check_node_modules_vulnerable(self, mock_file, mock_exists):
        """Test detection in node_modules"""
        # Mock package directory exists
        mock_exists.return_value = True

        # Mock package.json content
        mock_data = {"name": "react-server-dom-webpack", "version": "19.0.0"}
        mock_file.return_value.read.return_value = json.dumps(mock_data)

        with patch('os.path.join', side_effect=lambda *args: '/'.join(args)):
            result = check_node_modules("/path/to/node_modules")
            assert ("react-server-dom-webpack", "19.0.0") in result

    @patch('os.path.exists')
    def test_check_node_modules_no_packages(self, mock_exists):
        """Test when no vulnerable packages exist"""
        mock_exists.return_value = False

        result = check_node_modules("/path/to/node_modules")
        assert result == []


class TestProjectRootFinding:
    """Test project root detection functionality"""

    @patch('pathlib.Path.exists')
    def test_find_project_root_found(self, mock_exists):
        """Test finding project root with package.json"""
        mock_exists.side_effect = [False, False, True]  # package.json found at third level up

        result = find_project_root("/some/deep/path")
        assert result is not None

    @patch('pathlib.Path.exists')
    def test_find_project_root_not_found(self, mock_exists):
        """Test when no package.json found"""
        mock_exists.return_value = False

        result = find_project_root("/some/path")
        assert result is None