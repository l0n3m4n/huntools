import os
import sys
import pytest
import yaml
from unittest.mock import patch, mock_open

# Assuming huntools.py is in the parent directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import huntools

# Mock the Colors class to prevent ANSI escape codes in test output
class MockColors:
    def __getattr__(self, name):
        return ""

huntools.Colors = MockColors()

@pytest.fixture
def mock_config_dir(tmp_path):
    """Fixture to create a temporary config directory."""
    config_path = tmp_path / ".config" / "huntools"
    config_path.mkdir(parents=True)
    return config_path

@pytest.fixture
def mock_huntools_install_dir(tmp_path):
    """Fixture to create a temporary huntools install directory."""
    install_path = tmp_path / ".huntools"
    install_path.mkdir(parents=True)
    return install_path

def test_validate_config_valid_paths(mock_config_dir, mock_huntools_install_dir):
    """Test validate_config with valid paths."""
    mock_go_bin_dir = mock_huntools_install_dir / "go" / "bin"
    mock_go_bin_dir.mkdir(parents=True)
    mock_python_dir = mock_huntools_install_dir / "python"
    mock_python_dir.mkdir(parents=True)
    mock_git_dir = mock_huntools_install_dir / "git"
    mock_git_dir.mkdir(parents=True)

    mock_config_content = {
        "PATHS": {
            "install_dir": str(mock_huntools_install_dir),
            "go_bin_dir": str(mock_go_bin_dir),
            "python_dir": str(mock_python_dir),
            "git_dir": str(mock_git_dir),
            "config_file": str(mock_config_dir / "config.yml")
        }
    }
    
    with patch('builtins.open', mock_open(read_data=yaml.dump(mock_config_content))), \
         patch('os.path.exists', return_value=True), \
         patch('os.path.isdir', side_effect=lambda p: p in [
             str(mock_huntools_install_dir),
             str(mock_go_bin_dir),
             str(mock_python_dir),
             str(mock_git_dir),
             str(mock_config_dir) # For the config directory itself
         ]):
        # Should not raise SystemExit
        huntools.validate_config(mock_config_content)

def test_validate_config_invalid_path(mock_config_dir, mock_huntools_install_dir):
    """Test validate_config with an invalid path."""
    mock_config_content = {
        "PATHS": {
            "install_dir": str(mock_huntools_install_dir),
            "go_bin_dir": "/nonexistent/path/to/go/bin", # Invalid path
            "python_dir": str(mock_huntools_install_dir / "python"),
            "git_dir": str(mock_huntools_install_dir / "git"),
            "config_file": str(mock_config_dir / "config.yml")
        }
    }

    # Create only the valid directories
    mock_huntools_install_dir.mkdir(parents=True, exist_ok=True)
    (mock_huntools_install_dir / "python").mkdir(parents=True, exist_ok=True)
    (mock_huntools_install_dir / "git").mkdir(parents=True, exist_ok=True)

    with patch('builtins.open', mock_open(read_data=yaml.dump(mock_config_content))), \
         patch('os.path.exists', side_effect=lambda p: p in [
             str(mock_huntools_install_dir),
             str(mock_huntools_install_dir / "python"),
             str(mock_huntools_install_dir / "git"),
             str(mock_config_dir),
             str(mock_config_dir / "config.yml")
         ]), \
         patch('os.path.isdir', side_effect=lambda p: p in [
             str(mock_huntools_install_dir),
             str(mock_huntools_install_dir / "python"),
             str(mock_huntools_install_dir / "git"),
             str(mock_config_dir)
         ]):
        with pytest.raises(SystemExit) as excinfo:
            huntools.validate_config(mock_config_content)
        assert excinfo.type == SystemExit
        assert excinfo.value.code == 1

def test_load_config_with_invalid_path(mock_config_dir, mock_huntools_install_dir):
    """Test load_config calls validate_config and exits on invalid path."""
    # Simulate an existing config file with an invalid path
    invalid_go_bin_path = "/nonexistent/path/to/go/bin"
    mock_config_content = {
        "PATHS": {
            "install_dir": str(mock_huntools_install_dir),
            "go_bin_dir": invalid_go_bin_path,
            "python_dir": str(mock_huntools_install_dir / "python"),
            "git_dir": str(mock_huntools_install_dir / "git"),
            "config_file": str(mock_config_dir / "config.yml")
        }
    }
    
    # Write the mock config to the temporary file
    config_file = mock_config_dir / "config.yml"
    with open(config_file, "w") as f:
        yaml.dump(mock_config_content, f)

    # Create only the valid directories
    mock_huntools_install_dir.mkdir(parents=True, exist_ok=True)
    (mock_huntools_install_dir / "python").mkdir(parents=True, exist_ok=True)
    (mock_huntools_install_dir / "git").mkdir(parents=True, exist_ok=True)

    # Mock os.path.exists and os.path.isdir to control path validation
    with patch('os.path.exists', side_effect=lambda p: p in [
             str(mock_huntools_install_dir),
             str(mock_huntools_install_dir / "python"),
             str(mock_huntools_install_dir / "git"),
             str(mock_config_dir),
             str(config_file) # The mock config file itself
         ]), \
         patch('os.path.isdir', side_effect=lambda p: p in [
             str(mock_huntools_install_dir),
             str(mock_huntools_install_dir / "python"),
             str(mock_huntools_install_dir / "git"),
             str(mock_config_dir)
         ]), \
         patch('os.makedirs', return_value=None): # Patch os.makedirs
        with pytest.raises(SystemExit) as excinfo:
            huntools.load_config()
        assert excinfo.type == SystemExit
        assert excinfo.value.code == 1
