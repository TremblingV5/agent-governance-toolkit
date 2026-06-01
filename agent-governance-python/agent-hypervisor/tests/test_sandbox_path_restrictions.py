"""
Smoke tests for sandbox PATH restrictions.

These tests verify that denied binaries are not resolvable from PATH,
ensuring command denylist enforcement cannot be bypassed via alternate
binary locations.

Related Issue: #2713
"""

import subprocess
import pytest


# List of binaries that should NOT be resolvable from PATH
DENIED_BINARIES = [
    "gcc",
    "g++",
    "cc",
    "make",
    "apt-get",
    "apt",
    "dpkg",
    "sudo",
    "su",
    "wget",
    # Additional potentially dangerous binaries
    "nc",
    "netcat",
    "telnet",
    "ftp",
    "tftp",
]


# List of binaries that SHOULD be resolvable from PATH
ALLOWED_BINARIES = [
    "bash",
    "cat",
    "ls",
    "echo",
    "pwd",
    "test",
    "true",
    "false",
    "sleep",
    "env",
    "python",
    "python3",
    "pip",
    "pip3",
]


def is_binary_resolvable(binary_name: str) -> bool:
    """
    Check if a binary is resolvable from PATH using `which` command.
    
    Returns True if the binary is found, False otherwise.
    """
    try:
        result = subprocess.run(
            ["which", binary_name],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0 and result.stdout.strip() != ""
    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        # `which` command not available - skip this test
        pytest.skip("`which` command not available")
        return False


class TestDeniedBinariesNotResolvable:
    """Test that denied binaries cannot be found via PATH."""
    
    @pytest.mark.parametrize("binary", DENIED_BINARIES)
    def test_denied_binary_not_found(self, binary: str):
        """Verify that denied binaries are not resolvable from PATH."""
        assert not is_binary_resolvable(binary), (
            f"Denied binary '{binary}' is resolvable from PATH: "
            f"this violates sandbox security policy"
        )


class TestAllowedBinariesResolvable:
    """Test that allowed binaries can be found via PATH."""
    
    @pytest.mark.parametrize("binary", ALLOWED_BINARIES)
    def test_allowed_binary_found(self, binary: str):
        """Verify that allowed binaries are resolvable from PATH."""
        assert is_binary_resolvable(binary), (
            f"Allowed binary '{binary}' is not resolvable from PATH: "
            f"sandbox may be misconfigured"
        )


class TestPathConfiguration:
    """Test PATH environment variable configuration."""
    
    def test_path_is_minimal(self):
        """Verify PATH contains only minimal, expected directories."""
        import os
        
        path = os.environ.get("PATH", "")
        path_dirs = [d.strip() for d in path.split(":") if d.strip()]
        
        # Expected minimal PATH directories
        expected_dirs = {
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
        }
        
        # All PATH directories should be in expected set
        for dir_path in path_dirs:
            assert dir_path in expected_dirs, (
                f"Unexpected directory in PATH: '{dir_path}'. "
                f"PATH should only contain minimal known-good directories."
            )
    
    def test_path_does_not_contain_usr_sbin(self):
        """Verify /usr/sbin is NOT in PATH (contains dangerous binaries)."""
        import os
        
        path = os.environ.get("PATH", "")
        path_dirs = [d.strip() for d in path.split(":") if d.strip()]
        
        assert "/usr/sbin" not in path_dirs, (
            "/usr/sbin should not be in PATH - contains potentially "
            "dangerous system administration binaries"
        )
    
    def test_path_does_not_contain_usr_local_games(self):
        """Verify /usr/local/games is NOT in PATH."""
        import os
        
        path = os.environ.get("PATH", "")
        path_dirs = [d.strip() for d in path.split(":") if d.strip()]
        
        assert "/usr/local/games" not in path_dirs, (
            "/usr/local/games should not be in PATH - contains "
            "non-essential binaries"
        )


class TestSandboxHealthcheck:
    """Test sandbox healthcheck functionality."""
    
    def test_healthcheck_denied_binaries_check(self):
        """Verify healthcheck correctly checks for denied binaries."""
        # Simulate healthcheck logic
        denied_found = []
        for binary in ["gcc", "make", "apt-get"]:
            if is_binary_resolvable(binary):
                denied_found.append(binary)
        
        assert len(denied_found) == 0, (
            f"Healthcheck would fail: found denied binaries: {denied_found}"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])