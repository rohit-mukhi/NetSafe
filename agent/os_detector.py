"""
Cross-platform OS detection and capabilities mapping.
"""
import platform
import sys
from enum import Enum
from typing import Dict


class OSType(Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class OSDetector:
    """Detects OS and provides platform-specific information."""

    @staticmethod
    def detect() -> OSType:
        """Detect the current operating system."""
        system = platform.system().lower()
        
        if system == "windows":
            return OSType.WINDOWS
        elif system == "linux":
            return OSType.LINUX
        elif system == "darwin":
            return OSType.MACOS
        else:
            return OSType.UNKNOWN

    @staticmethod
    def get_details() -> Dict[str, str]:
        """Get detailed OS information."""
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "platform": sys.platform,
            "python_version": platform.python_version(),
        }

    @staticmethod
    def is_admin() -> bool:
        """Check if running with admin/root privileges."""
        try:
            import os
            return os.geteuid() == 0 if hasattr(os, 'geteuid') else (
                os.name == 'nt' and __import__('ctypes').windll.shell32.IsUserAnAdmin()
            )
        except Exception:
            return False

    @staticmethod
    def requires_elevation() -> bool:
        """Check if elevation is needed for system modifications."""
        os_type = OSDetector.detect()
        return os_type in [OSType.LINUX, OSType.MACOS] and not OSDetector.is_admin()

    @staticmethod
    def get_available_tools() -> Dict[str, bool]:
        """Check which security tools are available on this system."""
        tools = {
            "firewall": OSDetector._check_tool_firewall(),
            "process_management": OSDetector._check_tool_process_management(),
            "network_inspection": OSDetector._check_tool_network(),
            "packet_capture": OSDetector._check_tool_packet_capture(),
        }
        return tools

    @staticmethod
    def _check_tool_firewall() -> bool:
        """Check if firewall/netfilter tools are available."""
        import shutil
        os_type = OSDetector.detect()
        
        if os_type == OSType.WINDOWS:
            return shutil.which("netsh") is not None
        elif os_type == OSType.LINUX:
            return shutil.which("ufw") is not None or shutil.which("iptables") is not None
        elif os_type == OSType.MACOS:
            return True  # pfctl is built-in
        return False

    @staticmethod
    def _check_tool_process_management() -> bool:
        """Check if process management tools are available."""
        import shutil
        os_type = OSDetector.detect()
        
        if os_type == OSType.WINDOWS:
            return shutil.which("taskkill") is not None
        elif os_type == OSType.LINUX:
            return shutil.which("kill") is not None
        elif os_type == OSType.MACOS:
            return shutil.which("kill") is not None
        return False

    @staticmethod
    def _check_tool_network() -> bool:
        """Check if network inspection tools are available."""
        import shutil
        os_type = OSDetector.detect()
        
        if os_type == OSType.WINDOWS:
            return shutil.which("netstat") is not None or shutil.which("Get-NetTCPConnection") is not None
        elif os_type == OSType.LINUX:
            return shutil.which("netstat") is not None or shutil.which("ss") is not None
        elif os_type == OSType.MACOS:
            return shutil.which("netstat") is not None
        return False

    @staticmethod
    def _check_tool_packet_capture() -> bool:
        """Check if packet capture tools are available."""
        import shutil
        os_type = OSDetector.detect()
        
        if os_type == OSType.WINDOWS:
            return shutil.which("netsh") is not None
        elif os_type == OSType.LINUX:
            return shutil.which("tcpdump") is not None or shutil.which("tshark") is not None
        elif os_type == OSType.MACOS:
            return shutil.which("tcpdump") is not None
        return False
