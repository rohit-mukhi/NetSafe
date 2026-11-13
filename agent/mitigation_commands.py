"""
Cross-platform mitigation commands.
OS-specific implementations for firewall, process, and network management.
"""
import platform
import subprocess
from typing import Tuple, Optional, List
from dataclasses import dataclass


class OSType:
    """OS type constants."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


def get_os_type() -> str:
    """Detect current operating system."""
    system = platform.system().lower()
    if system == "windows":
        return OSType.WINDOWS
    elif system == "linux":
        return OSType.LINUX
    elif system == "darwin":
        return OSType.MACOS
    else:
        return "unknown"


def is_admin() -> bool:
    """Check if running with admin/root privileges."""
    try:
        import os
        if hasattr(os, 'geteuid'):
            return os.geteuid() == 0
        else:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def execute_command(command: str, shell: bool = False) -> Tuple[bool, str, Optional[str]]:
    """
    Execute a system command safely.
    
    Returns:
        (success, output, error_message)
    """
    try:
        result = subprocess.run(
            command,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return True, result.stdout.strip(), None
        else:
            return False, "", result.stderr.strip() or f"Command failed with code {result.returncode}"
    except subprocess.TimeoutExpired:
        return False, "", "Command execution timed out"
    except Exception as e:
        return False, "", str(e)


# ============================================================================
# FIREWALL COMMANDS
# ============================================================================

class FirewallCommands:
    """Cross-platform firewall operations."""

    @staticmethod
    def block_ip(ip: str) -> Tuple[str, Optional[str]]:
        """
        Block an IP address via firewall.
        Returns: (command, rollback_command)
        """
        os_type = get_os_type()

        if os_type == OSType.WINDOWS:
            # Windows: netsh firewall add rule
            cmd = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
            rollback = f'netsh advfirewall firewall delete rule name="Block {ip}"'
            return cmd, rollback

        elif os_type == OSType.LINUX:
            # Linux: ufw or iptables
            cmd = f"sudo ufw deny from {ip}"
            rollback = f"sudo ufw delete deny from {ip}"
            # Fallback to iptables if ufw not available
            if not _tool_exists("ufw"):
                cmd = f"sudo iptables -I INPUT -s {ip} -j DROP"
                rollback = f"sudo iptables -D INPUT -s {ip} -j DROP"
            return cmd, rollback

        elif os_type == OSType.MACOS:
            # macOS: pfctl
            cmd = f"sudo pfctl -t blocked_ips -T add {ip}"
            rollback = f"sudo pfctl -t blocked_ips -T remove {ip}"
            return cmd, rollback

        raise NotImplementedError(f"Firewall blocking not supported on {os_type}")

    @staticmethod
    def block_port(port: int, protocol: str = "tcp") -> Tuple[str, Optional[str]]:
        """
        Block incoming traffic on a specific port.
        Returns: (command, rollback_command)
        """
        os_type = get_os_type()

        if os_type == OSType.WINDOWS:
            cmd = f'netsh advfirewall firewall add rule name="Block Port {port}" dir=in action=block protocol={protocol} localport={port}'
            rollback = f'netsh advfirewall firewall delete rule name="Block Port {port}"'
            return cmd, rollback

        elif os_type == OSType.LINUX:
            cmd = f"sudo ufw deny {port}/{protocol}"
            rollback = f"sudo ufw delete deny {port}/{protocol}"
            if not _tool_exists("ufw"):
                cmd = f"sudo iptables -I INPUT -p {protocol} --dport {port} -j DROP"
                rollback = f"sudo iptables -D INPUT -p {protocol} --dport {port} -j DROP"
            return cmd, rollback

        elif os_type == OSType.MACOS:
            cmd = f"sudo pfctl -a 'netsafe' -f - <<< 'block in proto {protocol} from any to any port {port}'"
            rollback = f"sudo pfctl -a 'netsafe' -F rules"
            return cmd, rollback

        raise NotImplementedError(f"Port blocking not supported on {os_type}")

    @staticmethod
    def rate_limit(ip: str, packets_per_sec: int) -> Tuple[str, Optional[str]]:
        """
        Rate limit traffic from an IP.
        Returns: (command, rollback_command)
        """
        os_type = get_os_type()

        if os_type == OSType.WINDOWS:
            # Windows: netsh bandwidth reservation
            cmd = f"netsh int tcp set global autotuninglevel=disabled"
            rollback = f"netsh int tcp set global autotuninglevel=normal"
            return cmd, rollback

        elif os_type == OSType.LINUX:
            # Linux: tc (traffic control)
            cmd = f"sudo tc qdisc add dev eth0 root handle 1: htb default 30; sudo tc class add dev eth0 parent 1: classid 1:1 htb rate 100mbit; sudo tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip src {ip} flowid 1:1"
            rollback = f"sudo tc qdisc del dev eth0 root"
            return cmd, rollback

        elif os_type == OSType.MACOS:
            # macOS: limited rate limiting capability
            cmd = f"sudo dnctl pipe 1 config bw 1Mbit/s"
            rollback = f"sudo dnctl pipe delete 1"
            return cmd, rollback

        raise NotImplementedError(f"Rate limiting not supported on {os_type}")


# ============================================================================
# PROCESS COMMANDS
# ============================================================================

class ProcessCommands:
    """Cross-platform process management."""

    @staticmethod
    def kill_process(pid: int, force: bool = False) -> Tuple[str, Optional[str]]:
        """
        Terminate a process by PID.
        Returns: (command, rollback_command=None since not reversible)
        """
        os_type = get_os_type()

        if os_type == OSType.WINDOWS:
            signal = "/F" if force else ""
            cmd = f"taskkill /PID {pid} {signal}"
            return cmd, None

        elif os_type in [OSType.LINUX, OSType.MACOS]:
            signal = "SIGKILL" if force else "SIGTERM"
            cmd = f"kill -{signal} {pid}"
            return cmd, None

        raise NotImplementedError(f"Process killing not supported on {os_type}")

    @staticmethod
    def kill_process_by_port(port: int) -> Tuple[str, Optional[str]]:
        """
        Terminate process listening on a specific port.
        Returns: (command, rollback_command=None)
        """
        os_type = get_os_type()

        if os_type == OSType.WINDOWS:
            cmd = f"netstat -ano | findstr :{port} && for /f \"tokens=5\" %a in ('netstat -ano ^| findstr :{port}') do taskkill /PID %a /F"
            return cmd, None

        elif os_type == OSType.LINUX:
            cmd = f"sudo fuser -k {port}/tcp"
            return cmd, None

        elif os_type == OSType.MACOS:
            cmd = f"lsof -ti:{port} | xargs kill -9"
            return cmd, None

        raise NotImplementedError(f"Process killing by port not supported on {os_type}")

    @staticmethod
    def list_processes_by_port(port: int) -> Tuple[str, Optional[str]]:
        """
        List processes listening on a specific port.
        Returns: (command, rollback_command=None)
        """
        os_type = get_os_type()

        if os_type == OSType.WINDOWS:
            cmd = f"netstat -ano | findstr :{port}"
            return cmd, None

        elif os_type == OSType.LINUX:
            cmd = f"sudo netstat -tulpn | grep :{port} || sudo ss -tulpn | grep :{port}"
            return cmd, None

        elif os_type == OSType.MACOS:
            cmd = f"lsof -i :{port}"
            return cmd, None

        raise NotImplementedError(f"Process listing by port not supported on {os_type}")


# ============================================================================
# NETWORK COMMANDS
# ============================================================================

class NetworkCommands:
    """Cross-platform network management."""

    @staticmethod
    def drop_connection(src_ip: str, dest_ip: str, port: int) -> Tuple[str, Optional[str]]:
        """
        Drop all connections from src to dest on port.
        Returns: (command, rollback_command)
        """
        os_type = get_os_type()

        if os_type == OSType.WINDOWS:
            cmd = f"netsh int ipv4 add winsock catalog reset"
            rollback = None
            return cmd, rollback

        elif os_type == OSType.LINUX:
            cmd = f"sudo iptables -A INPUT -s {src_ip} -d {dest_ip} -p tcp --dport {port} -j DROP"
            rollback = f"sudo iptables -D INPUT -s {src_ip} -d {dest_ip} -p tcp --dport {port} -j DROP"
            return cmd, rollback

        elif os_type == OSType.MACOS:
            cmd = f"sudo pfctl -a 'netsafe' -f - <<< 'block in from {src_ip} to {dest_ip} port {port}'"
            rollback = f"sudo pfctl -a 'netsafe' -F rules"
            return cmd, rollback

        raise NotImplementedError(f"Connection dropping not supported on {os_type}")

    @staticmethod
    def reset_connections(ip: str) -> Tuple[str, Optional[str]]:
        """
        Reset all TCP connections from an IP.
        Returns: (command, rollback_command=None)
        """
        os_type = get_os_type()

        if os_type == OSType.WINDOWS:
            cmd = f"netstat -an | findstr {ip} && netsh int ipv4 reset all"
            return cmd, None

        elif os_type == OSType.LINUX:
            cmd = f"sudo tcpkill -i any host {ip}"
            return cmd, None

        elif os_type == OSType.MACOS:
            cmd = f"sudo tcpkill -i en0 host {ip}"
            return cmd, None

        raise NotImplementedError(f"Connection reset not supported on {os_type}")

    @staticmethod
    def isolate_interface(interface: str) -> Tuple[str, Optional[str]]:
        """
        Disable network interface (emergency measure).
        Returns: (command, rollback_command)
        """
        os_type = get_os_type()

        if os_type == OSType.WINDOWS:
            cmd = f"netsh interface set interface {interface} admin=disabled"
            rollback = f"netsh interface set interface {interface} admin=enabled"
            return cmd, rollback

        elif os_type == OSType.LINUX:
            cmd = f"sudo ip link set {interface} down"
            rollback = f"sudo ip link set {interface} up"
            return cmd, rollback

        elif os_type == OSType.MACOS:
            cmd = f"sudo ifconfig {interface} down"
            rollback = f"sudo ifconfig {interface} up"
            return cmd, rollback

        raise NotImplementedError(f"Interface isolation not supported on {os_type}")


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _tool_exists(tool_name: str) -> bool:
    """Check if a tool is available in PATH."""
    import shutil
    return shutil.which(tool_name) is not None


# ============================================================================
# COMMAND REGISTRY
# ============================================================================

MITIGATION_COMMANDS = {
    "firewall_block_ip": FirewallCommands.block_ip,
    "firewall_block_port": FirewallCommands.block_port,
    "firewall_rate_limit": FirewallCommands.rate_limit,
    "process_kill": ProcessCommands.kill_process,
    "process_kill_by_port": ProcessCommands.kill_process_by_port,
    "network_drop_connection": NetworkCommands.drop_connection,
    "network_reset_connections": NetworkCommands.reset_connections,
    "network_isolate_interface": NetworkCommands.isolate_interface,
}
