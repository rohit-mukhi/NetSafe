"""
Cross-platform packet capture module.
Uses Scapy for Linux/macOS, Npcap/WinPcap for Windows.
"""
import platform
import numpy as np
from typing import Optional, Tuple
from collections import defaultdict
from pathlib import Path

# Detect OS
OS_TYPE = platform.system().lower()


def get_packet_capturer():
    """Get appropriate packet capturer for current OS."""
    if OS_TYPE == "windows":
        return WindowsPacketCapturer()
    else:  # Linux, macOS, etc.
        return UnixPacketCapturer()


class PacketCapturer:
    """Base class for packet capture."""
    
    def capture(self, duration: int = 10, iface: Optional[str] = None):
        """Capture packets for specified duration."""
        raise NotImplementedError
    
    def check_dependencies(self) -> Tuple[bool, str]:
        """Check if required dependencies are installed."""
        raise NotImplementedError


class UnixPacketCapturer(PacketCapturer):
    """Packet capture for Linux/macOS using Scapy."""
    
    def __init__(self):
        self.name = "Scapy (Linux/macOS)"
    
    def check_dependencies(self) -> Tuple[bool, str]:
        """Check if Scapy is installed."""
        try:
            import scapy
            return True, f"Scapy {scapy.__version__} installed"
        except ImportError:
            return False, "Scapy not installed. Install with: pip install scapy"
    
    def capture(self, duration: int = 10, iface: Optional[str] = None):
        """Capture packets using Scapy."""
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP
        except ImportError as e:
            raise RuntimeError(f"Scapy not available: {e}")
        
        print(f"[Packet Capture] Starting Scapy capture for {duration}s on interface {iface or 'default'}")
        
        packets = sniff(iface=iface, timeout=duration, store=True)
        print(f"[Packet Capture] Captured {len(packets)} packets")
        
        return self._process_packets(packets)
    
    def _process_packets(self, packets):
        """Process captured packets into flows."""
        from scapy.all import IP, TCP, UDP, ICMP
        
        flows = defaultdict(lambda: {
            "start": None, "end": None, "proto": "other",
            "orig_bytes": 0, "resp_bytes": 0, "missed_bytes": 0,
            "orig_pkts": 0, "orig_ip_bytes": 0,
            "resp_pkts": 0, "resp_ip_bytes": 0,
            "syn_errors": 0, "rst_errors": 0, "total_pkts": 0,
            "dst": None, "dport": 0,
        })
        
        dst_counts = defaultdict(int)
        dst_syn_errs = defaultdict(int)
        
        for pkt in packets:
            if not pkt.haslayer(IP):
                continue
            
            ip = pkt[IP]
            proto = "tcp" if pkt.haslayer(TCP) else "udp" if pkt.haslayer(UDP) else "icmp" if pkt.haslayer(ICMP) else "other"
            sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
            key = (ip.src, ip.dst, sport, dport, proto)
            f = flows[key]
            t = float(pkt.time)
            
            if f["start"] is None:
                f["start"] = t
            f["end"] = t
            f["proto"] = proto
            f["dst"] = ip.dst
            f["dport"] = dport
            
            pkt_len = len(pkt)
            f["orig_pkts"] += 1
            f["orig_bytes"] += pkt_len
            f["orig_ip_bytes"] += pkt_len
            f["total_pkts"] += 1
            
            # Detect SYN-only packets
            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                if flags == 0x02:  # SYN only
                    f["syn_errors"] += 1
                    dst_syn_errs[ip.dst] += 1
            
            dst_counts[ip.dst] += 1
        
        return flows, dst_counts, dst_syn_errs


class WindowsPacketCapturer(PacketCapturer):
    """Packet capture for Windows using Npcap/WinPcap."""
    
    def __init__(self):
        self.name = "Npcap/WinPcap (Windows)"
    
    def check_dependencies(self) -> Tuple[bool, str]:
        """Check if Npcap is installed by testing Scapy's packet capture capability."""
        try:
            from scapy.all import get_if_list
            interfaces = get_if_list()
            if interfaces:
                return True, f"Npcap/WinPcap working - {len(interfaces)} interfaces available"
            else:
                return False, "Npcap detected but no network interfaces available"
        except ImportError:
            return False, (
                "Scapy not installed. Install with: pip install scapy\n"
                "Also ensure Npcap is installed from: https://npcap.com/download/\n"
                "(Choose 'Install Npcap in WinPcap API-compatible Mode' during installation)"
            )
        except Exception as e:
            return False, f"Error checking Npcap: {e}"
    
    def capture(self, duration: int = 10, iface: Optional[str] = None):
        """Capture packets using Npcap/WinPcap."""
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
        except ImportError as e:
            raise RuntimeError(
                f"Scapy with Npcap/WinPcap support not available: {e}\n"
                "Make sure Npcap is installed and Scapy is in WinPcap compatibility mode."
            )
        
        # List available interfaces if not specified
        if iface is None:
            interfaces = get_if_list()
            if interfaces:
                iface = interfaces[0]
                print(f"[Packet Capture] Using interface: {iface}")
            else:
                raise RuntimeError("No network interfaces available for capture")
        
        print(f"[Packet Capture] Starting Npcap capture for {duration}s on interface {iface}")
        
        try:
            packets = sniff(iface=iface, timeout=duration, store=True)
            print(f"[Packet Capture] Captured {len(packets)} packets")
            return self._process_packets(packets)
        except PermissionError:
            raise RuntimeError(
                "Permission denied. Packet capture requires administrator privileges.\n"
                "Please run the application as Administrator."
            )
        except Exception as e:
            raise RuntimeError(f"Npcap capture failed: {e}")
    
    def _process_packets(self, packets):
        """Process captured packets into flows."""
        from scapy.all import IP, TCP, UDP, ICMP
        
        flows = defaultdict(lambda: {
            "start": None, "end": None, "proto": "other",
            "orig_bytes": 0, "resp_bytes": 0, "missed_bytes": 0,
            "orig_pkts": 0, "orig_ip_bytes": 0,
            "resp_pkts": 0, "resp_ip_bytes": 0,
            "syn_errors": 0, "rst_errors": 0, "total_pkts": 0,
            "dst": None, "dport": 0,
        })
        
        dst_counts = defaultdict(int)
        dst_syn_errs = defaultdict(int)
        
        for pkt in packets:
            if not pkt.haslayer(IP):
                continue
            
            ip = pkt[IP]
            proto = "tcp" if pkt.haslayer(TCP) else "udp" if pkt.haslayer(UDP) else "icmp" if pkt.haslayer(ICMP) else "other"
            sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
            key = (ip.src, ip.dst, sport, dport, proto)
            f = flows[key]
            t = float(pkt.time)
            
            if f["start"] is None:
                f["start"] = t
            f["end"] = t
            f["proto"] = proto
            f["dst"] = ip.dst
            f["dport"] = dport
            
            pkt_len = len(pkt)
            f["orig_pkts"] += 1
            f["orig_bytes"] += pkt_len
            f["orig_ip_bytes"] += pkt_len
            f["total_pkts"] += 1
            
            # Detect SYN-only packets
            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                if flags == 0x02:  # SYN only
                    f["syn_errors"] += 1
                    dst_syn_errs[ip.dst] += 1
            
            dst_counts[ip.dst] += 1
        
        return flows, dst_counts, dst_syn_errs


def capture_live_traffic_cross_platform(duration: int = 10, iface: Optional[str] = None) -> np.ndarray:
    """
    Cross-platform live traffic capture.
    Automatically selects appropriate capturer based on OS.
    
    Args:
        duration: Capture duration in seconds
        iface: Network interface (None for default)
        
    Returns:
        Numpy array of features (68 dimensions)
    """
    capturer = get_packet_capturer()
    print(f"[Packet Capture] Using {capturer.name}")
    
    # Check dependencies
    available, message = capturer.check_dependencies()
    if not available:
        raise RuntimeError(f"Dependencies not available:\n{message}")
    
    print(f"[Packet Capture] {message}")
    
    # Capture packets
    flows, dst_counts, dst_syn_errs = capturer.capture(duration, iface)
    
    if not flows:
        print("[Packet Capture] No packets captured")
        # Import here to avoid circular imports
        from core.preprocessor import N_FEATURES
        return np.zeros((1, N_FEATURES))
    
    # Convert flows to feature vectors
    # Import here to avoid circular imports
    from core.preprocessor import N_FEATURES
    import pickle
    
    rows = []
    for f in flows.values():
        dur = (f["end"] - f["start"]) if (f["start"] is not None and f["end"] != f["start"]) else 0.0
        total = f["total_pkts"] or 1
        serror_rate = f["syn_errors"] / total
        rerror_rate = f["rst_errors"] / total
        dst_count = dst_counts.get(f["dst"], 0)
        dst_serr = dst_syn_errs.get(f["dst"], 0)
        dst_serr_rate = dst_serr / dst_count if dst_count > 0 else 0.0
        
        # Build 68-feature row
        kdd_vals = [
            dur, f["orig_bytes"], f["resp_bytes"], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            dst_count, dst_count, serror_rate, serror_rate, rerror_rate, rerror_rate, 0, 0, 0,
            dst_count, dst_count, 0, 0, 0, 0, dst_serr_rate, dst_serr_rate, rerror_rate, rerror_rate,
        ]
        
        iot_vals = [
            f["orig_bytes"], f["resp_bytes"], f["missed_bytes"], f["orig_pkts"], f["orig_ip_bytes"],
            f["resp_pkts"], f["resp_ip_bytes"],
            int(f["proto"] == "icmp"), int(f["proto"] == "tcp"), int(f["proto"] == "udp"),
            0, 0, int(f["dport"] == 53), int(f["dport"] == 80), 0, int(f["dport"] == 22), int(f["dport"] == 443),
            0, 0, 0, 0, 0, 0, int(serror_rate > 0.5), 0, 0, 0, int(serror_rate < 0.1), 0, 0,
        ]
        
        rows.append(kdd_vals + iot_vals)
    
    X = np.array(rows, dtype=np.float64)
    
    # Scale using saved scaler
    scaler = pickle.load(open(Path(__file__).parent.parent / "saved_models" / "scaler.pkl", "rb"))
    return scaler.transform(X)


if __name__ == "__main__":
    print(f"OS Detected: {OS_TYPE}")
    capturer = get_packet_capturer()
    print(f"Packet Capturer: {capturer.name}")
    
    available, message = capturer.check_dependencies()
    print(f"Dependencies: {message}")
    
    if available:
        print("\nAttempting to capture 5 seconds of traffic...")
        try:
            X = capture_live_traffic_cross_platform(duration=5)
            print(f"Captured traffic features shape: {X.shape}")
        except Exception as e:
            print(f"Capture failed: {e}")
