
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import argparse
import sys

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def get_protocol_name(packet):
    """Determine the protocol of the packet."""
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    else:
        return "Other"

def get_service_name(port, protocol):
    """Return common service name based on port number."""
    common_ports = {
        80: "HTTP",
        443: "HTTPS",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        110: "POP3",
        143: "IMAP",
        3306: "MySQL",
        3389: "RDP"
    }
    
    return common_ports.get(port, str(port))

def packet_callback(packet, verbose=False):
    """Process each packet and print its information."""
    if not IP in packet:
        return
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = get_protocol_name(packet)
    
    src_port = dst_port = "N/A"
    service = "N/A"
    
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        service = get_service_name(dst_port, "TCP")
        flags = get_tcp_flags(packet)
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        service = get_service_name(dst_port, "UDP")
        flags = ""
    else:
        flags = ""
    
    print(f"{Colors.HEADER}[{timestamp}]{Colors.ENDC} {Colors.BOLD}{protocol}{Colors.ENDC} - "
          f"{Colors.BLUE}{src_ip}{Colors.ENDC}:{src_port} -> "
          f"{Colors.GREEN}{dst_ip}{Colors.ENDC}:{dst_port} - "
          f"Service: {Colors.YELLOW}{service}{Colors.ENDC} {flags}")
    
    if verbose and (TCP in packet or UDP in packet):
        print_packet_details(packet)
        
    print("-" * 80)

def get_tcp_flags(packet):
    """Return a string representation of TCP flags."""
    if not TCP in packet:
        return ""
    
    flags = []
    if packet[TCP].flags.S:
        flags.append(f"{Colors.RED}SYN{Colors.ENDC}")
    if packet[TCP].flags.A:
        flags.append(f"{Colors.GREEN}ACK{Colors.ENDC}")
    if packet[TCP].flags.F:
        flags.append(f"{Colors.YELLOW}FIN{Colors.ENDC}")
    if packet[TCP].flags.R:
        flags.append(f"{Colors.RED}RST{Colors.ENDC}")
    if packet[TCP].flags.P:
        flags.append(f"{Colors.BLUE}PSH{Colors.ENDC}")
    
    if flags:
        return "Flags: " + " ".join(flags)
    return ""

def print_packet_details(packet):
    """Print detailed information about the packet."""
    if packet.haslayer("Raw"):
        payload = packet["Raw"].load
        try:
            decoded = payload.decode("utf-8")
            if any(32 <= ord(c) <= 126 or c in "\r\n\t" for c in decoded):
                # Only show if it contains printable characters
                print(f"{Colors.YELLOW}Payload Preview:{Colors.ENDC}")
                print(decoded[:100] + ("..." if len(decoded) > 100 else ""))
            else:
                print(f"{Colors.YELLOW}Payload (hex):{Colors.ENDC}")
                print(payload.hex()[:100] + ("..." if len(payload) > 100 else ""))
        except UnicodeDecodeError:
            print(f"{Colors.YELLOW}Payload (hex):{Colors.ENDC}")
            print(payload.hex()[:100] + ("..." if len(payload) > 100 else ""))

def main():
    parser = argparse.ArgumentParser(description="Simple Network Packet Analyzer")
    parser.add_argument("-i", "--interface", help="Network interface to capture from")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for infinite)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter to apply (e.g., 'tcp port 80')")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose packet information")
    args = parser.parse_args()

    print(f"{Colors.HEADER}Basic Network Packet Analyzer{Colors.ENDC}")
    print(f"Starting capture on interface: {args.interface or 'default'}")
    if args.filter:
        print(f"Filter: {args.filter}")
    print(f"Verbose mode: {'On' if args.verbose else 'Off'}")
    print("Press Ctrl+C to stop capturing")
    print("-" * 80)
    
    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=lambda pkt: packet_callback(pkt, args.verbose),
            count=args.count
        )
    except PermissionError:
        print(f"{Colors.RED}Error: This program requires administrator/root privileges.{Colors.ENDC}")
        print("Try running with sudo or as administrator.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nCapture stopped by user")
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.ENDC}")

if __name__ == "__main__":
    main()