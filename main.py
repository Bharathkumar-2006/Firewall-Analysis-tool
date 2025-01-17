import scapy.all as scapy
import argparse

def craft_and_send_packets(target_ip, last_port=65535):
    allowed_packets = []
    allowed_ports = []
    
    packet_types = ['TCP', 'UDP', 'ICMP']
    tcp_flags = ['S', 'A', 'F', 'R', 'P', 'U']  # SYN, ACK, FIN, RST, PSH, URG

    for port in range(0, last_port + 1):
        for pkt_type in packet_types:
            if pkt_type == 'TCP':
                for flag in tcp_flags:
                    pkt = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags=flag)
                    response = scapy.sr1(pkt, timeout=2, verbose=False)
                    if response and pkt not in allowed_packets:
                        allowed_packets.append(pkt)
                        if port not in allowed_ports:
                            allowed_ports.append(port)
            elif pkt_type == 'UDP':
                pkt = scapy.IP(dst=target_ip)/scapy.UDP(dport=port)
                response = scapy.sr1(pkt, timeout=2, verbose=False)
                if response and pkt not in allowed_packets:
                    allowed_packets.append(pkt)
                    if port not in allowed_ports:
                        allowed_ports.append(port)
            elif pkt_type == 'ICMP':
                icmp_types = [0, 3, 4, 5, 8, 11, 12]  # Echo Reply, Destination Unreachable, etc.
                for icmp_type in icmp_types:
                    pkt = scapy.IP(dst=target_ip)/scapy.ICMP(type=icmp_type)
                    response = scapy.sr1(pkt, timeout=2, verbose=False)
                    if response and pkt not in allowed_packets:
                        allowed_packets.append(pkt)
            else:
                continue
    
    return allowed_packets, allowed_ports

def display_results(allowed_packets, allowed_ports, ip_address):
    filename = f"{ip_address}_output.txt"
    with open(filename, 'w') as file:
        file.write("Allowed Packets:\n")
        for pkt in allowed_packets:
            file.write(f"- {pkt.summary()}\n")
  
        file.write("\nAllowed Ports:\n")
        for port in allowed_ports:
            file.write(f"- {port}\n")

    print(f"Results have been written to {filename}")

def main():
    parser = argparse.ArgumentParser(description="Firewall Analyzer Tool")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("last_port", type=int, default=65535, help="Last port to scan (default: 65535)")
    args = parser.parse_args()
    print("Sending different types of packets to the ports...")
    allowed_packets, allowed_ports = craft_and_send_packets(args.target, args.last_port)
    display_results(allowed_packets, allowed_ports,args.target)
        

if __name__ == "__main__":
    main()
