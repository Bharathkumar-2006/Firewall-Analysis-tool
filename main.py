import scapy.all as scapy
import argparse

def send_packets(target,last_port):
    allowed_packets = []
    allowed_ports = []
    
    packet_types = ['TCP', 'UDP', 'ICMP']
    tcp_flags = ['S', 'A', 'F', 'R', 'P', 'U']  #SYN, ACK, FIN, RST, PSH, URG

    for port in range(1, last_port): 
        for pkt_type in packet_types:
            if pkt_type == 'TCP':
                for flag in tcp_flags:
                    pkt = scapy.IP(dst=target)/scapy.TCP(dport=port, flags=flag)
                    response = scapy.sr1(pkt, timeout=2, verbose=False)
                    if response and pkt not in allowed_packets:
                        allowed_packets.append(pkt)
                        if port not in allowed_ports:
                            allowed_ports.append(port)
            elif pkt_type == 'UDP':
                pkt = scapy.IP(dst=target)/scapy.UDP(dport=port)
                response = scapy.sr1(pkt, timeout=2, verbose=False)
                if response and pkt not in allowed_packets:
                    allowed_packets.append(pkt)
                    if port not in allowed_ports:
                        allowed_ports.append(port)
            elif pkt_type == 'ICMP':
                icmp_types = [0, 3, 4, 5, 8, 11, 12]  #Echo Reply,Destination Unreachable, etc.
                for icmp_type in icmp_types:
                    pkt = scapy.IP(dst=target)/scapy.ICMP(type=icmp_type)
                    response = scapy.sr1(pkt, timeout=2, verbose=False)
                    if response and pkt not in allowed_packets:
                        allowed_packets.append(pkt)
            else:
                continue    
    return allowed_packets, allowed_ports
    
def display_result(allowed_packets,allowed_ports):
    print("\nAllowed packets")
    for pkt in allowed_packets:
        print(f"-{pkt.summary()}")    
    for prt in allowed_ports:
        print(f"-{prt}")
        
#def nmap_scan(target_ip,allowed_packets):
    
    
            
def main():
    parser = argparse.ArgumentParser(description="Firewall Analysis Tool")
    parser.add_argument("target",help="target ip address")
    parser.add_argument("last_port",help="last port to scan")
    args = parser.parse_args()
    
    allowed_packets,allowed_ports = send_packets(args.target,args.last_port)
    display_result(allowed_packets,allowed_ports)
    print("\nRunning scan...")
    nmap_scan(args.target,allowed_packets)
    
    
if __name__ == "__main__":
    main()