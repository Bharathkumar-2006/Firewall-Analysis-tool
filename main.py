import scapy.all as scapy
import argparse

def send_packets(target,last_port):
    
    
def display_result(allowed_packets,allowed_ports):
    
    
def nmap_scan(target,alowed_packets):
    
    
            
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