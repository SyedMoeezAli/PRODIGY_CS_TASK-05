from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP


def packet_handler(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] Packet: {ip_layer.src} -> {ip_layer.dst}")
        
        
        if packet.haslayer(TCP):
            print(f"    Protocol: TCP | Source Port: {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"    Protocol: UDP | Source Port: {packet[UDP].sport} -> Destination Port: {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print("    Protocol: ICMP")

        
        if packet[IP].payload:
            print(f"    Payload: {bytes(packet[IP].payload).hex()}")  # Print payload as hex for readability


def start_sniffer(interface):
    print(f"[*] Starting packet sniffer on interface: {interface}")
    sniff(iface=interface, prn=packet_handler, store=False)

if __name__ == "__main__":
   
    interface = input("Enter the network interface to sniff on (e.g., eth0, wlan0): ")
    start_sniffer(interface)
