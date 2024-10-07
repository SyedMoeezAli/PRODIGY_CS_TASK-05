from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def analyze_packet(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Display basic IP packet information
        print(f"\nSource IP: {src_ip} -> Destination IP: {dst_ip}")

        # Determine the transport layer protocol
        if protocol == 6 and TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP | Source Port: {tcp_layer.sport} -> Destination Port: {tcp_layer.dport}")
            print(f"Payload (Raw Data): {bytes(tcp_layer.payload)}")
        elif protocol == 17 and UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP | Source Port: {udp_layer.sport} -> Destination Port: {udp_layer.dport}")
            print(f"Payload (Raw Data): {bytes(udp_layer.payload)}")
        elif protocol == 1 and ICMP in packet:
            print(f"Protocol: ICMP")
            print(f"Payload (Raw Data): {bytes(packet[ICMP].payload)}")
        else:
            print(f"Protocol: Unknown")

def start_sniffer():
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    # Start sniffing packets on the network
    sniff(prn=analyze_packet, filter="ip", store=0)

if __name__ == "__main__":
    start_sniffer()
