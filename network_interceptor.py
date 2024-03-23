import scapy.all as scapy
from datetime import datetime

def log_packet(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        if packet.haslayer(scapy.TCP):
            protocol = "TCP"
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            payload = str(packet[scapy.TCP].payload)
        elif packet.haslayer(scapy.UDP):
            protocol = "UDP"
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            payload = str(packet[scapy.UDP].payload)
        else:
            protocol = "Other"
            src_port = None
            dst_port = None
            payload = None
        log_message = f"[{timestamp}] {protocol} packet: {ip_src}:{src_port} --> {ip_dst}:{dst_port}\nPayload: {payload}"
        with open("intercepted_packets.log", "a") as logfile:
            logfile.write(log_message + "\n\n")
        print(log_message)

def intercept():
    print("[+] Starting interceptor...")
    try:
        scapy.sniff(prn=log_packet, store=0)
    except KeyboardInterrupt:
        print("\n[+] Stopping interceptor...")

if __name__ == "__main__":
    intercept()
