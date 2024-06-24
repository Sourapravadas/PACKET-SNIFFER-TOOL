import scapy.all as scapy
from scapy.layers import http

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        print(f"IP Packet: {src_ip} -> {dst_ip}")

        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        if packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            print(f"UDP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        if packet.haslayer(scapy.ICMP):
            icmp_type = packet[scapy.ICMP].type
            icmp_code = packet[scapy.ICMP].code
            print(f"ICMP Packet: {src_ip} -> {dst_ip} (Type: {icmp_type}, Code: {icmp_code})")

        if packet.haslayer(scapy.ARP):
            arp_opcode = packet[scapy.ARP].op
            print(f"ARP Packet: {src_ip} -> {dst_ip} (Opcode: {arp_opcode})")

        if packet.haslayer(http.HTTPRequest):
            url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
            print(f"HTTP Request: {url}")

def sniff_packets(interface, count):
    scapy.sniff(iface=interface, count=count, store=False, prn=process_packet)

interface = input("Enter the interface to sniff (e.g. eth0, wlan0): ")
count = int(input("Enter the number of packets to capture: "))

sniff_packets(interface, count)