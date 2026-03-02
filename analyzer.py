# analyzer.py
from scapy.all import IP, TCP, UDP, ICMP
import time
from db import insert_record

PACKET_THRESHOLD = 25
PORT_THRESHOLD = 10
ALERT_COOLDOWN = 30

ip_packet_count = {}
ip_ports = {}
last_alert_time = {}

def process_packet(packet):
    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst

    if packet.haslayer(TCP):
        proto = "TCP"
        port = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto = "UDP"
        port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        proto = "ICMP"
        port = None
    else:
        return

    if src not in ip_packet_count:
        ip_packet_count[src] = 0
        ip_ports[src] = set()
        last_alert_time[src] = 0

    ip_packet_count[src] += 1
    if port:
        ip_ports[src].add(port)

    alert = "NONE"
    now = time.time()

    if (
        ip_packet_count[src] > PACKET_THRESHOLD or
        len(ip_ports[src]) > PORT_THRESHOLD
    ):
        if now - last_alert_time[src] > ALERT_COOLDOWN:
            alert = f"Suspicious activity from {src}"
            last_alert_time[src] = now

    # 🔴 THIS WAS MISSING BEFORE
    insert_record(
        src, dst, proto,
        ip_packet_count[src],
        len(ip_ports[src]),
        alert
    )
