# -------------------------------------------------
# Network Traffic Analyzer – REALISTIC FINAL VERSION
# -------------------------------------------------

from scapy.all import sniff, IP, TCP, UDP, ICMP
from db import init_db, get_connection
init_db()
import matplotlib.pyplot as plt
import threading
import time
from collections import defaultdict, deque

# -----------------------------
# Configuration
# -----------------------------
LOG_FILE = "network_log.txt"

WINDOW_SIZE = 15            # seconds
SUMMARY_INTERVAL = 10       # seconds

PACKET_RATE_ALERT = 120     # realistic threshold
PORT_SCAN_ALERT = 10        # realistic threshold
ALERT_COOLDOWN = 60         # seconds (per IP per alert)

SAFE_PORTS = {80, 443, 53, 22}
IGNORED_IP_PREFIXES = ("127.", "192.168.", "10.")

# -----------------------------
# Data Structures
# -----------------------------
packet_window = defaultdict(deque)
port_window = defaultdict(set)
total_packets = defaultdict(int)
last_alert_time = defaultdict(dict)

# -----------------------------
# Logging
# -----------------------------
def log(text):
    with open(LOG_FILE, "a") as f:
        f.write(text + "\n")

# -----------------------------
# Alert Control
# -----------------------------
def can_alert(ip, alert_type):
    now = time.time()
    last = last_alert_time[ip].get(alert_type, 0)
    if now - last >= ALERT_COOLDOWN:
        last_alert_time[ip][alert_type] = now
        return True
    return False

def print_alert(ip, title, details):
    print("\n" + "=" * 55)
    print(f"🚨 ALERT: {title}")
    print(f"Source IP : {ip}")
    print(f"Details   : {details}")
    print("=" * 55 + "\n")

# -----------------------------
# Packet Processing
# -----------------------------
def process_packet(packet):
    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    now = time.time()

    # Ignore local noise
    if src.startswith(IGNORED_IP_PREFIXES):
        return

    if packet.haslayer(TCP):
        proto = "TCP"
        dport = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto = "UDP"
        dport = packet[UDP].dport
    elif packet.haslayer(ICMP):
        proto = "ICMP"
        dport = None
    else:
        return

    total_packets[src] += 1
    packet_window[src].append(now)

    if dport and dport not in SAFE_PORTS:
        port_window[src].add(dport)

    # Cleanup window
    while packet_window[src] and now - packet_window[src][0] > WINDOW_SIZE:
        packet_window[src].popleft()

    log(f"[DATA] {src} {proto} PORT={dport}")

    # Packet rate alert
    if len(packet_window[src]) > PACKET_RATE_ALERT:
        if can_alert(src, "rate"):
            print_alert(
                src,
                "High Traffic Rate",
                f"{len(packet_window[src])} packets in {WINDOW_SIZE}s"
            )
            log(f"[ALERT] {src} High packet rate")

    # Port scan alert
    if len(port_window[src]) > PORT_SCAN_ALERT:
        if can_alert(src, "portscan"):
            print_alert(
                src,
                "Suspicious Port Scanning",
                f"{len(port_window[src])} unusual ports"
            )
            log(f"[ALERT] {src} Port scan detected")

# -----------------------------
# Summary Printer
# -----------------------------
def print_summary():
    while True:
        time.sleep(SUMMARY_INTERVAL)
        if not total_packets:
            continue

        print("\n[INFO] Traffic Summary")
        print("-" * 45)
        for ip, count in total_packets.items():
            print(f"{ip:<18} Packets: {count:<6} Ports: {len(port_window[ip])}")
        print("-" * 45)

# -----------------------------
# Live Graph
# -----------------------------
def live_graph():
    plt.ion()
    fig, ax = plt.subplots(figsize=(8, 4))

    while True:
        ax.clear()
        if total_packets:
            ips = list(total_packets.keys())[:6]
            counts = [total_packets[ip] for ip in ips]
            ax.bar(ips, counts)
            ax.set_title("Packet Count (Top IPs)")
            plt.xticks(rotation=30)
            plt.tight_layout()
        plt.pause(4)

# -----------------------------
# Threads
# -----------------------------
print("[INFO] Network Monitor Started")

threading.Thread(
    target=lambda: sniff(prn=process_packet, store=False),
    daemon=True
).start()

threading.Thread(
    target=print_summary,
    daemon=True
).start()

threading.Thread(
    target=live_graph,
    daemon=True
).start()

while True:
    time.sleep(1)
