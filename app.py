from flask import Flask, render_template
from scapy.all import sniff
import threading

from db import init_db, fetch_recent
from analyzer import process_packet

app = Flask(__name__)
init_db()

# 🔹 Background packet sniffer
def start_sniffer():
    sniff(prn=process_packet, store=False)

# 🔹 Start sniffer in background (ONCE)
sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
sniffer_thread.start()

@app.route("/")
def dashboard():
    records = fetch_recent(200)
    total_packets = sum(r[4] for r in records)
    unique_ips = len(set(r[1] for r in records))
    alert_count = len([r for r in records if r[6] != "NONE"])

    return render_template(
        "dashboard.html",
        total_packets=total_packets,
        unique_ips=unique_ips,
        alert_count=alert_count
    )

@app.route("/traffic")
def traffic():
    records = fetch_recent(200)
    return render_template("traffic.html", records=records)

@app.route("/alerts")
def alerts():
    records = fetch_recent(200)
    alerts_only = [r for r in records if r[6] != "NONE"]
    return render_template("alerts.html", records=alerts_only)

if __name__ == "__main__":
    app.run(debug=True)
