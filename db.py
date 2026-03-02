import sqlite3
from datetime import datetime

DB_NAME = "netpulse.db"

def get_connection():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            source_ip TEXT,
            dest_ip TEXT,
            protocol TEXT,
            packet_count INTEGER,
            port_count INTEGER,
            alert TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_record(src, dst, proto, pkt_count, port_count, alert="NONE"):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO traffic VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        src, dst, proto, pkt_count, port_count, alert
    ))
    conn.commit()
    conn.close()

def fetch_recent(limit=50):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT time, source_ip, dest_ip, protocol,
               packet_count, port_count, alert
        FROM traffic
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows
