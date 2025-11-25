# network_sniffer_luxury.py
#
# Requirements:
#   pip install scapy matplotlib requests
# Optional (for IDS): pip install scikit-learn joblib
# Optional (for gradient background): pip install pillow
#
# Features:
# - Tkinter GUI Network Sniffer (Scapy)
# - Collapsible sidebar with tooltips
# - Luxury dark theme (Satin Black + Gold)
# - Start/Stop toggle button for sniffing
# - IDS with toggle button (Isolation Forest, if available)
# - Traffic Analytics pie chart with legend (no overlapping labels)
# - Device details view with on-demand:
#       * MAC Vendor lookup (buttons)
#       * IP Geolocation lookup (button)
# - Vendor info cached and used in main table AFTER lookup

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sniff, ARP, IP, Ether, DNS, DNSQR
from collections import defaultdict, deque
import threading
import subprocess
import platform
import csv
import time
import queue
import os
import numpy as np
import requests
import ipaddress

# Optional: Pillow for nicer gradient background (fallback to solid if not present)
try:
    from PIL import Image, ImageDraw, ImageFilter, ImageTk
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

# Optional sklearn & joblib for IDS model; if missing, IDS is gracefully disabled.
try:
    from sklearn.ensemble import IsolationForest
    import joblib
except Exception:
    IsolationForest = None
    joblib = None

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

# -------------------- Backend state & logic --------------------
devices = {}  # MAC -> IP
protocols_by_device = defaultdict(lambda: defaultdict(int))
destinations_by_device = defaultdict(set)
packet_counters = defaultdict(int)
bytes_counters = defaultdict(int)
last_seen = {}
recent_packets = defaultdict(lambda: deque(maxlen=200))

sniffing = False
sniff_thread = None
packet_queue = queue.Queue()

WINDOW_SECONDS = 10
feature_windows = defaultdict(lambda: deque(maxlen=6))
current_window = defaultdict(lambda: {
    "pkts": 0, "bytes": 0, "dests": set(),
    "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "dns": 0
})
window_lock = threading.Lock()

ids_model = None
model_path = "ids_model.joblib"
ids_enabled = False
baseline_collection = []
collecting_baseline = False
BASELINE_PERIODS = 6
CONTAMINATION = 0.02

alerts = []
anomaly_reasons = defaultdict(lambda: deque(maxlen=50))

Z_THRESHOLD = 2.0
MULTIPLIER_THRESHOLD = 3.0
FEATURE_LABELS = [
    "packets", "bytes", "unique_dests",
    "tcp", "udp", "icmp", "arp", "dns"
]

# MAC vendor cache & sample OUI map (offline)
mac_vendor_cache = {}
OUI_VENDOR_MAP = {
    "00:1A:2B": "Cisco Systems",
    "00:1C:B3": "Apple, Inc.",
    "3C:5A:B4": "Google, Inc.",
    "F4:5C:89": "Samsung Electronics",
    "18:CF:5E": "Xiaomi Communications",
    "B8:27:EB": "Raspberry Pi Foundation",
    "BC:92:6B": "Dell Inc.",
    "00:25:9C": "Intel Corporate",
    "00:50:56": "VMware, Inc.",
    "00:15:5D": "Microsoft Corp."
}

# Vendor info per MAC (only filled on-demand)
vendor_info = {}  # MAC -> vendor string

# For refreshing vendor in main table from device details
main_device_table = None  # assigned in launch_gui

# -------------------- Utility & packet processing --------------------
def get_connected_ssid():
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output(
                "netsh wlan show interfaces",
                shell=True
            ).decode("utf-8", errors="ignore")
            ssid, interface = "Unknown", "Unknown"
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Name") and ':' in line:
                    interface = line.split(":", 1)[1].strip()
                if line.startswith("SSID") and "BSSID" not in line:
                    ssid = line.split(":", 1)[1].strip()
            return ssid, interface
        except Exception:
            return "Unknown", "Unknown"
    if platform.system() == "Linux":
        try:
            output = subprocess.check_output(
                ["iwgetid", "-r"], stderr=subprocess.DEVNULL
            ).decode().strip()
            return output if output else "Unknown", "Unknown"
        except Exception:
            return "Not available", "Not available"
    return "Not available", "Not available"

def normalize_mac(mac: str) -> str:
    """Normalize MAC to upper, colon-separated."""
    mac = mac.strip().upper().replace("-", ":")
    parts = mac.split(":")
    if len(parts) < 6:
        return mac
    return ":".join(parts[:6])

def lookup_mac_vendor(mac: str) -> str:
    """Offline-first vendor lookup, with optional online fallback.
       Called ONLY when user clicks a vendor lookup button."""
    if not mac:
        return "Unknown"
    norm = normalize_mac(mac)
    if norm in mac_vendor_cache:
        return mac_vendor_cache[norm]
    prefix = ":".join(norm.split(":")[:3])
    # 1) Offline OUI table
    if prefix in OUI_VENDOR_MAP:
        vendor = OUI_VENDOR_MAP[prefix]
        mac_vendor_cache[norm] = vendor
        return vendor
    # 2) Optional online fallback (best-effort, may fail quietly)
    try:
        url = f"https://api.macvendors.co/{prefix}"
        resp = requests.get(url, timeout=3)
        vendor = resp.text.strip()
        if vendor and "errors" not in vendor.lower():
            mac_vendor_cache[norm] = vendor
            return vendor
    except Exception:
        pass
    mac_vendor_cache[norm] = "Unknown"
    return "Unknown"

def packet_callback(packet):
    try:
        if not packet:
            return
        summary = {}
        if packet.haslayer(Ether):
            ether = packet[Ether]
            mac = ether.src
            summary['mac'] = mac
            summary['len'] = len(packet)
            summary['time'] = time.time()
            if packet.haslayer(IP):
                summary['ip'] = packet[IP].src
                summary['dst'] = packet[IP].dst
                summary['proto'] = packet[IP].proto
            elif packet.haslayer(ARP):
                summary['ip'] = packet[ARP].psrc
                summary['dst'] = None
                summary['proto'] = 'ARP'
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                try:
                    summary['dns'] = packet[DNSQR].qname.decode().strip('.')
                except Exception:
                    summary['dns'] = None
            packet_queue.put(summary)
    except Exception:
        pass

def process_queued_packets(tree, info_labels, alerts_text):
    updated = False
    while True:
        try:
            summary = packet_queue.get_nowait()
        except queue.Empty:
            break
        mac = summary.get('mac')
        if not mac:
            continue
        ip = summary.get('ip')
        dst = summary.get('dst')
        proto = summary.get('proto')
        dns = summary.get('dns')
        plen = summary.get('len', 0)
        ptime = summary.get('time', time.time())

        if ip:
            devices[mac] = ip
        last_seen[mac] = ptime
        packet_counters[mac] += 1
        bytes_counters[mac] += plen

        if dst:
            destinations_by_device[mac].add(dst)
        if dns:
            destinations_by_device[mac].add(dns)

        recent_packets[mac].appendleft({
            'time': ptime, 'ip': ip,
            'dst': dst or dns, 'proto': proto, 'len': plen
        })

        if proto == 6 or proto == '6':
            protocols_by_device[mac]['TCP'] += 1
        elif proto == 17 or proto == '17':
            protocols_by_device[mac]['UDP'] += 1
        elif proto == 1 or proto == '1':
            protocols_by_device[mac]['ICMP'] += 1
        elif proto == 'ARP':
            protocols_by_device[mac]['ARP'] += 1
        if dns:
            protocols_by_device[mac]['DNS'] += 1

        # Feature window update
        with window_lock:
            w = current_window[mac]
            w['pkts'] += 1
            w['bytes'] += plen
            if dst:
                w['dests'].add(dst)
            if proto == 6 or proto == '6':
                w['tcp'] += 1
            elif proto == 17 or proto == '17':
                w['udp'] += 1
            elif proto == 1 or proto == '1':
                w['icmp'] += 1
            elif proto == 'ARP':
                w['arp'] += 1
            if dns:
                w['dns'] += 1

        updated = True

    if updated:
        update_table(tree)
        update_info_labels(info_labels)
    run_window_rollover_if_needed(tree, alerts_text)

last_window_time = time.time()

def run_window_rollover_if_needed(tree, alerts_text):
    global last_window_time, collecting_baseline
    now = time.time()
    if now - last_window_time >= WINDOW_SECONDS:
        with window_lock:
            for mac, data in list(current_window.items()):
                feat = [
                    data['pkts'], data['bytes'], len(data['dests']),
                    data['tcp'], data['udp'], data['icmp'],
                    data['arp'], data['dns']
                ]
                feature_windows[mac].append(feat)
                current_window[mac] = {
                    "pkts": 0, "bytes": 0, "dests": set(),
                    "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "dns": 0
                }
        last_window_time = now
        if collecting_baseline:
            collect_baseline_samples()
        if ids_enabled and ids_model is not None:
            score_and_flag_devices(tree, alerts_text)

def collect_baseline_samples():
    global baseline_collection, collecting_baseline
    rows = []
    for mac, deq in feature_windows.items():
        if len(deq) >= BASELINE_PERIODS:
            arr = np.array(list(deq)[-BASELINE_PERIODS:])
            avg = np.mean(arr, axis=0)
            rows.append(avg)
    if rows:
        baseline_collection.extend(rows)
    if len(baseline_collection) >= 50:
        collecting_baseline = False
        train_ids_model()

def train_ids_model():
    global ids_model
    if IsolationForest is None:
        return
    X = np.array(baseline_collection)
    if len(X) < 5:
        return
    model = IsolationForest(contamination=CONTAMINATION, random_state=42)
    model.fit(X)
    ids_model = model
    try:
        joblib.dump(model, model_path)
    except Exception:
        pass

def load_ids_model_if_exists():
    global ids_model
    if joblib is None:
        return
    if os.path.exists(model_path):
        try:
            ids_model = joblib.load(model_path)
        except Exception:
            ids_model = None

def explain_anomaly(mac, deq):
    reasons = []
    try:
        arr = np.array(list(deq))
        if arr.size == 0 or arr.shape[0] == 1:
            return reasons
        hist = arr[:-1]
        last = arr[-1].astype(float)
        mu = np.mean(hist, axis=0)
        sigma = np.std(hist, axis=0, ddof=0)
        for i, feat_name in enumerate(FEATURE_LABELS):
            last_val = float(last[i])
            mean_val = float(mu[i]) if not np.isnan(mu[i]) else 0.0
            std_val = float(sigma[i]) if not np.isnan(sigma[i]) else 0.0
            if std_val > 0:
                z = (last_val - mean_val) / std_val
            else:
                z = None
            if z is not None and z >= Z_THRESHOLD:
                reasons.append(
                    f"High {feat_name} (z={z:.2f}, last={int(last_val)}, mean={int(mean_val)})"
                )
            elif mean_val > 0 and last_val >= mean_val * MULTIPLIER_THRESHOLD:
                reasons.append(f"Spike in {feat_name} (last={int(last_val)})")
        last_unique = int(arr[-1][2])
        if last_unique >= 20:
            reasons.append("Many unique destinations")
        last_dns = int(arr[-1][7])
        if last_dns >= 30:
            reasons.append("High DNS query rate")
    except Exception:
        pass
    return reasons

def score_and_flag_devices(tree, alerts_text):
    rows = []
    macs = []
    for mac, deq in feature_windows.items():
        if len(deq) == 0:
            continue
        arr = np.array(list(deq))
        rows.append(np.mean(arr, axis=0))
        macs.append(mac)
    if not rows:
        return
    X = np.array(rows)
    try:
        preds = ids_model.predict(X)
        scores = ids_model.decision_function(X)
    except Exception:
        return
    for mac, pred, score in zip(macs, preds, scores):
        if pred == -1:
            deq = feature_windows.get(mac, deque())
            reasons = explain_anomaly(mac, deq)
            if reasons:
                msg = (
                    f"Anomaly detected on {mac} (score={score:.4f}) - Reasons: "
                    + " | ".join(reasons)
                )
            else:
                msg = f"Anomaly detected on {mac} (score={score:.4f})"
            log_alert(msg, alerts_text)
            anomaly_reasons[mac].appendleft(
                (time.strftime('%Y-%m-%d %H:%M:%S'), reasons)
            )
            highlight_device_in_tree(tree, mac)

def highlight_device_in_tree(tree, mac):
    for item in tree.get_children():
        vals = tree.item(item, 'values')
        # MAC is at index 1 (IP, MAC, Vendor, Protocols, ...)
        if len(vals) >= 2 and vals[1] == mac:
            tree.item(item, tags=('anomaly',))
            tree.tag_configure('anomaly', background='#5a0000')

def log_alert(msg, alerts_text):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    full = f"[{timestamp}] {msg}"
    alerts.append(full)
    try:
        alerts_text.config(state='normal')
        alerts_text.insert('end', full + "\n")
        alerts_text.see('end')
        alerts_text.config(state='disabled')
    except Exception:
        pass

# -------------------- Theme definitions (Luxury Satin Black + Gold) --------------------
DARK_THEME = {
    "bg": "#0A0A0A",        # main background
    "panel_bg": "#151515",  # sidebars / panels
    "card_bg": "#151515",   # cards
    "fg": "#EADBC8",        # main text (warm off-white)
    "muted": "#9A8C76",     # secondary text
    "accent": "#C8A94D",    # gold
    "accent2": "#B38C2A",   # deeper gold
    "text_bg": "#111111",   # text widgets
    "panel_fg": "#0A0A0A"   # text over accent backgrounds
}

LIGHT_THEME = {
    "bg": "#E5E1DA",        # warm light beige
    "panel_bg": "#D5CFC3",
    "card_bg": "#F3EEE5",
    "fg": "#3A3125",
    "muted": "#7B6C57",
    "accent": "#C8A94D",    # still gold, to keep identity
    "accent2": "#B38C2A",
    "text_bg": "#F7F2E9",
    "panel_fg": "#0A0A0A"
}

APP_THEME = DARK_THEME.copy()

def apply_theme_to_style(root):
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure(
        "Treeview",
        background=APP_THEME["card_bg"],
        foreground=APP_THEME["fg"],
        fieldbackground=APP_THEME["card_bg"],
        rowheight=26
    )
    style.configure(
        "Treeview.Heading",
        background=APP_THEME["panel_bg"],
        foreground=APP_THEME["fg"],
        font=("Segoe UI", 10, "bold")
    )
    style.map(
        "Treeview",
        background=[("selected", APP_THEME["accent"])],
        foreground=[("selected", APP_THEME["panel_fg"])]
    )
    style.configure("TButton", font=("Segoe UI", 10, "bold"))
    root.configure(bg=APP_THEME["bg"])

def make_gradient_image(width, height):
    if not PIL_AVAILABLE:
        return None
    img = Image.new("RGBA", (width, height), APP_THEME["bg"])
    draw = ImageDraw.Draw(img)
    top_col = tuple(
        int(APP_THEME["bg"].lstrip('#')[i:i+2], 16)
        for i in (0, 2, 4)
    )
    bottom_col = tuple(
        int(APP_THEME["panel_bg"].lstrip('#')[i:i+2], 16)
        for i in (0, 2, 4)
    )
    for y in range(height):
        ratio = y / max(1, height - 1)
        r = int(top_col[0] * (1 - ratio) + bottom_col[0] * ratio)
        g = int(top_col[1] * (1 - ratio) + bottom_col[1] * ratio)
        b = int(top_col[2] * (1 - ratio) + bottom_col[2] * ratio)
        draw.line([(0, y), (width, y)], fill=(r, g, b, 255))
    img = img.filter(ImageFilter.GaussianBlur(radius=10))
    return ImageTk.PhotoImage(img)

# -------------------- Device detail window (on-demand vendor + geo) --------------------
def open_device_detail_window(mac):
    detail_win = tk.Toplevel()
    detail_win.title(f"Device Details - {mac}")
    detail_win.geometry("900x600")
    detail_win.configure(bg=APP_THEME["bg"])

    summary_frame = tk.Frame(
        detail_win,
        bg=APP_THEME["panel_bg"],
        relief="groove",
        bd=1
    )
    summary_frame.pack(fill='x', pady=8)

    ip = devices.get(mac, 'N/A')

    tk.Label(
        summary_frame,
        text=f"MAC: {mac}",
        bg=APP_THEME["panel_bg"],
        fg=APP_THEME["accent"],
        font=("Segoe UI", 12, "bold")
    ).pack(side='left', padx=10)
    tk.Label(
        summary_frame,
        text=f"IP: {ip}",
        bg=APP_THEME["panel_bg"],
        fg=APP_THEME["fg"],
        font=("Segoe UI", 12)
    ).pack(side='left', padx=10)

    anom_count = sum(1 for a in alerts if mac in a)
    tk.Label(
        summary_frame,
        text=f"Anomalies: {anom_count}",
        bg=APP_THEME["panel_bg"],
        fg='red' if anom_count > 0 else APP_THEME["fg"],
        font=("Segoe UI", 12, "bold")
    ).pack(side='left', padx=10)

    # Vendor + Geo labels (initially not looked up)
    vendor_text = tk.StringVar(
        value="Vendor: (click a lookup button)"
    )
    geo_text = tk.StringVar(
        value="Geo: (not looked up)"
    )

    vendor_label = tk.Label(
        summary_frame,
        textvariable=vendor_text,
        bg=APP_THEME["panel_bg"],
        fg=APP_THEME["fg"],
        font=("Segoe UI", 11)
    )
    vendor_label.pack(side="left", padx=10)

    geo_label = tk.Label(
        summary_frame,
        textvariable=geo_text,
        bg=APP_THEME["panel_bg"],
        fg=APP_THEME["fg"],
        font=("Segoe UI", 11)
    )
    geo_label.pack(side="left", padx=10)

    # --- Vendor-only lookup button ---
    def lookup_vendor_only():
        vendor = lookup_mac_vendor(mac)
        vendor_info[mac] = vendor
        vendor_text.set(f"Vendor: {vendor}")

        # Refresh main table
        global main_device_table
        try:
            if main_device_table is not None:
                update_table(main_device_table)
        except Exception:
            pass

    vendor_btn = tk.Button(
        summary_frame,
        text="Vendor Only",
        command=lookup_vendor_only,
        bg=APP_THEME["accent2"],
        fg=APP_THEME["panel_fg"],
        font=("Segoe UI", 10, "bold"),
        relief="flat",
        padx=10,
        pady=4
    )
    vendor_btn.pack(side="right", padx=10)

    # Combined lookup button – performs BOTH vendor + geo on demand
    def lookup_info():
        # 1) Vendor lookup (sync, fast)
        vendor = lookup_mac_vendor(mac)
        vendor_info[mac] = vendor
        vendor_text.set(f"Vendor: {vendor}")

        # Optionally refresh main table vendor column
        global main_device_table
        try:
            if main_device_table is not None:
                update_table(main_device_table)
        except Exception:
            pass

        # 2) Geo lookup (async)
        def geo_worker():
            if not ip or ip == "N/A":
                result = "Geo: unavailable"
            else:
                try:
                    if ipaddress.ip_address(ip).is_private:
                        result = "Geo: Private network (no geo)"
                    else:
                        url = (
                            f"http://ip-api.com/json/{ip}"
                            "?fields=status,country,city,isp,message"
                        )
                        try:
                            resp = requests.get(url, timeout=4)
                            data = resp.json()
                            if data.get("status") == "success":
                                city = data.get("city", "Unknown")
                                country = data.get("country", "Unknown")
                                isp = data.get("isp", "Unknown")
                                result = (
                                    f"Geo: {city}, {country} | ISP: {isp}"
                                )
                            else:
                                result = "Geo: lookup failed"
                        except Exception:
                            result = "Geo: error during lookup"
                except Exception:
                    result = "Geo: error (invalid IP)"
            detail_win.after(
                0,
                lambda: geo_text.set(result)
            )

        threading.Thread(target=geo_worker, daemon=True).start()

    tk.Button(
        summary_frame,
        text="Lookup Info",
        command=lookup_info,
        bg=APP_THEME["accent"],
        fg=APP_THEME["panel_fg"],
        font=("Segoe UI", 10, "bold"),
        relief="flat",
        padx=10,
        pady=4
    ).pack(side="right", padx=10)

    # Anomaly reasons
    reasons_frame = tk.LabelFrame(
        detail_win,
        text="Anomaly Reasons (recent)",
        bg=APP_THEME["panel_bg"],
        fg=APP_THEME["fg"]
    )
    reasons_frame.pack(fill='x', padx=10, pady=6)

    reasons_text = tk.Text(
        reasons_frame,
        height=6,
        wrap='word',
        bg=APP_THEME["text_bg"],
        fg=APP_THEME["fg"],
        insertbackground=APP_THEME["fg"]
    )
    reasons_text.pack(fill='x', padx=6, pady=6)
    reasons_text.delete('1.0', 'end')
    for ts, rlist in list(anomaly_reasons.get(mac, [])):
        if rlist:
            reasons_text.insert('end', f"[{ts}] " + "; ".join(rlist) + "\n")
        else:
            reasons_text.insert('end', f"[{ts}] Anomaly\n")
    reasons_text.config(state='disabled')

    # Destination counts
    dest_frame = tk.LabelFrame(
        detail_win,
        text="Accessed Servers / Destinations",
        bg=APP_THEME["panel_bg"],
        fg=APP_THEME["fg"]
    )
    dest_frame.pack(fill='both', expand=False, padx=10, pady=6)

    dest_tree = ttk.Treeview(
        dest_frame,
        columns=("Destination", "Count"),
        show='headings',
        height=6
    )
    dest_tree.heading('Destination', text='Destination')
    dest_tree.heading('Count', text='Count')
    dest_tree.pack(fill='both', expand=True, padx=6, pady=6)

    dest_counts = defaultdict(int)
    for pkt in recent_packets.get(mac, []):
        target = pkt.get('dst')
        if target:
            dest_counts[target] += 1
    for d, c in sorted(dest_counts.items(), key=lambda x: -x[1]):
        dest_tree.insert('', 'end', values=[d, c])

    # Recent packets
    pkt_frame = tk.LabelFrame(
        detail_win,
        text="Recent Packets (latest first)",
        bg=APP_THEME["panel_bg"],
        fg=APP_THEME["fg"]
    )
    pkt_frame.pack(fill='both', expand=True, padx=10, pady=6)

    pkt_tree = ttk.Treeview(
        pkt_frame,
        columns=("Time", "Src IP", "Dst", "Proto", "Len"),
        show='headings'
    )
    for col in ("Time", "Src IP", "Dst", "Proto", "Len"):
        pkt_tree.heading(col, text=col)
        pkt_tree.column(col, width=140)
    pkt_tree.pack(fill='both', expand=True, padx=6, pady=6)

    for pkt in list(recent_packets.get(mac, []))[:200]:
        ts = time.strftime(
            '%H:%M:%S',
            time.localtime(pkt.get('time', time.time()))
        )
        pkt_tree.insert(
            '',
            'end',
            values=[
                ts,
                pkt.get('ip', 'N/A'),
                pkt.get('dst', 'N/A'),
                str(pkt.get('proto', 'N/A')),
                pkt.get('len', 0)
            ]
        )

    def save_device_activity():
        fname = filedialog.asksaveasfilename(defaultextension='.csv')
        if not fname:
            return
        with open(fname, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['time', 'src_ip', 'dst', 'proto', 'len'])
            for pkt in list(recent_packets.get(mac, [])):
                writer.writerow([
                    time.strftime(
                        '%Y-%m-%d %H:%M:%S',
                        time.localtime(pkt.get('time', time.time()))
                    ),
                    pkt.get('ip', ''),
                    pkt.get('dst', ''),
                    pkt.get('proto', ''),
                    pkt.get('len', 0)
                ])
        messagebox.showinfo('Saved', f'Device activity saved to {fname}')

    tk.Button(
        detail_win,
        text='Save Device Activity (CSV)',
        command=save_device_activity,
        bg=APP_THEME["accent2"],
        fg=APP_THEME["panel_fg"],
        font=("Segoe UI", 10, "bold"),
        relief="flat"
    ).pack(pady=6)

# -------------------- Table & control functions --------------------
def update_table(tree):
    ssid, _ = get_connected_ssid()
    tree.delete(*tree.get_children())
    for mac, ip in devices.items():
        proto_counts = protocols_by_device[mac]
        proto_list = ', '.join(
            f"{k}:{v}" for k, v in sorted(proto_counts.items())
        )
        dest_list = ', '.join(
            sorted(list(destinations_by_device[mac]))[:5]
        )
        vendor = vendor_info.get(mac, "Unknown")
        tree.insert(
            "",
            "end",
            values=[
                ip,
                mac,
                vendor,
                proto_list if proto_list else "N/A",
                dest_list if dest_list else "N/A",
                ssid
            ]
        )

def update_info_labels(labels):
    ssid, iface = get_connected_ssid()
    labels["ssid"].config(text=f"Wi-Fi SSID: {ssid}")
    labels["iface"].config(text=f"Interface: {iface}")
    labels["devices"].config(text=f"Connected Devices: {len(devices)}")

def start_sniffing(tree, info_labels):
    global sniff_thread, sniffing
    if not sniffing:
        sniffing = True
        sniff_thread = threading.Thread(
            target=lambda: sniff(
                prn=lambda pkt: packet_callback(pkt),
                store=False,
                stop_filter=lambda x: not sniffing
            ),
            daemon=True
        )
        sniff_thread.start()

def stop_sniffing():
    global sniffing
    sniffing = False

def export_to_csv():
    file = filedialog.asksaveasfilename(defaultextension=".csv")
    if file:
        with open(file, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                "IP Address", "MAC Address", "Vendor",
                "Protocols", "Accessed Servers", "Wi-Fi SSID"
            ])
            ssid, _ = get_connected_ssid()
            for mac, ip in devices.items():
                proto_list = ', '.join(
                    sorted(protocols_by_device[mac].keys())
                )
                dest_list = ', '.join(sorted(destinations_by_device[mac]))
                vendor = vendor_info.get(mac, "Unknown")
                writer.writerow([
                    ip,
                    mac,
                    vendor,
                    proto_list if proto_list else "N/A",
                    dest_list if dest_list else "N/A",
                    ssid
                ])

def reset_data(tree, info_labels, alerts_text):
    global devices, protocols_by_device, destinations_by_device
    global packet_counters, bytes_counters, feature_windows
    global baseline_collection, ids_model, alerts, recent_packets
    global anomaly_reasons, mac_vendor_cache, vendor_info

    devices.clear()
    protocols_by_device.clear()
    destinations_by_device.clear()
    packet_counters.clear()
    bytes_counters.clear()
    feature_windows.clear()
    baseline_collection = []
    alerts = []
    recent_packets.clear()
    anomaly_reasons.clear()
    mac_vendor_cache.clear()
    vendor_info.clear()

    if alerts_text:
        alerts_text.config(state='normal')
        alerts_text.delete('1.0', 'end')
        alerts_text.config(state='disabled')

    update_table(tree)
    update_info_labels(info_labels)

def launch_analytics_legacy():
    """Optional separate analytics window, if wanted."""
    analytics_window = tk.Toplevel()
    analytics_window.title("Data Visualization")
    analytics_window.geometry("700x500")
    analytics_window.configure(bg=APP_THEME["bg"])

    tk.Label(
        analytics_window,
        text="Network Traffic Analytics",
        font=("Arial", 16, "bold"),
        fg=APP_THEME["fg"],
        bg=APP_THEME["bg"]
    ).pack(pady=10)

    fig, ax = plt.subplots(figsize=(5, 4))
    canvas = FigureCanvasTkAgg(fig, master=analytics_window)
    canvas.get_tk_widget().pack(pady=20, fill="both", expand=True)

    def update_chart_periodically():
        proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "DNS": 0}
        for plist in protocols_by_device.values():
            for proto, cnt in plist.items():
                if proto in proto_counts:
                    proto_counts[proto] += cnt
        labels = [k for k, v in proto_counts.items() if v > 0]
        sizes = [v for v in proto_counts.values() if v > 0]
        if not labels:
            labels = ["No Data"]
            sizes = [1]
        ax.clear()
        total = sum(sizes)
        wedges, _ = ax.pie(sizes, startangle=90)
        legend_labels = []
        for lbl, size in zip(labels, sizes):
            pct = (size / total * 100.0) if total > 0 else 0.0
            legend_labels.append(f"{lbl} ({pct:.1f}%)")
        ax.legend(
            wedges,
            legend_labels,
            title="Protocols",
            loc="center left",
            bbox_to_anchor=(1, 0.5)
        )
        ax.set_title("Protocol Distribution")
        canvas.draw()
        analytics_window.after(1000, update_chart_periodically)

    update_chart_periodically()

def enable_ids(tree, alerts_text, baseline_seconds=WINDOW_SECONDS*BASELINE_PERIODS):
    global ids_enabled, collecting_baseline, baseline_collection
    if IsolationForest is None:
        messagebox.showerror("Missing", "Install scikit-learn & joblib")
        return
    ids_enabled = True
    load_ids_model_if_exists()
    if ids_model is None:
        collecting_baseline = True
        baseline_collection = []
        messagebox.showinfo(
            "IDS",
            f"Collecting baseline for {baseline_seconds} seconds."
        )
    else:
        messagebox.showinfo("IDS", "Loaded model. Detection enabled.")

def disable_ids():
    global ids_enabled
    ids_enabled = False
    messagebox.showinfo("IDS", "IDS disabled.")

# -------------------- Tooltip helper --------------------
class Tooltip:
    """Simple tooltip for widgets; uses a small Toplevel window."""
    def __init__(self, widget, text_getter, sidebar_state_getter):
        self.widget = widget
        self.text_getter = text_getter
        self.sidebar_state_getter = sidebar_state_getter
        self.tipwindow = None

    def show(self):
        try:
            if not self.sidebar_state_getter():
                return
            text = self.text_getter()
            if not text:
                return
            if self.tipwindow:
                return
            x = self.widget.winfo_rootx() + self.widget.winfo_width() + 8
            y = self.widget.winfo_rooty() + int(self.widget.winfo_height() / 2) - 12
            self.tipwindow = tw = tk.Toplevel(self.widget)
            tw.wm_overrideredirect(True)
            tw.wm_geometry("+%d+%d" % (x, y))

            dark = (
                APP_THEME.get("bg", "").lower()
                == DARK_THEME["bg"].lower()
            )
            if dark:
                bg = "#000000"
                fg = "#ffffff"
                alpha = 0.85
            else:
                bg = "#f0ece4"
                fg = "#3A3125"
                alpha = 0.95
            try:
                tw.attributes("-alpha", alpha)
            except Exception:
                pass

            lbl = tk.Label(
                tw,
                text=text,
                justify="left",
                background=bg,
                foreground=fg,
                bd=0,
                padx=8,
                pady=4,
                font=("Segoe UI", 10)
            )
            lbl.pack()
        except Exception:
            self.hide()

    def hide(self):
        try:
            if self.tipwindow:
                self.tipwindow.destroy()
                self.tipwindow = None
        except Exception:
            self.tipwindow = None

# -------------------- About frame --------------------
def make_about_frame(parent):
    frame = tk.Frame(parent, bg=APP_THEME["bg"])
    tk.Label(
        frame,
        text="About / Help",
        font=("Segoe UI", 16, "bold"),
        bg=APP_THEME["bg"],
        fg=APP_THEME["fg"]
    ).pack(anchor="w", padx=8, pady=8)
    text = (
        "NetScope — Network Sniffer & IDS\n"
        "Theme: Satin Black & Gold\n\n"
        "Features:\n"
        "- Real-time packet sniffing\n"
        "- Device profiling & vendor info\n"
        "- On-demand IP geolocation\n"
        "- Traffic analytics & anomaly detection\n"
        "- Collapsible sidebar & tooltips\n"
        "- Dark & Light classy themes\n\n"
        "Created by: You 😎"
    )
    tk.Label(
        frame,
        text=text,
        justify="left",
        bg=APP_THEME["bg"],
        fg=APP_THEME["fg"],
        font=("Segoe UI", 11)
    ).pack(anchor="w", padx=12, pady=4)
    return frame

# -------------------- Main GUI --------------------
def launch_gui():
    global main_device_table

    root = tk.Tk()
    root.title("NetScope — Network Packet Sniffer")
    root.geometry("1350x780")
    root.minsize(1000, 700)

    apply_theme_to_style(root)

    root.update_idletasks()
    w = max(800, root.winfo_width())
    h = max(600, root.winfo_height())
    bg_img = make_gradient_image(w, h) if PIL_AVAILABLE else None
    if bg_img:
        bg_label = tk.Label(root, image=bg_img)
        bg_label.image = bg_img
        bg_label.place(x=0, y=0, relwidth=1, relheight=1)
    else:
        root.configure(bg=APP_THEME["bg"])

    container = tk.Frame(root, bg=APP_THEME["bg"])
    container.pack(fill="both", expand=True)

    SIDEBAR_EXPANDED_WIDTH = 260
    SIDEBAR_COLLAPSED_WIDTH = 60
    sidebar_collapsed = {"state": False}

    sidebar = tk.Frame(
        container,
        width=SIDEBAR_EXPANDED_WIDTH,
        bg=APP_THEME["panel_bg"]
    )
    sidebar.pack(side="left", fill="y", padx=(20, 10), pady=20)
    sidebar.pack_propagate(False)

    # Top bar (logo + collapse)
    top_bar = tk.Frame(sidebar, bg=APP_THEME["panel_bg"])
    top_bar.pack(fill="x", pady=(8, 6))

    logo_full = tk.Label(
        top_bar,
        text="NetScope",
        font=("Segoe UI", 18, "bold"),
        bg=APP_THEME["panel_bg"],
        fg=APP_THEME["accent"]
    )
    logo_mini = tk.Label(
        top_bar,
        text="NS",
        font=("Segoe UI", 16, "bold"),
        bg=APP_THEME["panel_bg"],
        fg=APP_THEME["accent"]
    )
    logo_full.pack(side="left", padx=(12, 6))

    def is_sidebar_collapsed():
        return sidebar_collapsed["state"]

    nav_button_map = {}

    def toggle_sidebar():
        collapsed = sidebar_collapsed["state"]
        if not collapsed:
            sidebar.configure(width=SIDEBAR_COLLAPSED_WIDTH)
            logo_full.pack_forget()
            logo_mini.pack(side="left", padx=(8, 4))
            for key, (btn, meta, tooltip) in nav_button_map.items():
                icon = meta.get("icon", "?")
                btn.config(
                    text=icon,
                    font=("Segoe UI", 14),
                    anchor="center",
                    padx=0
                )
            sidebar_collapsed["state"] = True
        else:
            sidebar.configure(width=SIDEBAR_EXPANDED_WIDTH)
            logo_mini.pack_forget()
            logo_full.pack(side="left", padx=(12, 6))
            for key, (btn, meta, tooltip) in nav_button_map.items():
                btn.config(
                    text=meta.get("label", ""),
                    font=("Segoe UI", 11),
                    anchor="w",
                    padx=12
                )
                tooltip.hide()
            sidebar_collapsed["state"] = False

    collapse_btn = tk.Button(
        top_bar,
        text="☰",
        command=toggle_sidebar,
        relief="flat",
        bg=APP_THEME["panel_bg"],
        fg=APP_THEME["fg"],
        font=("Segoe UI", 12)
    )
    collapse_btn.pack(side="right", padx=(0, 6))

    # Sidebar badges
    badge_frame = tk.Frame(sidebar, bg=APP_THEME["panel_bg"])
    badge_frame.pack(pady=(8, 14))

    dev_badge = tk.Label(
        badge_frame,
        text="Devices: 0",
        bg=APP_THEME["card_bg"],
        fg=APP_THEME["fg"],
        padx=8,
        pady=4,
        font=("Segoe UI", 10, "bold"),
        relief="groove",
        bd=1
    )
    dev_badge.pack(side="left", padx=6)

    alert_badge = tk.Label(
        badge_frame,
        text="Alerts: 0",
        bg="#3A0000",
        fg="white",
        padx=8,
        pady=4,
        font=("Segoe UI", 10, "bold"),
        relief="groove",
        bd=1
    )
    alert_badge.pack(side="left")

    # Navigation items
    nav_items = [
        ("Dashboard", "dashboard", "🏠"),
        ("Alerts Center", "alerts", "🔔"),
        ("Traffic Analytics", "analytics", "📊"),
        ("Export", "export", "⤓"),
        ("Help / About", "about", "❓")
    ]

    def nav_btn_clicked(key):
        show_frame(key)
        for k, (btn, meta, tooltip) in nav_button_map.items():
            if k == key:
                btn.configure(
                    bg=APP_THEME["accent"],
                    fg=APP_THEME["panel_fg"]
                )
            else:
                btn.configure(
                    bg=APP_THEME["panel_bg"],
                    fg=APP_THEME["fg"]
                )

    for title, key, icon in nav_items:
        b = tk.Button(
            sidebar,
            text=title,
            anchor="w",
            relief="flat",
            bg=APP_THEME["panel_bg"],
            fg=APP_THEME["fg"],
            bd=0,
            padx=12,
            pady=10,
            font=("Segoe UI", 11),
            command=lambda k=key: nav_btn_clicked(k)
        )
        b.pack(fill="x", padx=12, pady=6)

        tt = Tooltip(b, lambda t=title: t, is_sidebar_collapsed)

        def make_enter(t_):
            return lambda e: t_.show()

        def make_leave(t_):
            return lambda e: t_.hide()

        b.bind("<Enter>", make_enter(tt))
        b.bind("<Leave>", make_leave(tt))

        nav_button_map[key] = (b, {"label": title, "icon": icon}, tt)

    # Theme switches
    def set_theme_and_reload(theme_dict, parent_root):
        global APP_THEME
        APP_THEME = theme_dict.copy()
        try:
            parent_root.destroy()
        except Exception:
            pass
        launch_gui()

    theme_frame = tk.Frame(sidebar, bg=APP_THEME["panel_bg"])
    theme_frame.pack(side="bottom", pady=18)

    tk.Label(
        theme_frame,
        text="Theme",
        bg=APP_THEME["panel_bg"],
        fg=APP_THEME["muted"],
        font=("Segoe UI", 9)
    ).pack()

    tk.Button(
        theme_frame,
        text="Dark (Satin Gold)",
        bg=DARK_THEME["panel_bg"],
        fg=DARK_THEME["accent"],
        relief="flat",
        command=lambda: set_theme_and_reload(DARK_THEME, root)
    ).pack(pady=4, padx=6, fill="x")

    tk.Button(
        theme_frame,
        text="Light (Warm Gray)",
        bg=LIGHT_THEME["panel_bg"],
        fg=LIGHT_THEME["accent"],
        relief="flat",
        command=lambda: set_theme_and_reload(LIGHT_THEME, root)
    ).pack(pady=4, padx=6, fill="x")

    # ---------------- Main content ----------------
    content = tk.Frame(container, bg=APP_THEME["bg"])
    content.pack(
        side="left",
        fill="both",
        expand=True,
        padx=(10, 20),
        pady=20
    )

    header = tk.Frame(content, bg=APP_THEME["bg"])
    header.pack(fill="x")

    header_title = tk.Label(
        header,
        text="Dashboard",
        font=("Segoe UI", 16, "bold"),
        bg=APP_THEME["bg"],
        fg=APP_THEME["fg"]
    )
    header_title.pack(side="left", padx=8)

    top_actions = tk.Frame(content, bg=APP_THEME["bg"])
    top_actions.pack(fill="x", pady=(0, 8), padx=8, anchor="e")

    frames = {}

    # Dashboard
    dash_frame = tk.Frame(content, bg=APP_THEME["bg"])
    frames["dashboard"] = dash_frame

    cards_row = tk.Frame(dash_frame, bg=APP_THEME["bg"])
    cards_row.pack(fill="x", padx=6, pady=8)

    def make_card(parent):
        frm = tk.Frame(
            parent,
            bg=APP_THEME["card_bg"],
            bd=1,
            relief="groove"
        )
        frm.pack_propagate(False)
        return frm

    card1 = make_card(cards_row)
    card1.config(width=220, height=80)
    card1.pack(side="left", padx=8)

    tk.Label(
        card1,
        text="Devices",
        bg=APP_THEME["card_bg"],
        fg=APP_THEME["muted"]
    ).pack(anchor="nw", padx=10, pady=6)
    devices_label = tk.Label(
        card1,
        text="0",
        font=("Segoe UI", 17, "bold"),
        bg=APP_THEME["card_bg"],
        fg=APP_THEME["fg"]
    )
    devices_label.pack(anchor="nw", padx=10)

    card2 = make_card(cards_row)
    card2.config(width=220, height=80)
    card2.pack(side="left", padx=8)
    tk.Label(
        card2,
        text="Total Packets",
        bg=APP_THEME["card_bg"],
        fg=APP_THEME["muted"]
    ).pack(anchor="nw", padx=10, pady=6)
    packets_label = tk.Label(
        card2,
        text="0",
        font=("Segoe UI", 16, "bold"),
        bg=APP_THEME["card_bg"],
        fg=APP_THEME["fg"]
    )
    packets_label.pack(anchor="nw", padx=10)

    card3 = make_card(cards_row)
    card3.config(width=220, height=80)
    card3.pack(side="left", padx=8)
    tk.Label(
        card3,
        text="Alerts",
        bg=APP_THEME["card_bg"],
        fg=APP_THEME["muted"]
    ).pack(anchor="nw", padx=10, pady=6)
    alerts_label = tk.Label(
        card3,
        text="0",
        font=("Segoe UI", 16, "bold"),
        bg=APP_THEME["card_bg"],
        fg="#ff6f6f"
    )
    alerts_label.pack(anchor="nw", padx=10)

    card4 = make_card(cards_row)
    card4.config(width=220, height=80)
    card4.pack(side="left", padx=8)
    tk.Label(
        card4,
        text="IDS Status",
        bg=APP_THEME["card_bg"],
        fg=APP_THEME["muted"]
    ).pack(anchor="nw", padx=10, pady=6)
    ids_status_label = tk.Label(
        card4,
        text="Disabled",
        font=("Segoe UI", 12, "bold"),
        bg=APP_THEME["card_bg"],
        fg=APP_THEME["fg"]
    )
    ids_status_label.pack(anchor="nw", padx=10)

    # Device table
    table_outer = tk.Frame(
        dash_frame,
        bg=APP_THEME["bg"],
        highlightbackground=APP_THEME.get("accent2", "#B38C2A"),
        highlightthickness=2
    )
    table_outer.pack(fill="both", expand=True, padx=6, pady=8)

    table_frame = tk.Frame(table_outer, bg=APP_THEME["bg"])
    table_frame.pack(fill="both", expand=True, padx=6, pady=6)

    columns = (
        "IP Address", "MAC Address", "Vendor",
        "Protocols", "Accessed Servers", "Wi-Fi SSID"
    )
    device_table = ttk.Treeview(
        table_frame,
        columns=columns,
        show="headings"
    )
    for col in columns:
        device_table.heading(col, text=col)
        device_table.column(col, anchor="center", width=200)
    device_table.pack(
        fill="both",
        expand=True,
        side="left",
        padx=(0, 6)
    )

    dev_scroll = ttk.Scrollbar(
        table_frame,
        orient="vertical",
        command=device_table.yview
    )
    dev_scroll.pack(side="right", fill="y")
    device_table.configure(yscroll=dev_scroll.set)

    main_device_table = device_table  # for vendor refresh after lookup

    def on_device_double(e):
        item = device_table.identify_row(e.y)
        if not item:
            return
        vals = device_table.item(item, 'values')
        if len(vals) >= 2:
            open_device_detail_window(vals[1])

    device_table.bind("<Double-1>", on_device_double)

    dash_frame.pack(fill="both", expand=True)

    # Alerts frame
    alerts_frame = tk.Frame(content, bg=APP_THEME["bg"])
    frames["alerts"] = alerts_frame

    tk.Label(
        alerts_frame,
        text="Alerts Center",
        font=("Segoe UI", 14, "bold"),
        bg=APP_THEME["bg"],
        fg=APP_THEME["fg"]
    ).pack(anchor="w", padx=8, pady=6)

    alerts_text_outer = tk.Frame(
        alerts_frame,
        bg=APP_THEME["bg"],
        highlightbackground=APP_THEME.get("accent2", "#B38C2A"),
        highlightthickness=2
    )
    alerts_text_outer.pack(fill="both", expand=True, padx=8, pady=6)

    alerts_text = tk.Text(
        alerts_text_outer,
        height=20,
        bg=APP_THEME["card_bg"],
        fg=APP_THEME["fg"],
        state="disabled"
    )
    alerts_text.pack(fill="both", expand=True, padx=4, pady=4)

    # Analytics frame
    analytics_frame = tk.Frame(content, bg=APP_THEME["bg"])
    frames["analytics"] = analytics_frame

    tk.Label(
        analytics_frame,
        text="Traffic Analytics",
        font=("Segoe UI", 14, "bold"),
        bg=APP_THEME["bg"],
        fg=APP_THEME["fg"]
    ).pack(anchor="w", padx=8, pady=6)

    fig, ax = plt.subplots(figsize=(5, 3))
    chart_canvas = FigureCanvasTkAgg(fig, master=analytics_frame)
    chart_canvas.get_tk_widget().pack(
        fill="both",
        expand=True,
        padx=8,
        pady=8
    )

    def refresh_chart():
        proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "DNS": 0}
        for plist in protocols_by_device.values():
            for proto, cnt in plist.items():
                if proto in proto_counts:
                    proto_counts[proto] += cnt
        labels = [k for k, v in proto_counts.items() if v > 0]
        sizes = [v for v in proto_counts.values() if v > 0]
        if not labels:
            labels = ["No Data"]
            sizes = [1]
        ax.clear()
        total = sum(sizes)
        wedges, _ = ax.pie(sizes, startangle=90)
        legend_labels = []
        for lbl, size in zip(labels, sizes):
            pct = (size / total * 100.0) if total > 0 else 0.0
            legend_labels.append(f"{lbl} ({pct:.1f}%)")
        ax.legend(
            wedges,
            legend_labels,
            title="Protocols",
            loc="center left",
            bbox_to_anchor=(1, 0.5)
        )
        ax.set_title("Protocol Distribution")
        chart_canvas.draw()
        analytics_frame.after(1500, refresh_chart)

    refresh_chart()

    # Export frame
    export_frame = tk.Frame(content, bg=APP_THEME["bg"])
    frames["export"] = export_frame

    tk.Label(
        export_frame,
        text="Export",
        font=("Segoe UI", 14, "bold"),
        bg=APP_THEME["bg"],
        fg=APP_THEME["fg"]
    ).pack(anchor="w", padx=8, pady=6)

    tk.Button(
        export_frame,
        text="Export CSV",
        bg=APP_THEME["accent2"],
        fg=APP_THEME["panel_fg"],
        command=export_to_csv,
        relief="flat",
        font=("Segoe UI", 10, "bold")
    ).pack(padx=8, pady=6, anchor="w")

    tk.Button(
        export_frame,
        text="Reset Data",
        bg="#ff9800",
        fg="white",
        command=lambda: reset_data(
            device_table,
            {"ssid": ssid_lbl, "iface": iface_lbl, "devices": devices_label},
            alerts_text
        ),
        relief="flat",
        font=("Segoe UI", 10, "bold")
    ).pack(padx=8, pady=6, anchor="w")

    # About frame
    about_frame = make_about_frame(content)
    frames["about"] = about_frame

    # Info bar
    info_bar = tk.Frame(content, bg=APP_THEME["bg"])
    info_bar.pack(fill="x", padx=8, pady=(4, 0))

    ssid_lbl = tk.Label(
        info_bar,
        text="Wi-Fi SSID: N/A",
        bg=APP_THEME["bg"],
        fg=APP_THEME["muted"],
        font=("Segoe UI", 10)
    )
    iface_lbl = tk.Label(
        info_bar,
        text="Interface: N/A",
        bg=APP_THEME["bg"],
        fg=APP_THEME["muted"],
        font=("Segoe UI", 10)
    )
    ssid_lbl.pack(side="left", padx=8)
    iface_lbl.pack(side="left", padx=14)

    info_labels = {
        "ssid": ssid_lbl,
        "iface": iface_lbl,
        "devices": devices_label
    }

    # --- Buttons (Start/Stop + IDS toggle + Export) ---
    def toggle_sniffing():
        global sniffing
        if not sniffing:
            start_sniffing(device_table, info_labels)
            start_btn.config(
                text="Stop",
                bg="#c0392b",
                fg="white"
            )
        else:
            stop_sniffing()
            start_btn.config(
                text="Start",
                bg=APP_THEME["accent"],
                fg=APP_THEME["panel_fg"]
            )

    start_btn = tk.Button(
        top_actions,
        text="Start",
        bg=APP_THEME["accent"],
        fg=APP_THEME["panel_fg"],
        command=toggle_sniffing,
        relief="flat",
        font=("Segoe UI", 10, "bold"),
        padx=10,
        pady=4
    )
    start_btn.pack(side="right", padx=6)

    export_btn_header = tk.Button(
        top_actions,
        text="Export CSV",
        bg=APP_THEME["accent2"],
        fg=APP_THEME["panel_fg"],
        command=export_to_csv,
        relief="flat",
        font=("Segoe UI", 10, "bold"),
        padx=10,
        pady=4
    )
    export_btn_header.pack(side="right", padx=6)

    def toggle_ids():
        global ids_enabled
        if not ids_enabled:
            enable_ids(device_table, alerts_text)
            ids_status_label.config(text="Enabled")
            ids_btn.config(
                text="Disable IDS",
                bg="#c0392b",
                fg="white"
            )
        else:
            disable_ids()
            ids_status_label.config(text="Disabled")
            ids_btn.config(
                text="Enable IDS",
                bg=APP_THEME["accent"],
                fg=APP_THEME["panel_fg"]
            )

    ids_btn = tk.Button(
        top_actions,
        text="Enable IDS",
        bg=APP_THEME["accent"],
        fg=APP_THEME["panel_fg"],
        command=toggle_ids,
        relief="flat",
        font=("Segoe UI", 10, "bold"),
        padx=10,
        pady=4
    )
    ids_btn.pack(side="right", padx=6)

    tk.Button(
        top_actions,
        text="Collect Baseline",
        bg=APP_THEME["accent2"],
        fg=APP_THEME["panel_fg"],
        command=lambda: messagebox.showinfo(
            "Baseline",
            "Baseline collection will begin during runtime (no UI change)."
        ),
        relief="flat",
        font=("Segoe UI", 10, "bold"),
        padx=10,
        pady=4
    ).pack(side="right", padx=6)

    # Frame switching
    def show_frame(key):
        header_title.config(
            text=key.capitalize() if key != "export" else "Export"
        )
        for k, f in frames.items():
            if k == key:
                f.pack(fill="both", expand=True)
            else:
                f.forget()
        if key == "dashboard":
            update_dashboard_cards()
        if key == "alerts":
            alerts_text.config(state="normal")
            alerts_text.delete("1.0", "end")
            for a in alerts[-500:]:
                alerts_text.insert("end", a + "\n")
            alerts_text.config(state="disabled")

    def update_dashboard_cards():
        try:
            devices_label.config(text=str(len(devices)))
            packets_label.config(text=str(sum(packet_counters.values())))
            alerts_label.config(text=str(len(alerts)))
            dev_badge.config(text=f"Devices: {len(devices)}")
            alert_badge.config(text=f"Alerts: {len(alerts)}")
        except Exception:
            pass

    def schedule_queue_processing(root_obj, tree, info_labels_obj, alerts_text_obj):
        process_queued_packets(tree, info_labels_obj, alerts_text_obj)
        update_dashboard_cards()
        root_obj.after(
            1000,
            schedule_queue_processing,
            root_obj,
            tree,
            info_labels_obj,
            alerts_text_obj
        )

    nav_btn_clicked("dashboard")
    schedule_queue_processing(root, device_table, info_labels, alerts_text)

    def on_close():
        try:
            stop_sniffing()
        except Exception:
            pass
        for _, (_, _, tt) in nav_button_map.items():
            try:
                tt.hide()
            except Exception:
                pass
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

# -------------------- ENTRY POINT --------------------
if __name__ == "__main__":
    APP_THEME = DARK_THEME.copy()  # start in luxury dark mode
    launch_gui()
