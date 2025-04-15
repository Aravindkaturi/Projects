import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import matplotlib.pyplot as plt
import threading
import time


class LiveTrafficAnalyzer:
    def __init__(self):
        self.packets = []
        self.running = False

    def process_packet(self, packet):
        if IP in packet:
            proto = "Other"
            if TCP in packet:
                proto = "TCP"
            elif UDP in packet:
                proto = "UDP"
            self.packets.append({
                "src": packet[IP].src,
                "dst": packet[IP].dst,
                "proto": proto,
                "len": len(packet),
                "timestamp": time.time()
            })

    def start_sniffing(self, duration=15):
        self.packets = []
        self.running = True
        sniff(prn=self.process_packet, timeout=duration, store=False)
        self.running = False

    def analyze_packets(self):
        df = pd.DataFrame(self.packets)
        alerts = []
        if df.empty:
            return df, ["⚠️ No packets captured. Try again."]

        suspicious_ips = df['src'].value_counts()
        for ip, count in suspicious_ips.items():
            if count > 10:
                alerts.append(f"🚨 [ALERT] High traffic from {ip}: {count} packets")

        return df, alerts


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Real-Time Network Traffic Analyzer")
        self.root.geometry("800x700")
        self.root.configure(bg="#1e1e2f")

        self.analyzer = LiveTrafficAnalyzer()

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", padding=6, relief="flat", background="#3e3e5b", foreground="white")
        style.configure("TLabel", background="#1e1e2f", foreground="white", font=("Segoe UI", 11))
        style.configure("TFrame", background="#1e1e2f")

        self.frame = ttk.Frame(self.root, padding="20")
        self.frame.pack(expand=True, fill=tk.BOTH)

        self.project_name = ttk.Label(self.frame, text="🛡️ ZKP Warriors", font=("Segoe UI", 20, "bold"), foreground="#00d4ff")
        self.project_name.pack(pady=(0, 5))

        self.title_label = ttk.Label(self.frame, text="🛰️ Real-Time Network Traffic Analyzer", font=("Segoe UI", 16, "bold"))
        self.title_label.pack(pady=(0, 10))


        self.description = ttk.Label(self.frame, text=(
            "📡 This tool captures live network packets on your machine for 15 seconds.\n"
            "It analyzes them to identify abnormal behavior (e.g., too many packets from the same IP).\n"
            "You can also view a chart of protocol usage (TCP/UDP/etc)."
        ), font=("Segoe UI", 10), justify="left")
        self.description.pack(pady=5)

        self.status_label = ttk.Label(self.frame, text="Status: 🟡 Idle", font=("Segoe UI", 10, "italic"))
        self.status_label.pack(pady=2)

        self.counter_label = ttk.Label(self.frame, text="Packets Captured: 0", font=("Segoe UI", 10))
        self.counter_label.pack(pady=2)

        self.start_btn = ttk.Button(self.frame, text="▶️ Start Sniffing", command=self.start_sniffing)
        self.start_btn.pack(pady=10)

        self.text_area = tk.Text(self.frame, width=95, height=18, bg="#2e2e3f", fg="white",
                                 insertbackground="white", font=("Consolas", 10))
        self.text_area.pack(pady=10)

        self.chart_btn = ttk.Button(self.frame, text="📊 Show Protocol Chart", command=self.show_chart)
        self.chart_btn.pack(pady=5)
        self.chart_btn['state'] = 'disabled'

        self.footer_label = ttk.Label(
            self.frame,
            text="💡 Tip: You may need to run this app as administrator for packet sniffing to work.\n"
                 "Use responsibly. This tool is for educational and diagnostic use only.",
            font=("Segoe UI", 9), foreground="#aaa"
        )
        self.footer_label.pack(pady=10)

        self.df = None

    def start_sniffing(self):
        self.text_area.delete(1.0, tk.END)
        self.status_label.config(text="Status: 🟠 Sniffing...")
        self.counter_label.config(text="Packets Captured: 0")
        self.start_btn['state'] = 'disabled'
        self.chart_btn['state'] = 'disabled'

        def sniff_thread():
            self.analyzer.start_sniffing(duration=15)
            self.df, alerts = self.analyzer.analyze_packets()
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, "\n".join(alerts) if alerts else "✅ No threats detected.")
            self.status_label.config(text="Status: 🟢 Done")
            self.counter_label.config(text=f"Packets Captured: {len(self.analyzer.packets)}")
            self.start_btn['state'] = 'normal'
            self.chart_btn['state'] = 'normal'

        threading.Thread(target=sniff_thread).start()

    def show_chart(self):
        if self.df is not None and not self.df.empty:
            proto_counts = self.df['proto'].value_counts()
            proto_counts.plot(kind='bar', title="Protocol Distribution", color='skyblue')
            plt.xlabel("Protocol")
            plt.ylabel("Packet Count")
            plt.tight_layout()
            plt.show()


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
