from scapy.all import sniff, TCP, IP, Raw
import time
from collections import defaultdict
from utils.logger import log_alert  # kwa ajili ya kuhifadhi alerts

# -----------------------------
# Global Counters & Settings
# -----------------------------
packet_counter = defaultdict(int)       # kuhesabu packets kwa IP
syn_counter = defaultdict(int)          # kuhesabu SYN floods
connection_counter = defaultdict(list)  # kuhesabu timestamps kwa IP:port

TIME_WINDOW = 10       # muda wa kuhesabu (sekunde)
THRESHOLD = 5          # idadi ya packets kabla alert
SYN_THRESHOLD = 20     # threshold ya SYN flood

# -----------------------------
# Kazi kuu ya kugundua packets
# -----------------------------
def detect_packet(pkt):
    alerts = []

    # 1. Kagua kama packet ina layer ya IP
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # Hesabu packets kutoka IP hii
        packet_counter[src_ip] += 1

        # 2. Gundua Port Scanning (kwa kutumia time window)
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            key = f"{src_ip}:{dport}"

            now = time.time()
            connection_counter[key].append(now)

            # futa timestamps za zamani zisizo ndani ya window
            connection_counter[key] = [t for t in connection_counter[key] if now - t <= TIME_WINDOW]

            # kagua kama idadi imevuka threshold
            if len(connection_counter[key]) > THRESHOLD:
                alerts.append(
                    f"[ALERT] Possible Port Scan Detected from {src_ip} on port {dport} | "
                    f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                )

        # 3. Gundua SYN Flood
        if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            syn_counter[src_ip] += 1
            if syn_counter[src_ip] > SYN_THRESHOLD:
                alerts.append(
                    f"[ALERT] Possible SYN Flood Attack from {src_ip} to {dst_ip} | "
                    f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                )

        # 4. Angalia payload (keywords hatari)
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode(errors="ignore")
            suspicious_keywords = ["password", "login", "bank", "credit", "pin"]

            for keyword in suspicious_keywords:
                if keyword in payload.lower():
                    alerts.append(
                        f"[ALERT] Suspicious Payload Detected from {src_ip} -> {dst_ip} | "
                        f"Keyword: {keyword} | Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                    )

    # Mwisho: print & log alerts kama zipo
    for alert in alerts:
        print(alert)
        log_alert(alert)  # sasa inahifadhi alert kwenye file pia


# -----------------------------
# Function ya kuanza sniffer
# -----------------------------
def start_sniffer(interface="Ethernet"):
    """
    Kuanza kusniff traffic kwenye interface husika.
    Tumia jina kamili la interface kutoka show_interfaces().
    """
    print(f"[*] Starting packet sniffer on interface {interface}...")
    sniff(iface=interface, prn=detect_packet, store=False)


# -----------------------------
# Main Entry Point
# -----------------------------
if __name__ == "__main__":
    # Anza sniffer kwa Ethernet interface (ndiyo yenye IP yako 192.168.88.11)
    start_sniffer(interface="Ethernet")
