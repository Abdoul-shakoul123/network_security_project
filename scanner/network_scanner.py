from scapy.all import ARP, Ether, srp
import socket
import time

def scan_network(target_ip):
    """
    Kuscan network kwa kutumia ARP requests.
    Inarudisha list ya devices zilizounganishwa.
    target_ip mfano: "192.168.1.1/24"
    """
    try:
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=3, verbose=0)[0]

        devices = []
        for sent, received in result:
            devices.append({
                'ip': received.psrc,
                'mac': received.hwsrc,
                'hostname': resolve_hostname(received.psrc),
                'last_seen': time.strftime("%Y-%m-%d %H:%M:%S")
            })

        return devices

    except Exception as e:
        print(f"❌ Error scanning network: {e}")
        return []


def resolve_hostname(ip_address):
    """
    Kutafuta jina la kifaa (hostname) kulingana na IP.
    Ikiwa haipatikani, inarudisha None.
    """
    try:
        hostname = socket.gethostbyaddr(ip_address)
        return hostname[0]
    except socket.herror:
        return None


# Test script
if __name__ == "__main__":
    target_range = "192.168.1.1/24"  # badilisha range ya LAN yako
    print("🔍 Advanced Network Scan in progress...")
    devices = scan_network(target_range)

    if devices:
        print(f"✅ {len(devices)} Devices Found:\n")
        for dev in devices:
            print(
                f"IP: {dev['ip']} | MAC: {dev['mac']} | Hostname: {dev['hostname']} | Last Seen: {dev['last_seen']}"
            )
    else:
        print("⚠️ Hakuna device imepatikana kwenye network.")
