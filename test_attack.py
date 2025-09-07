from scapy.all import IP, TCP, send
import time

# Lengo: LAN IP yako ya ndani
target_ip = "192.168.88.11"   # hakikisha hii ni IP yako ya ndani sahihi
target_port = 80              # port ya kawaida (HTTP)

print("🚀 Kuanza kutuma test packets...")

# 1. Jaribu Port Scan Style (kutuma packets kwa ports tofauti haraka)
for port in range(75, 85):  # ports 75 mpaka 85
    pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
    send(pkt, verbose=0)
    print(f"[TEST] Packet sent to {target_ip}:{port}")
    time.sleep(0.2)  # kidogo delay ili kuonekana kama scanning

# 2. Jaribu SYN Flood Style (kutuma SYN nyingi haraka)
for i in range(25):  # tuma zaidi ya threshold ya 20
    pkt = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
    send(pkt, verbose=0)

print("✅ Test packets zimetumwa (port scan + SYN flood style)")
