import time

def detect_intrusion(known_devices, scanned_devices):
    """
    Kulinganisha devices za mwanzo (known_devices) na zilizopo sasa (scanned_devices).
    Inarudisha list ya alerts ikiwa kuna mashaka.
    """

    alerts = []

    # 1. Gunduwa devices mpya zisizojulikana
    for device in scanned_devices:
        if not any(d['mac'] == device['mac'] for d in known_devices):
            alerts.append(
                f"⚠️ New Device Detected (Intruder Suspect)! "
                f"IP: {device['ip']} | MAC: {device['mac']} | Hostname: {device['hostname']} | Time: {device['last_seen']}"
            )

    # 2. Gunduwa duplicate IPs (IP moja kwa devices tofauti)
    seen_ips = {}
    for device in scanned_devices:
        if device['ip'] in seen_ips and seen_ips[device['ip']] != device['mac']:
            alerts.append(
                f"🚨 Duplicate IP Detected! IP {device['ip']} is being used by "
                f"MAC {device['mac']} and {seen_ips[device['ip']]} | Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
            )
        else:
            seen_ips[device['ip']] = device['mac']

    # 3. Gunduwa MAC spoofing (MAC address inabadilika kwa IP ile ile)
    seen_macs = {}
    for device in scanned_devices:
        if device['mac'] in seen_macs and seen_macs[device['mac']] != device['ip']:
            alerts.append(
                f"🚨 Possible MAC Spoofing! MAC {device['mac']} is now on IP {device['ip']} "
                f"(previously {seen_macs[device['mac']]}) | Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
            )
        else:
            seen_macs[device['mac']] = device['ip']

    return alerts


# Test script
if __name__ == "__main__":
    # Known devices (mfano database ya mwanzo)
    known = [
        {"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "DESKTOP-XYZ", "last_seen": "2025-09-06 00:00:00"},
        {"ip": "192.168.1.3", "mac": "11:22:33:44:55:66", "hostname": "LAPTOP-ABC", "last_seen": "2025-09-06 00:00:00"},
    ]

    # Scan mpya (mfano kuna intruders na spoofing)
    scanned = [
        {"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "DESKTOP-XYZ", "last_seen": "2025-09-06 00:10:00"},
        {"ip": "192.168.1.4", "mac": "77:88:99:AA:BB:CC", "hostname": None, "last_seen": "2025-09-06 00:10:01"},  # intruder
        {"ip": "192.168.1.3", "mac": "77:88:99:AA:BB:CC", "hostname": None, "last_seen": "2025-09-06 00:10:02"},  # duplicate IP/MAC
    ]

    alerts = detect_intrusion(known, scanned)

    if alerts:
        print("\n🚨 ALERTS DETECTED:")
        for a in alerts:
            print(a)
    else:
        print("✅ No intruders detected.")
