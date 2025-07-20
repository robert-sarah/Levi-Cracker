import subprocess
import csv


def run_command(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except Exception:
        return ""


def set_channel(iface, channel):
    if channel == "Auto":
        return True
    try:
        subprocess.run(["sudo", "iwconfig", iface, "channel", str(channel)], check=True)
        return True
    except Exception:
        return False


def export_csv(filename, networks, clients):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["SSID", "BSSID", "Channel"])
        for bssid, (ssid, channel) in networks.items():
            writer.writerow([ssid, bssid, channel])
        writer.writerow([])
        writer.writerow(["Clients détectés"])
        writer.writerow(["Client MAC", "BSSID associé"])
        for client_mac, bssid in clients:
            writer.writerow([client_mac, bssid])
