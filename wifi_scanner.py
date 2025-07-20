from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp
from PyQt5.QtCore import QThread, pyqtSignal


class WifiScannerThread(QThread):
    new_network = pyqtSignal(str, str, int)  # ssid, bssid, channel
    new_client = pyqtSignal(str, str)  # client_mac, associated_bssid

    def __init__(self, iface, target_bssid=None):
        super().__init__()
        self.iface = iface
        self.running = True
        self.networks = set()
        self.clients = set()
        self.target_bssid = target_bssid  # filtre clients associés à ce BSSID si défini

    def run(self):
        def packet_handler(pkt):
            if not self.running:
                return False
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                ssid = pkt[Dot11Elt].info.decode(errors="ignore")
                bssid = pkt[Dot11].addr2
                channel = None
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 3:
                        channel = elt.info[0]
                        break
                    elt = elt.payload.getlayer(Dot11Elt)
                if channel is None:
                    channel = -1
                if bssid not in self.networks:
                    self.networks.add(bssid)
                    self.new_network.emit(ssid, bssid, channel)
            elif pkt.haslayer(Dot11) and pkt.addr1 and pkt.addr2:
                client_mac = pkt.addr1
                ap_mac = pkt.addr2
                if self.target_bssid and ap_mac.lower() == self.target_bssid.lower():
                    if client_mac not in self.clients:
                        self.clients.add(client_mac)
                        self.new_client.emit(client_mac, ap_mac)
        sniff(iface=self.iface, prn=packet_handler, timeout=30)

    def stop(self):
        self.running = False
