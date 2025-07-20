import sys
import re
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QLabel,
    QMessageBox, QComboBox, QTextEdit, QTabWidget, QFileDialog
)
from PyQt5.QtCore import Qt
from wifi_scanner import WifiScannerThread
from utils import run_command, set_channel, export_csv


class WifiCrackerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WiFi Cracker PyQt5 - Kali Linux")
        self.resize(900, 600)

        self.current_monitor_iface = None
        self.networks = {}  # bssid -> (ssid, channel)
        self.clients = set()  # (client_mac, bssid)

        self.layout = QVBoxLayout()
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)

        self.tab_scan = QWidget()
        self.tabs.addTab(self.tab_scan, "Scan WiFi")
        self.init_tab_scan()

        self.tab_attack = QWidget()
        self.tabs.addTab(self.tab_attack, "Attaques WiFi")
        self.init_tab_attack()

        self.tab_crack = QWidget()
        self.tabs.addTab(self.tab_crack, "Cracking")
        self.init_tab_crack()

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.layout.addWidget(QLabel("Logs / Statuts"))
        self.layout.addWidget(self.log)

        self.setLayout(self.layout)
        self.scanner_thread = None

        self.refresh_ifaces()

    def refresh_ifaces(self):
        output = run_command(["iw", "dev"])
        ifaces = re.findall(r'Interface\s+(\w+)', output)
        self.combo_ifaces.clear()
        self.combo_ifaces.addItems(ifaces)
        self.current_monitor_iface = None
        self.label_iface.setText("Interface WiFi (mode monitor) : Aucun")
        self.log.append(f"Interfaces WiFi détectées : {', '.join(ifaces)}")

    def enable_monitor_mode(self):
        iface = self.combo_ifaces.currentText()
        if not iface:
            QMessageBox.warning(self, "Erreur", "Sélectionne une interface WiFi")
            return
        # Stop any existing monitor mode interface on wlan0mon
        run_command(["sudo", "airmon-ng", "stop", "wlan0mon"])
        output = run_command(["sudo", "airmon-ng", "start", iface])
        mon_iface = None
        for line in output.splitlines():
            if "monitor mode enabled on" in line:
                mon_iface = line.split()[-1]
                break
        if mon_iface:
            self.log.append(f"Mode monitor activé sur {mon_iface}")
            self.current_monitor_iface = mon_iface
            self.label_iface.setText(f"Interface WiFi (mode monitor) : {mon_iface}")
        else:
            QMessageBox.warning(self, "Erreur", "Impossible d'activer le mode monitor")

    def start_scan(self):
        if not self.current_monitor_iface:
            QMessageBox.warning(self, "Erreur", "Active d'abord le mode monitor")
            return
        if self.scanner_thread and self.scanner_thread.isRunning():
            QMessageBox.warning(self, "Attention", "Scan déjà en cours")
            return

        # Forcer canal si manuel
        canal = self.combo_channel.currentText()
        if canal != "Auto":
            success = set_channel(self.current_monitor_iface, canal)
            if success:
                self.log.append(f"Canal forcé à {canal}")
            else:
                self.log.append(f"Erreur lors du changement de canal")

        self.networks.clear()
        self.clients.clear()
        self.table.setRowCount(0)
        self.log.append("Début du scan WiFi (30 secondes)...")
        self.scanner_thread = WifiScannerThread(self.current_monitor_iface)
        self.scanner_thread.new_network.connect(self.add_network)
        self.scanner_thread.new_client.connect(self.add_client)
        self.scanner_thread.start()

    def add_network(self, ssid, bssid, channel):
        if bssid in self.networks:
            return
        self.networks[bssid] = (ssid, channel)
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(ssid))
        self.table.setItem(row, 1, QTableWidgetItem(bssid))
        self.table.setItem(row, 2, QTableWidgetItem(str(channel)))
        self.log.append(f"Réseau trouvé : {ssid} ({bssid}) Canal {channel}")
        self.refresh_targets()

    def add_client(self, client_mac, bssid):
        if (client_mac, bssid) in self.clients:
            return
        self.clients.add((client_mac, bssid))
        self.log.append(f"Client détecté : {client_mac} connecté à {bssid}")
        self.refresh_clients()

    def refresh_targets(self):
        self.combo_targets.clear()
        self.combo_targets.addItems(self.networks.keys())

    def refresh_clients(self):
        self.list_clients.clear()
        for client_mac, bssid in self.clients:
            self.list_clients.addItem(f"{client_mac} (connecté à {bssid})")

    def init_tab_scan(self):
        layout = QVBoxLayout()

        hbox = QHBoxLayout()
        self.combo_ifaces = QComboBox()
        self.btn_refresh_ifaces = QPushButton("Rafraîchir Interfaces")
        self.btn_enable_monitor = QPushButton("Activer Mode Monitor")
        hbox.addWidget(QLabel("Interface WiFi :"))
        hbox.addWidget(self.combo_ifaces)
        hbox.addWidget(self.btn_refresh_ifaces)
        hbox.addWidget(self.btn_enable_monitor)
        layout.addLayout(hbox)

        self.label_iface = QLabel("Interface WiFi (mode monitor) : Aucun")
        layout.addWidget(self.label_iface)

        hbox2 = QHBoxLayout()
        self.combo_channel = QComboBox()
        self.combo_channel.addItem("Auto")
        for i in range(1, 15):
            self.combo_channel.addItem(str(i))
        self.btn_start_scan = QPushButton("Démarrer Scan")
        hbox2.addWidget(QLabel("Canal :"))
        hbox2.addWidget(self.combo_channel)
        hbox2.addWidget(self.btn_start_scan)
        layout.addLayout(hbox2)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["SSID", "BSSID", "Canal"])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        self.tab_scan.setLayout(layout)

        self.btn_refresh_ifaces.clicked.connect(self.refresh_ifaces)
        self.btn_enable_monitor.clicked.connect(self.enable_monitor_mode)
        self.btn_start_scan.clicked.connect(self.start_scan)

    def init_tab_attack(self):
        layout = QVBoxLayout()

        hbox = QHBoxLayout()
        self.combo_targets = QComboBox()
        self.btn_start_deauth = QPushButton("Lancer Déauth (Tout le réseau)")
        hbox.addWidget(QLabel("Réseau ciblé (BSSID) :"))
        hbox.addWidget(self.combo_targets)
        hbox.addWidget(self.btn_start_deauth)
        layout.addLayout(hbox)

        layout.addWidget(QLabel("Clients connectés détectés :"))
        from PyQt5.QtWidgets import QListWidget
        self.list_clients = QListWidget()
        layout.addWidget(self.list_clients)

        self.tab_attack.setLayout(layout)

        self.btn_start_deauth.clicked.connect(self.deauth_network)

    def deauth_network(self):
        bssid = self.combo_targets.currentText()
        if not bssid:
            QMessageBox.warning(self, "Erreur", "Sélectionne un réseau cible")
            return
        # Ici tu pourrais lancer aireplay-ng en déauth sur le bssid
        self.log.append(f"Lancement de la déauthentification sur {bssid} (tout le réseau)")
        # Exemple (remplacer par ta commande adaptée) :
        # subprocess.run(['sudo', 'aireplay-ng', '--deauth', '10', '-a', bssid, self.current_monitor_iface])
        QMessageBox.information(self, "Info", f"Simulation déauth sur {bssid} (commande à implémenter)")

    def init_tab_crack(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Cracking Handshake (à implémenter)"))
        self.tab_crack.setLayout(layout)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WifiCrackerApp()
    window.show()
    sys.exit(app.exec_())
