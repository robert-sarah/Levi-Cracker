# WiFi Cracker PyQt5 Kali Linux

Outil puissant de pentesting WiFi avec interface graphique PyQt5, conçu pour Kali Linux.

## Fonctionnalités

- Scan WiFi avec détection auto des canaux
- Gestion manuelle des canaux (option "Auto")
- Détection des clients connectés aux réseaux
- Attaques déauthentification ciblées (client ou réseau)
- Capture handshake avec choix canal automatique
- Craquage handshake avec wordlists intégrées ou personnalisées
- Export CSV des réseaux et clients détectés
- Interface multi-onglets intuitive avec logs en temps réel

## Installation

```bash
sudo apt update
sudo apt install python3-pyqt5 python3-pip aircrack-ng wireless-tools iw
pip3 install scapy
