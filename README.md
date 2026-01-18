# AntiFi – Wi-Fi Pentesting Tool

<p align="center">
  <img src="img/Antifi.png" alt="AntiFi Logo" width="400"/>
</p>

## Overview

**AntiFi** is an ESP32-based Wi-Fi penetration testing and security research platform that provides **full low-level control** for **penetration testers, learners, and researchers**.

---

## Features

* **Wi‑Fi Monitoring** (Passive 802.11 frame sniffing with PCAPNG output)
* **Network Scanning** (APs & clients)
* **Beacon Flood Attacks** (1.3k SSIDs)
* **Deauthentication Attacks** (Adjustable packet rate & channel)
* **Captive Portals** (Multiple portal templates)
* **Raw Packet Injection** (Send custom 802.11 frames)
* **Serial-based Command Interface** (CLI over UART)

---

## Quick Start

### Flash Pre-Built Binary

```bash
pip install esptool

esptool \
  --chip esp32 \
  --port COM3 \
  --baud 921600 \
  --before default-reset \
  --after hard-reset \
  erase-flash

esptool \
  --chip esp32 \
  --port COM3 \
  --baud 921600 \
  write-flash -z \
  0x1000  Antifi.esp32.bootloader.bin \
  0x8000  Antifi.esp32.partitions.bin \
  0x10000 Antifi.esp32.bin
```

---

## Commands

Open a serial monitor at **921600 baud**:

```text
╔══════════════════════════════════════════════════════════════════════════════════╗
║                               ANTIFI COMMAND HELP                                ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║ SNIFFING:                                                                        ║
║   sniff -c <ch || all>        Sniff WiFi on all channels or specific channel     ║
║                                                                                  ║
║ SCANNING:                                                                        ║
║   scan -t <ap || sta>         Scan for WiFi networks or clients                  ║
║                                                                                  ║
║ PACKET INJECTION:                                                                ║
║   inject<i> -i <hex> -ch <ch> -pps <rate> -m <max|non>                           ║
║     Example: inject0 -i 00 00 00 -ch 6 -pps 100 -m 1000                          ║
║     -i: Packet data in hex (space-separated bytes)                               ║
║     -ch: Channel 1-13                                                            ║
║     -pps: Packets per second                                                     ║
║     -m: Max packets or 'non' for unlimited                                       ║
║   list_injectors                List all active packet injectors                 ║
║                                                                                  ║
║ BEACON ATTACK:                                                                   ║
║   beacon -s                  Start beacon spam attack                            ║
║                                                                                  ║
║ DEAUTH ATTACK:                                                                   ║
║   deauth -s <src mac> -t <tgt mac> -c <channel> -p <packets per second>          ║
║                                                                                  ║
║ CAPTIVE PORTAL:                                                                  ║
║   captive_portal -s <ssid> -p <pass> -t <type> -m <mac> -e <encryption>          ║
║     Types: wifi, google, microsoft, apple, facebook                              ║
║                                                                                  ║
║ MANAGEMENT:                                                                      ║
║   stop                        Stop all attacks/portals/scans                     ║
║   stop -p <name|all>          Stop specific sender or all senders                ║
║   status                      Show current system status                         ║
║   creds                       Show captured credentials                          ║
║   clear                       Clear all credentials and senders                  ║
║   version / v                 Show firmware version                              ║
║   help / ?                    Show help menu                                     ║
║                                                                                  ║
║ NOTES:                                                                           ║
║   • Use '' for empty password (two single quotes)                                ║
║   • Packet data must be in hex format (e.g., 08 00 27 AA BB CC)                  ║
║   • Sender names must be 'send' followed by a number (e.g., send1, send2)        ║
║   • Sniffer output is a pcapng format                                            ║
║   • Maximum packet size: 512 bytes                                               ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

---

## Support

* **Issues**: GitHub Issues
* **Binaries**: GitHub Releases
* **Source Code**: GitHub Repository

---

## License

**MIT License**
For **educational and authorized security testing only**.
