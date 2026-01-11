# AntiFi – Wi-Fi Pentesting Tool

<p align="center">
  <img src="img/Antifi.png" alt="AntiFi Logo" width="400"/>
</p>

## Overview

**AntiFi** is an ESP32-based Wi-Fi penetration testing and security research platform that provides **full low-level control** for **penetration testers, learners, and researchers**.

---

## Features

* **Network scanning** (APs & clients)
* **Beacon flood attacks** (1.3k SSIDs)
* **Deauthentication attacks** (Adjustable packet rate & channel)
* **Captive portals** (Multiple portal templates)
* **Raw packet injection** (Send custom 802.11 frames)
* **Serial-based command interface** (CLI over UART)

---

## Quick Start

### Flash Pre-Built Binary

```bash
# Install esptool
pip install esptool

# Flash to ESP32 (change port and file paths as needed)
esptool.py --chip esp32 --port /dev/ttyUSB0 --baud 921600 \
  --before default_reset --after hard_reset \
  erase_flash write_flash -z \
  0x1000 Antifi.bootloader.bin \
  0x8000 Antifi.partition-table.bin \
  0x10000 Antifi.bin
```

---

## Commands

Open a serial monitor at **115200 baud**:

```text
╔══════════════════════════════════════════════════════════════════════════════════╗
║                               ANTIFI COMMAND HELP                                ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║ SCANNING:                                                                        ║
║   scan -t ap                  Scan for WiFi networks (Access Points)             ║
║   scan -t sta                 Scan for WiFi clients (Stations)                   ║
║                                                                                  ║
║ PACKET INJECTION:                                                                ║
║   send<i> -i <hex> -ch <ch> -pps <rate> -m <max|non>                             ║
║     Example: send1 -i 00:00:00 -ch 6 -pps 100 -m 1000                            ║
║     -i: Packet data in hex (space-separated bytes)                               ║
║     -ch: Channel 1-13                                                            ║
║     -pps: Packets per second                                                     ║
║     -m: Max packets or 'non' for unlimited                                       ║
║   listsenders                List all active packet senders                      ║
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
║   help / ?                    Show this help menu                                ║
║                                                                                  ║
║ NOTES:                                                                           ║
║   • Use '' for empty password (two single quotes)                                ║
║   • Packet data must be in hex format (e.g., ff ff ff ff ff ff)                  ║
║   • Sender names must be 'send' followed by a number (e.g., send1, send2)        ║
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
