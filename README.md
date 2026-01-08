# AntiFi - WiFi Pentesting Tool

<p align="center">
  <img src="img/Antifi.png" alt="Antifi" width="500"/>
</p>

## Overview
AntiFi is an ESP32-based WiFi security testing platform for **penetration testing and security education**.

## Features
- **Network scanning**
- **Beacon flood**
- **Deauthentication**
- **Captive portals**
- **Packet injection**

## Quick Start
Flash Pre-Built Binary
```bash
# Install esptool
pip install esptool

# Flash to ESP32 (change COM3 to your port & bin files paths)
esptool.py --chip esp32 --port /dev/ttyUSB0 --baud 921600 \
  --before default_reset --after hard_reset \
  erase_flash write_flash -z \
  0x1000 Antifi.bootloader.bin \
  0x8000 Antifi.partition-table.bin \
  0x10000 Antifi.bin
```

## Commands
Open Serial Monitor at **115200 baud**:
```bash
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
║   • Packet data must be in hex format (e.g., 08:00:27:AA:BB:CC)                  ║
║   • Sender names must be 'send' followed by a number (e.g., send1, send2)        ║
║   • Maximum packet size: 512 bytes                                               ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

## Support
- **Issues**: GitHub Issues page
- **Binaries**: Releases page
- **Source**: GitHub repository

## License
MIT License - For educational use only.

---

**Use responsibly. Only test networks you own.**
