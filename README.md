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

## Basic Commands
Open Serial Monitor at **115200 baud**:
```bash
antifi> help                    # Show all commands
antifi> scan -t ap              # Find WiFi networks
antifi> scan -t sta             # Find connected devices
antifi> beacon -s               # Start beacon flood demo
antifi> stop                    # Stop everything
```

## Support
- **Issues**: GitHub Issues page
- **Binaries**: Releases page
- **Source**: GitHub repository

## License
MIT License - For educational use only.

---

**Use responsibly. Only test networks you own.**
