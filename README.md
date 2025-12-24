# AntiFi - WiFi Security Research Tool

![Version](https://img.shields.io/badge/Version-1.0-blue)
![Platform](https://img.shields.io/badge/Platform-ESP32-green)
![License](https://img.shields.io/badge/License-MIT-orange)
![Binary](https://img.shields.io/badge/Pre--compiled-Binary_Available-green)

## Overview

AntiFi is an educational ESP32-based tool for authorized WiFi security research and penetration testing. Built with Arduino IDE, this project demonstrates wireless security concepts in controlled environments.

## Features

- **Network Scanning**: Passive discovery of access points and clients
- **Security Testing**: Deauthentication and beacon flooding demonstrations
- **Captive Portal**: Educational portal simulations
- **Multiple Portal Types**: WiFi, Google, Microsoft, Apple, Facebook
- **Performance Controls**: Adjustable transmission rates and power

## Installation Options

### Option 1: Binary Installation (Quick Start)

#### Step 1: Download Required Tools
1. **Download Python** (if not installed):
   - Windows: [python.org/downloads](https://python.org/downloads)
   - macOS: `brew install python`
   - Linux: `sudo apt-get install python3 python3-pip`

2. **Install esptool.py**:
   ```bash
   pip install esptool
   ```

3. **Download AntiFi Binary**:
   - Visit [Releases Page](https://github.com/dfyR433/AntiFi/releases)
   - Download the latest `.bin` file (e.g., `antifi-v1.0.bin`)

#### Step 2: Prepare Your ESP32
1. Connect ESP32 to your computer via USB
2. Identify the COM port:
   - Windows: Check Device Manager → Ports (COM & LPT)
   - macOS/Linux: Run `ls /dev/tty.*` or `ls /dev/ttyUSB*`

#### Step 3: Flash the Binary
**Windows (Command Prompt/PowerShell):**
```bash
# Example for COM3
esptool.py --chip esp32 --port COM3 write_flash 0x1000 antifi-v1.0.bin
```

**macOS/Linux:**
```bash
# Example for /dev/ttyUSB0
esptool.py --chip esp32 --port /dev/ttyUSB0 write_flash 0x1000 antifi-v1.0.bin
```

**Complete Flash Command (All Partitions):**
```bash
esptool.py --chip esp32 --port COM3 --baud 921600 \
  --before default_reset --after hard_reset write_flash \
  -z --flash_mode dio --flash_freq 80m --flash_size 4MB \
  0x1000 antifi-v1.0.bin
```

#### Step 4: Verify Installation
1. Open Serial Monitor (any terminal program)
2. Set baud rate to **921600**
3. Press ESP32 reset button
4. You should see:
   ```
   AntiFi v1.0
   Ready...
   antifi> 
   ```

#### Troubleshooting Binary Installation
1. **Permission Denied** (Linux/macOS):
   ```bash
   sudo chmod 666 /dev/ttyUSB0  # Linux
   sudo chmod 666 /dev/tty.usbserial*  # macOS
   ```

2. **Port Not Found**:
   - Check USB cable (use data cable, not charge-only)
   - Try different USB port
   - Install proper drivers (CP210x or CH340)

3. **Flash Error**:
   - Put ESP32 in download mode (hold BOOT button, press RESET, release RESET, then release BOOT)
   - Lower baud rate: add `--baud 115200` to esptool command

### Option 2: Source Compilation (Advanced)

#### Step 1: Install Arduino IDE
1. Download Arduino IDE 1.8.19+ from [arduino.cc](https://arduino.cc)
2. Install for your operating system

#### Step 2: Add ESP32 Support
1. Open Arduino IDE
2. Go to **File → Preferences**
3. Add to Additional Board Manager URLs:
   ```
   https://espressif.github.io/arduino-esp32/package_esp32_index.json
   ```
4. Go to **Tools → Board → Boards Manager**
5. Search for "esp32" and install "ESP32 by Espressif Systems"

#### Step 3: Download Source Code
```bash
# Clone repository
git clone https://github.com/yourusername/AntiFi.git
cd AntiFi

# Or download ZIP from GitHub
# Extract to a folder named "AntiFi"
```

#### Step 4: Compile and Upload
1. Open `AntiFi.ino` in Arduino IDE
2. Select your board:
   - **Tools → Board → ESP32 Arduino → ESP32 Dev Module**
3. Configure settings:
   - Upload Speed: 921600
   - Flash Frequency: 80MHz
   - Flash Mode: QIO
   - Partition Scheme: Default 4MB with spiffs
4. Select correct COM port
5. Click **Upload** (→ button)

## Basic Usage

After installation (binary or compiled), open Serial Monitor at **921600 baud**:

```bash
antifi> help                     # Show command list
antifi> scan -t ap               # Scan for networks
antifi> scan -t sta              # Scan for clients
antifi> beacon -s                # Start beacon flooding
antifi> captive_portal FreeWiFi  # Start educational portal
antifi> stop                     # Stop all operations
```

## Support & Resources

- **Issues**: [GitHub Issues](https://github.com/dfyR433/AntiFi/issues)
- **Binary Downloads**: [Releases Page](https://github.com/dfyR433/AntiFi/releases)
- **Source Code**: [GitHub Repository](https://github.com/dfyR433/AntiFi)
- **Documentation**: See `docs/` folder in repository

## License

MIT License - See [LICENSE](LICENSE) file for details.
