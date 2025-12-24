# AntiFi - Advanced WiFi Security Research Platform

![AntiFi Banner](https://img.shields.io/badge/AntiFi-1.0-blue)
![ESP32](https://img.shields.io/badge/Platform-ESP32-green)
![Arduino](https://img.shields.io/badge/Built%20with-Arduino%20IDE-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Official Documentation v1.0

**AntiFi** is a comprehensive WiFi security research platform designed for the ESP32 microcontroller. This project enables security researchers, network administrators, and educational institutions to perform authorized wireless security assessments in controlled environments.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Hardware Requirements](#hardware-requirements)
- [Installation](#installation)
- [Usage Guide](#usage-guide)
- [Command Reference](#command-reference)
- [Module Documentation](#module-documentation)
- [Legal & Ethical Use](#legal--ethical-use)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## Overview

AntiFi is an open-source wireless security assessment tool built on the ESP32 platform. It provides a suite of tools for:
- Wireless network discovery and analysis
- Security vulnerability assessment
- Educational demonstrations of wireless security concepts
- Authorized penetration testing in controlled environments

**Version**: 1.0  
**Release Date**: 2025  
**Platform**: ESP32 (Arduino Framework)  
**License**: MIT

## Features

### Core Modules

#### 1. **Network Scanning Module**
- Passive network discovery
- Client device detection
- Signal strength analysis (RSSI)
- Hidden SSID detection
- WPS capability identification
- Vendor identification via MAC OUI

#### 2. **Security Assessment Module**
- Deauthentication frame transmission
- Beacon frame generation
- Network vulnerability analysis
- Encryption type detection (WEP, WPA, WPA2, WPA3)

#### 3. **Evil Portal Module**
- Captive portal implementation
- Multiple portal types (WiFi, Google, Microsoft, Apple, Facebook)
- Credential capture simulation (for educational purposes)
- Security awareness demonstrations

#### 4. **Performance Features**
- Multi-channel scanning
- Configurable transmission power
- Adjustable packet rates
- Memory-efficient design
- Real-time statistics

## Hardware Requirements

### Minimum Requirements
- **ESP32 Development Board** (ESP32-WROOM-32, ESP32-S2, ESP32-S3, or compatible)
  - Minimum: 4MB Flash, 520KB SRAM
  - Recommended: 8MB Flash, ESP32-S3 with PSRAM
- **USB Cable** (Type-C or Micro-USB depending on board)
- **Computer** with Arduino IDE installed

### Recommended Hardware
- **ESP32-S3-DevKitC-1** (8MB Flash, 8MB PSRAM)
- **External Antenna** (optional, for improved range)
- **Battery Pack** (optional, for portable use)
- **OLED Display** (optional, for standalone operation)

### Supported ESP32 Variants
- ESP32-WROOM-32
- ESP32-WROVER
- ESP32-S2
- ESP32-S3
- ESP32-C3
- Most ESP32 development boards with sufficient memory

## Installation

### Prerequisites

1. **Arduino IDE Installation**
   - Download Arduino IDE from [arduino.cc](https://www.arduino.cc/en/software)
   - Version 1.8.19 or 2.x recommended
   - Install on your operating system (Windows, macOS, or Linux)

2. **ESP32 Board Support**
   - Open Arduino IDE
   - Go to **File → Preferences**
   - In "Additional Board Manager URLs", add:
     ```
     https://espressif.github.io/arduino-esp32/package_esp32_index.json
     ```
   - Click OK

3. **Install ESP32 Boards**
   - Go to **Tools → Board → Boards Manager**
   - Search for "esp32"
   - Install "ESP32 by Espressif Systems"
   - Select version 2.0.10

### Project Setup

1. **Download AntiFi**
   - Download the project as a ZIP file
   - Extract to a folder named "AntiFi"

2. **Open Project in Arduino IDE**
   - Open Arduino IDE
   - Go to **File → Open**
   - Navigate to the AntiFi folder
   - Select `AntiFi.ino`

3. **Install Required Libraries**
   The following libraries are required:
   - **WiFi** (included with ESP32 core)
   - **WebServer** (included with ESP32 core)
   - **DNSServer** (included with ESP32 core)
   - **Preferences** (included with ESP32 core)

   To verify installation:
   - Go to **Sketch → Include Library → Manage Libraries**
   - Search for each library and ensure they're installed

4. **Board Configuration**
   - Go to **Tools → Board**
   - Select your ESP32 board (e.g., "ESP32 Dev Module")
   - Configure board settings:
     - **Upload Speed**: 921600
     - **Flash Frequency**: 80MHz
     - **Flash Mode**: QIO
     - **Partition Scheme**: Default 4MB with spiffs (1.2MB APP/1.5MB SPIFFS)
     - **Core Debug Level**: None

5. **Port Selection**
   - Connect your ESP32 via USB
   - Go to **Tools → Port**
   - Select the COM port for your ESP32
     - Windows: COMx
     - macOS: /dev/cu.usbserial-xxxx
     - Linux: /dev/ttyUSB0

### Compilation and Upload

1. **Verify Compilation**
   - Click the checkmark (✓) or go to **Sketch → Verify/Compile**
   - Ensure no errors appear in the output

2. **Upload to ESP32**
   - Click the right arrow (→) or go to **Sketch → Upload**
   - The code will compile and upload to your ESP32
   - You may need to press the BOOT button on some boards during upload

3. **Open Serial Monitor**
   - After upload, go to **Tools → Serial Monitor**
   - Set baud rate to **921600**
   - You should see the AntiFi banner and prompt

### Troubleshooting Installation

#### Common Issues

1. **Upload Fails**
   - Ensure correct board selection
   - Check USB cable (use data cable, not charge-only)
   - Press BOOT button during upload
   - Lower upload speed to 115200

2. **Compilation Errors**
   - Update ESP32 board package to latest version
   - Ensure all required libraries are installed
   - Check for duplicate library installations

3. **Serial Monitor Not Showing Output**
   - Verify baud rate is 921600
   - Check correct COM port
   - Press ESP32 reset button
   - Close and reopen Serial Monitor

## Usage Guide

### First-Time Setup

1. **Initial Connection**
   ```
   ============================================
          █████████               █████
         ███░░░░░███             ░░███
        ░███    ░███  ████████   ███████
        ░███████████ ░░███░░███ ░░░███░
        ░███░░░░░███  ░███ ░███   ░███
        ░███    ░███  ░███ ░███   ░███ ███
        █████   █████ ████ █████  ░░█████
       ░░░░░   ░░░░░ ░░░░ ░░░░░    ░░░░░
   
                           by: dfyR433
                               v1.0
   
   antifi> 
   ```

2. **Basic Commands**
   - Type `help` to see all available commands
   - Type `scan -t ap` to start network scanning
   - Type `stop` to halt any active operations

### Command Line Interface

AntiFi provides an interactive command-line interface via Serial Monitor. All commands follow this format:

```
antifi> [command] [options]
```

**Available Commands:**

| Command | Description | Example |
|---------|-------------|---------|
| `help` | Show help information | `help` |
| `scan -t ap` | Scan for access points | `scan -t ap` |
| `scan -t sta` | Scan for client devices | `scan -t sta` |
| `deauth` | Start deauthentication attack | See deauth section |
| `beacon -s` | Start beacon flooding | `beacon -s` |
| `captive_portal` | Start captive portal | See portal section |
| `stop` | Stop all operations | `stop` |
| `status` | Show current status | `status` |
| `creds` | Show captured credentials | `creds` |
| `clear` | Clear stored credentials | `clear` |

## Command Reference

### Scanning Commands

#### `scan -t ap`
Initiates access point scanning mode.

**Features:**
- Passive scanning of all WiFi channels (1-14)
- Detection of hidden SSIDs
- Signal strength measurement (RSSI)
- Encryption type identification
- WPS capability detection
- Vendor identification

**Output Format:**
```
============================================================================================================================================
Nr | SSID                           | Len | Orig | H | RSSI | Chan | Clients | Encryption               | WPS | Revealed | BSSID
============================================================================================================================================
1  | HomeNetwork                   |   8 |    8 |   |  -45 |    6 |       3 | WPA2_PSK                 |  No | -        | AA:BB:CC:DD:EE:FF
2  | [Hidden]                      |   8 |    0 | H |  -62 |   11 |       1 | WPA2_PSK                 | Yes | Yes      | 11:22:33:44:55:66
============================================================================================================================================
Active APs: 2 | Hidden: 1 | Revealed: 1 | Total Reveals: 1 | Channel: 6 | Time: 45 s
```

#### `scan -t sta`
Initiates client device scanning mode.

**Features:**
- Detection of connected clients
- Probe request monitoring
- Signal strength tracking
- Association state monitoring
- Manufacturer identification

**Output Format:**
```
==========================================================================================================
Nr | Client MAC           | RSSI | Chan | Packets | Probes | Associated AP       | Manufacturer
==========================================================================================================
1  | AA:BB:CC:DD:EE:FF   |  -52 |    6 |     124 |     12 | 11:22:33:44:55:66   | Apple Inc.
2  | 11:22:33:44:55:66   |  -68 |   11 |      89 |      5 | AA:BB:CC:DD:EE:FF   | Samsung Electronics
==========================================================================================================
Active Clients: 2 | Total Clients: 2 | Total Packets: 213
```

### Deauthentication Commands

#### `deauth -s <source> -t <target> -c <channel> -p <pps>`
Initiates a deauthentication attack.

**Parameters:**
- `-s <source>`: Source MAC address (AP BSSID)
- `-t <target>`: Target MAC address (client MAC)
- `-c <channel>`: WiFi channel (1-14)
- `-p <pps>`: Packets per second (1-1000)

**Example:**
```
antifi> deauth -s AA:BB:CC:DD:EE:FF -t 11:22:33:44:55:66 -c 6 -p 25
```

**Important Notes:**
- Only use on networks you own or have permission to test
- Higher PPS values may cause network disruption
- Monitor network impact carefully

### Beacon Flooding Commands

#### `beacon -s`
Initiates beacon flooding with default settings.

**Features:**
- Generates fake access point beacons
- Multiple transmission modes
- Configurable SSID generation
- Channel hopping capability
- Performance statistics

**Configuration Options (via code):**
```cpp
// Available in beacon.h/cpp
setTransmissionMode(MODE_NORMAL);  // MODE_NORMAL, MODE_AGGRESSIVE, MODE_STEALTH
setChannelStrategy(STRAT_HOPPING);  // STRAT_HOPPING, STRAT_FOCUSED, STRAT_SWEEP
setTxPower(20);                     // 1-20 dBm
setMaxPacketsPerSecond(1000);       // Rate limiting
```

### Captive Portal Commands

#### `captive_portal <ssid> [password] [type]`
Creates a captive portal for educational demonstrations.

**Parameters:**
- `<ssid>`: Network name to broadcast (1-32 characters)
- `[password]`: Optional password (8-63 characters, or '' for open)
- `[type]`: Portal type: `wifi`, `google`, `microsoft`, `apple`, `facebook`

**Examples:**
```
# Open WiFi portal
antifi> captive_portal FreeWiFi

# Secured WiFi portal
antifi> captive_portal SecureNet Password123

# Google login portal (open network)
antifi> captive_portal GoogleWiFi '' google

# Microsoft portal with password
antifi> captive_portal Office365 Pass123 microsoft
```

**Portal Types:**
1. **wifi**: Standard WiFi authentication portal
2. **google**: Google account login simulation
3. **microsoft**: Microsoft account login simulation
4. **apple**: Apple ID login simulation
5. **facebook**: Facebook login simulation

**Important:** These portals are for educational demonstrations only. Always obtain proper authorization before use.

### Management Commands

#### `stop`
Stops all active operations including:
- Scanning
- Deauthentication attacks
- Beacon flooding
- Captive portals

#### `status`
Displays current system status including:
- Active operations
- Memory usage
- Network information
- Performance statistics

#### `creds`
Displays credentials captured by captive portals.

#### `clear`
Clears all stored credentials and session data.

## Module Documentation

### 1. Scanning Module (`scan.h`/`scan.cpp`)

#### Architecture
The scanning module operates in promiscuous mode to capture all WiFi traffic. It includes:

**Data Structures:**
- `APInfo`: Access point information storage
- `ClientInfo`: Client device information storage
- `ScanState`: Scanning configuration and state

**Key Functions:**
- `scan_setup()`: Initialize scanning mode
- `scan_loop()`: Main scanning loop
- `promiscuousCallback()`: Packet processing callback
- `displayAPs()`: Display formatted AP information

**Configuration Options:**
```cpp
// Available configuration functions
setScanDuration(60000);        // Scan duration in milliseconds
setChannelHopInterval(300);    // Channel hop interval
setMinimumRSSI(-90);           // Minimum RSSI threshold
enableWPSDetection(true);      // Enable WPS detection
enableProbeSniffing(true);     // Enable probe request analysis
```

### 2. Deauthentication Module (`deauth.h`/`deauth.cpp`)

#### Architecture
Creates and transmits 802.11 deauthentication frames.

**Frame Structure:**
- 26-byte deauthentication frame
- Configurable source and destination addresses
- Adjustable transmission rate

**Key Functions:**
- `deauth_setup()`: Configure deauthentication parameters
- `deauth_loop()`: Transmission loop
- `stop_deauth()`: Stop transmission

**Technical Details:**
- Uses raw 802.11 frame transmission
- Bypasses ESP32 sanity checks for research purposes
- Configurable packet rate (1-100 PPS)

### 3. Beacon Flooding Module (`beacon.h`/`beacon.cpp`)

#### Architecture
Generates and transmits beacon frames to create fake access points.

**Features:**
- Multiple transmission modes
- Custom SSID generation
- Channel strategies
- Performance optimization

**Configuration Structure:**
```cpp
struct BeaconConfig {
    uint16_t num_ssids;              // Number of SSIDs to generate
    uint8_t tx_power;                // Transmission power (1-20 dBm)
    uint16_t dwell_ms;               // Channel dwell time
    bool enable_rsn;                 // Enable RSN (WPA2) elements
    bool realistic_ssids;            // Generate realistic SSIDs
    // ... additional configuration options
};
```

**Transmission Modes:**
1. **MODE_NORMAL**: Balanced performance
2. **MODE_AGGRESSIVE**: Higher packet rate
3. **MODE_STEALTH**: Lower packet rate, random delays
4. **MODE_TURBO**: Maximum packet rate
5. **MODE_EXPLOSIVE**: Extreme performance (use with caution)

### 4. Captive Portal Module (`captive_portal.h`/`captive_portal.cpp`)

#### Architecture
Implements captive portal functionality with multiple authentication page types.

**Components:**
- DNS server for captive portal redirection
- Web server for serving authentication pages
- Credential storage with encryption
- Session management

**Security Features:**
- Encrypted credential storage using Preferences
- Session timeout (5 minutes)
- Client IP tracking
- User-agent logging

**HTML Templates:**
- Professional, responsive design
- Brand-accurate login pages
- Mobile-compatible layouts
- CSS styling for realism

## Legal & Ethical Use

### Authorized Use Only
AntiFi is intended for:
1. **Security Research**: Authorized testing of your own networks
2. **Education**: Classroom demonstrations with proper supervision
3. **Professional Assessment**: Penetration testing with written authorization
4. **Personal Learning**: Testing on your personal, isolated lab equipment

### Prohibited Uses
DO NOT use AntiFi for:
- Unauthorized network access
- Disrupting public or private networks
- Surveillance without consent
- Any illegal activities
- Testing networks you don't own or have explicit permission to test

### Legal Compliance
Users must comply with:
- **Computer Fraud and Abuse Act (CFAA)**
- **Wireless Telegraphy Act**
- **General Data Protection Regulation (GDPR)**
- **Local and national computer crime laws**
- **Terms of Service of network providers**

### Best Practices
1. **Always obtain written permission** before testing
2. **Use in isolated lab environments** when learning
3. **Document all testing activities**
4. **Report vulnerabilities responsibly** to affected parties
5. **Stay within authorized scope** of testing

## Troubleshooting

### Common Issues

#### 1. Compilation Errors
**Problem**: Errors during compilation in Arduino IDE
**Solutions**:
- Update ESP32 board package to latest version
- Ensure all required libraries are installed
- Check for conflicting library versions
- Verify board selection matches your hardware

#### 2. Upload Failures
**Problem**: Code won't upload to ESP32
**Solutions**:
- Use a quality USB data cable (not charge-only)
- Press BOOT button during upload if required
- Lower upload speed to 115200
- Check driver installation (CP210x or CH340)

#### 3. Serial Connection Issues
**Problem**: No output in Serial Monitor
**Solutions**:
- Verify baud rate is 921600
- Check correct COM port selection
- Press ESP32 reset button
- Try different USB port

#### 4. Memory Issues
**Problem**: Device crashes or behaves unpredictably
**Solutions**:
- Reduce SSID cache size in beacon.h
- Lower packet transmission rates
- Enable power saving features
- Use ESP32 with PSRAM for better performance

#### 5. WiFi Performance Issues
**Problem**: Poor range or packet loss
**Solutions**:
- Ensure antenna is properly connected
- Increase transmission power (setTxPower())
- Use external antenna for better range
- Avoid physical obstructions

### Performance Optimization

#### For Scanning:
```cpp
// Reduce memory usage
setScanDuration(30000);  // 30 seconds
setMinimumRSSI(-80);     // Ignore weak signals
enableProbeSniffing(false);  // Disable if not needed
```

#### For Beacon Flooding:
```cpp
// Balance performance and stability
setTransmissionMode(MODE_NORMAL);
setMaxPacketsPerSecond(500);
setTxPower(17);  // 17dBm for good balance
```

### Debugging Tips

1. **Enable Serial Debugging**
   ```cpp
   // Add to setup()
   Serial.setDebugOutput(true);
   ```

2. **Monitor Memory Usage**
   ```cpp
   Serial.printf("Free Heap: %d\n", ESP.getFreeHeap());
   ```

3. **Check WiFi Status**
   ```cpp
   Serial.printf("WiFi Status: %d\n", WiFi.status());
   ```

## Contributing

AntiFi welcomes contributions from the security research community.

### Contribution Guidelines

1. **Fork the Repository**
   ```bash
   git clone https://github.com/yourusername/AntiFi.git
   cd AntiFi
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/improvement-name
   ```

3. **Make Your Changes**
   - Follow existing code style
   - Add comments for complex logic
   - Include error handling
   - Update documentation

4. **Test Thoroughly**
   - Test on different ESP32 variants
   - Verify no memory leaks
   - Ensure backward compatibility

5. **Submit Pull Request**
   - Clear description of changes
   - Reference any related issues
   - Update README if needed

### Code Standards

- **Naming**: Use descriptive names (camelCase for variables/functions)
- **Comments**: Document complex algorithms and security considerations
- **Error Handling**: Always check return values and handle errors gracefully
- **Memory Management**: Free allocated memory, avoid fragmentation
- **Security**: Never hardcode credentials, use secure defaults

### Areas for Contribution

1. **New Features**
   - Additional portal types
   - Enhanced scanning capabilities
   - New attack modules (for research)
   - GUI interface

2. **Improvements**
   - Performance optimization
   - Memory efficiency
   - Code cleanup and refactoring
   - Documentation enhancement

3. **Bug Fixes**
   - Stability improvements
   - Compatibility fixes
   - Security vulnerabilities

## License

### MIT License

Copyright (c) 2024 AntiFi Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

### Third-Party Licenses

This project includes or depends on:
- **ESP32 Arduino Core**: MIT License
- **Arduino Framework**: LGPL
- **HTML/CSS Templates**: Created for this project, MIT licensed

## Disclaimer

### Important Legal Notice

**THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY.**

The authors and contributors of AntiFi are not responsible for:
1. Any misuse or illegal activities conducted with this software
2. Damages caused by unauthorized use of this software
3. Legal consequences resulting from improper use
4. Violations of terms of service or laws

### User Responsibility

By using AntiFi, you agree to:
1. Use the software only for legitimate, authorized purposes
2. Comply with all applicable laws and regulations
3. Obtain proper authorization before testing any network
4. Accept full responsibility for your actions
5. Use the software at your own risk

### No Warranty

This software is provided "as is" without any warranty of any kind, either expressed or implied, including but not limited to the implied warranties of merchantability and fitness for a particular purpose.

### Security Researchers

If you discover vulnerabilities using AntiFi:
1. **Responsible Disclosure**: Report to affected parties privately
2. **Proof of Concept**: Provide clear, reproducible steps
3. **Timeframe**: Allow reasonable time for remediation
4. **Public Disclosure**: Only after fixes are available or agreed timeframe

### Educational Use

For classroom or training use:
1. **Supervision**: Always have qualified instructor supervision
2. **Isolation**: Use isolated lab networks
3. **Consent**: Obtain consent from all participants
4. **Documentation**: Keep records of all training activities

---

## Support

For issues, questions, or contributions:
- **GitHub Issues**: Report bugs or request features
- **Documentation**: Refer to this README and source code comments
- **Community**: Join security research forums for discussion

**Remember**: With great power comes great responsibility. Use AntiFi ethically, legally, and responsibly.

---
*AntiFi v1.0 - Advanced WiFi Security Research Platform*  
*Built with Arduino IDE for ESP32*  
*MIT License - Use Responsibly*
