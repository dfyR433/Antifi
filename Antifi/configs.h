#ifndef CONFIG_H
#define CONFIG_H

extern "C" int ieee80211_raw_frame_sanity_check(int32_t, int32_t, int32_t) {
  return 0;
}

#define SERIAL_BAUD 921600

// SD Card pins
#define SD_MISO_PIN 19
#define SD_MOSI_PIN 23
#define SD_SCK_PIN 18
#define SD_CS_PIN 5

// Global instances and variables
WiFiSniffer sniffer;
injectorManager injectorManager;
int currentChannel = 1;
String inputBuffer = "";
const int led = 2;
const char* version = "v1.3";

void showHelp() {
  Serial.println(F("\n"
                   "╔══════════════════════════════════════════════════════════════════════════════════╗\n"
                   "║                               ANTIFI COMMAND HELP                                ║\n"
                   "╠══════════════════════════════════════════════════════════════════════════════════╣\n"
                   "║ SNIFFING:                                                                        ║\n"
                   "║   sniff -c <ch || all>        Sniff WiFi on all channels or specific channel     ║\n"
                   "║                                                                                  ║\n"
                   "║ SCANNING:                                                                        ║\n"
                   "║   scan -t <ap || sta>         Scan for WiFi networks or clients                  ║\n"
                   "║                                                                                  ║\n"
                   "║ PACKET INJECTION:                                                                ║\n"
                   "║   inject<i> -i <hex> -ch <ch> -pps <rate> -m <max|non>                           ║\n"
                   "║     -i: Packet data in hex (space-separated bytes)                               ║\n"
                   "║     -ch: Channel 1-14                                                            ║\n"
                   "║     -pps: Packets per second                                                     ║\n"
                   "║     -m: Max packets or 'non' for unlimited                                       ║\n"
                   "║   list_injectors                List all active packet injectors                 ║\n"
                   "║                                                                                  ║\n"
                   "║ BEACON ATTACK:                                                                   ║\n"
                   "║   beacon -s                  Start beacon spam attack                            ║\n"
                   "║                                                                                  ║\n"
                   "║ DEAUTH ATTACK:                                                                   ║\n"
                   "║   deauth -s <src mac> -t <tgt mac> -c <channel> -p <packets per second>          ║\n"
                   "║                                                                                  ║\n"
                   "║ CAPTIVE PORTAL:                                                                  ║\n"
                   "║   captive_portal <ssid> <pass> <type>                                            ║\n"
                   "║     Types: wifi, google, microsoft, apple, facebook                              ║\n"
                   "║                                                                                  ║\n"
                   "║ MANAGEMENT:                                                                      ║\n"
                   "║   stop                        Stop all attacks/portals/scans                     ║\n"
                   "║   stop -p <name|all>          Stop specific sender or all senders                ║\n"
                   "║   creds                       Show captured credentials                          ║\n"
                   "║   clear                       Clear all credentials and senders                  ║\n"
                   "║   version / v                 Show firmware version                              ║\n"
                   "║   help / ?                    Show help menu                                     ║\n"
                   "║                                                                                  ║\n"
                   "║ NOTES:                                                                           ║\n"
                   "║   • Use '' for empty password (two single quotes)                                ║\n"
                   "║   • Packet data must be in hex format (e.g., 08 00 27 AA BB CC)                  ║\n"
                   "║   • Sender names must be 'send' followed by a number (e.g., send1, send2)        ║\n"
                   "║   • Sniffer output is a pcapng format                                            ║\n"
                   "║   • Maximum packet size: 512 bytes                                               ║\n"
                   "║                                                                                  ║\n"
                   "╚══════════════════════════════════════════════════════════════════════════════════╝\n"));
}

void showBanner() {
  Serial.println(F(
    "\n"
    "     █████████               █████     ███     ██████   ███ \n"
    "    ███░░░░░███             ░░███     ░░░     ███░░███ ░░░  \n"
    "   ░███    ░███  ████████   ███████   ████   ░███ ░░░  ████ \n"
    "   ░███████████ ░░███░░███ ░░░███░   ░░███  ███████   ░░███ \n"
    "   ░███░░░░░███  ░███ ░███   ░███     ░███ ░░░███░     ░███ \n"
    "   ░███    ░███  ░███ ░███   ░███ ███ ░███   ░███      ░███ \n"
    "   █████   █████ ████ █████  ░░█████  █████  █████     █████\n"
    "  ░░░░░   ░░░░░ ░░░░ ░░░░░    ░░░░░  ░░░░░  ░░░░░     ░░░░░ \n"
    "\n"));
}

#endif