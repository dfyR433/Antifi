#ifndef CONFIG_H
#define CONFIG_H

extern "C" int ieee80211_raw_frame_sanity_check(int32_t, int32_t, int32_t) {
  return 0;
}

// Global instances and variables
injectorManager injectorManager;
int currentChannel = 1;
String inputBuffer = "";
const int led = 15;
const char* version = "v1.0";

typedef struct {
  String ssid;
  String mac;
  String password;
  String portalType;
  String encryption;
  bool verbose;
} PortalConfig;

PortalConfig config;

void showHelp() {
  Serial.println(F("\n"
                   "╔══════════════════════════════════════════════════════════════════════════════════╗\n"
                   "║                               ANTIFI COMMAND HELP                                ║\n"
                   "╠══════════════════════════════════════════════════════════════════════════════════╣\n"
                   "║ SCANNING:                                                                        ║\n"
                   "║   scan -t ap                  Scan for WiFi networks (Access Points)             ║\n"
                   "║   scan -t sta                 Scan for WiFi clients (Stations)                   ║\n"
                   "║                                                                                  ║\n"
                   "║ PACKET INJECTION:                                                                ║\n"
                   "║   inject<i> -i <hex> -ch <ch> -pps <rate> -m <max|non>                           ║\n"
                   "║     Example: inject0 -i 00 00 00 -ch 6 -pps 100 -m 1000                          ║\n"
                   "║     -i: Packet data in hex (space-separated bytes)                               ║\n"
                   "║     -ch: Channel 1-13                                                            ║\n"
                   "║     -pps: Packets per second                                                     ║\n"
                   "║     -m: Max packets or 'non' for unlimited                                       ║\n"
                   "║   list_injectors                List all active packet senders                   ║\n"
                   "║                                                                                  ║\n"
                   "║ BEACON ATTACK:                                                                   ║\n"
                   "║   beacon -s                  Start beacon spam attack                            ║\n"
                   "║                                                                                  ║\n"
                   "║ DEAUTH ATTACK:                                                                   ║\n"
                   "║   deauth -s <src mac> -t <tgt mac> -c <channel> -p <packets per second>          ║\n"
                   "║                                                                                  ║\n"
                   "║ CAPTIVE PORTAL:                                                                  ║\n"
                   "║   captive_portal -s <ssid> -p <pass> -t <type> -m <mac> -e <encryption>          ║\n"
                   "║     Types: wifi, google, microsoft, apple, facebook                              ║\n"
                   "║                                                                                  ║\n"
                   "║ MANAGEMENT:                                                                      ║\n"
                   "║   stop                        Stop all attacks/portals/scans                     ║\n"
                   "║   stop -p <name|all>          Stop specific sender or all senders                ║\n"
                   "║   status                      Show current system status                         ║\n"
                   "║   creds                       Show captured credentials                          ║\n"
                   "║   clear                       Clear all credentials and senders                  ║\n"
                   "║   help / ?                    Show this help menu                                ║\n"
                   "║                                                                                  ║\n"
                   "║ NOTES:                                                                           ║\n"
                   "║   • Use '' for empty password (two single quotes)                                ║\n"
                   "║   • Packet data must be in hex format (e.g., 08 00 27 AA BB CC)                  ║\n"
                   "║   • Sender names must be 'send' followed by a number (e.g., send1, send2)        ║\n"
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