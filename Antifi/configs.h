#ifndef CONFIG_H
#define CONFIG_H

#include <functional>
#include <vector>

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
const char* version = "v1.4";

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
                   "║   inject -i <hex> -ch <ch> -pps <rate> -m <max|non>                              ║\n"
                   "║     -i: Packet data in hex (space-separated bytes)                               ║\n"
                   "║     -ch: Channel 1-14                                                            ║\n"
                   "║     -pps: Packets per second                                                     ║\n"
                   "║     -m: Max packets or 'non' for unlimited                                       ║\n"
                   "║   list_injectors                List all active packet injectors                 ║\n"
                   "║                                                                                  ║\n"
                   "║ BEACON ATTACK:                                                                   ║\n"
                   "║   beacon -s                    Start beacon spam attack                          ║\n"
                   "║                                                                                  ║\n"
                   "║ DEAUTH ATTACK:                                                                   ║\n"
                   "║   deauth -s <src mac> -t <tgt mac> -c <channel> -p <pps>                         ║\n"
                   "║                                                                                  ║\n"
                   "║ CAPTIVE PORTAL:                                                                  ║\n"
                   "║   captive_portal <ssid> <pass> <type>                                            ║\n"
                   "║     Types: wifi, google, microsoft, apple, facebook                              ║\n"
                   "║                                                                                  ║\n"
                   "║ FILESYSTEM / SD:                                                                 ║\n"
                   "║   sd_info                      Show SD card information (type/size/usage)        ║\n"
                   "║   sd_ls [opts] [path]          List files (opts: -h human, -r recursive,         ║\n"
                   "║                                 -e <ext> filter by extension)                    ║\n"
                   "║   sd_tree [opts] [path]        Show ASCII tree (opts: -h human, -d <depth>)      ║\n"
                   "║   sd_rm [-r] [-y] <path>       Remove file or directory.                         ║\n"
                   "║                                 -r : recursive delete (requires -y to execute)   ║\n"
                   "║                                 -y : confirm & perform deletes when -r used      ║\n"
                   "║   sd_rmdir <path>              Remove empty directory only                       ║\n"
                   "║                                                                                  ║\n"
                   "║ POWER FILES (utility):                                                           ║\n"
                   "║   sd_du [-h] [path]            Disk usage (recursive). -h for human readable     ║\n"
                   "║   sd_cat <file>                Print small text file to serial (capped)          ║\n"
                   "║   sd_mv [-f] <src> <dst>       Move/rename (use -f to overwrite)                 ║\n"
                   "║   sd_cp [-f] <src> <dst>       Copy file (use -f to overwrite)                   ║\n"
                   "║   sd_head [-n <lines>] <file>  Print first N lines (default 10)                  ║\n"
                   "║   sd_tail [-n <lines>] <file>  Print last N lines (default 10), safe cap         ║\n"
                   "║   sd_find [opts] <substr|ext>  Find files by substring or -e <ext> (recursive)   ║\n"
                   "║                                                                                  ║\n"
                   "║ MANAGEMENT:                                                                      ║\n"
                   "║   stop                        Stop all attacks/portals/scans                     ║\n"
                   "║   stop -p <name|all>          Stop specific injector or all injectors            ║\n"
                   "║   creds                       Show captured credentials                          ║\n"
                   "║   clear                       Clear all credentials and injectors                ║\n"
                   "║   version / v                 Show firmware version                              ║\n"
                   "║   help / ?                    Show help menu                                     ║\n"
                   "║                                                                                  ║\n"
                   "║ NOTES:                                                                           ║\n"
                   "║   • Use '' for empty password (two single quotes)                                ║\n"
                   "║   • Packet data must be in hex format (e.g., 08 00 27 AA BB CC)                  ║\n"
                   "║   • Injectors names must be 'inject' followed by a number (e.g., inject0)        ║\n"
                   "║   • Sniffer output is pcapng format                                              ║\n"
                   "║   • Maximum packet size: 2346 bytes                                              ║\n"
                   "║   • SD paths are absolute (start with /)                                         ║\n"
                   "║   • sd_rm refuses '/' and is dry-run by default for recursive operations         ║\n"
                   "║   • sd_cat and sd_head/tail cap output to avoid blocking serial for long perids  ║\n"
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