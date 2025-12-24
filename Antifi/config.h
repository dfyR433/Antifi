#ifndef CONFIG_H
#define CONFIG_H

// ===== Global Variables =====
String inputBuffer = "";
int led = 2;

// Custom SSIDs for targeted attack
const char* TARGETED_SSIDS[] = {
  // Corporate networks
  "CORP_WIFI", "OFFICE_SECURE", "BUSINESS_NET", "COMPANY_GUEST",
  "ENTERPRISE", "INTRANET", "VPN_ACCESS", "SERVER_ROOM",
  
  // Government/Military
  "GOV_SECURE", "MILITARY_NET", "POLICE_WIFI", "FIRE_DEPT",
  "EMERGENCY", "RESCUE_TEAM", "SECURITY_NET", "SURVEILLANCE",
  
  // Infrastructure
  "POWER_GRID", "WATER_PLANT", "TRAFFIC_CTRL", "AIRPORT_CTRL",
  "RAIL_CONTROL", "BRIDGE_MGMT", "TUNNEL_NET", "HARBOR_CTRL",
  
  // Financial
  "BANK_SECURE", "ATM_NETWORK", "TRADING_FLOOR", "STOCK_EXCHANGE",
  "CREDIT_UNION", "PAYMENT_NET", "TRANSACTION", "CLEARING_HOUSE"
};

// ===== Help Function =====
void showHelp() {
  Serial.println(F("\n"
                   "╔══════════════════════════════════════════════════════════════╗\n"
                   "║                         COMMAND HELP                         ║\n"
                   "╠══════════════════════════════════════════════════════════════╣\n"
                   "║ SCANNING:                                                    ║\n"
                   "║   scan -t ap                  Scan for WiFi networks         ║\n"
                   "║   scan -t sta                 Scan for WiFi clients          ║\n"
                   "║                                                              ║\n"
                   "║ ATTACKS:                                                     ║\n"
                   "║   deauth -s <src> -t <tgt> -c <ch> -p <pps>                  ║\n"
                   "║   beacon -s                                                  ║\n"
                   "║                                                              ║\n"
                   "║ CAPTIVE PORTAL:                                              ║\n"
                   "║   captive_portal <ssid> [pass] [type]                        ║\n"
                   "║     Types: wifi, google, microsoft, apple, facebook          ║\n"
                   "║   Examples:                                                  ║\n"
                   "║     captive_portal FreeWifi                    (Open WiFi)   ║\n"
                   "║     captive_portal FreeWifi password123        (WPA2 WiFi)   ║\n"
                   "║     captive_portal FreeWifi '' google          (Google)      ║\n"
                   "║     captive_portal FreeWifi '' microsoft       (Microsoft)   ║\n"
                   "║     captive_portal FreeWifi '' apple           (Apple)       ║\n"
                   "║     captive_portal FreeWifi '' facebook        (Facebook)    ║\n"
                   "║                                                              ║\n"
                   "║ MANAGEMENT:                                                  ║\n"
                   "║   stop                        Stop all attacks/portals       ║\n"
                   "║   status                      Show current status            ║\n"
                   "║   creds                       Show captured credentials      ║\n"
                   "║   clear                       Clear credentials              ║\n"
                   "║   help                        Show this help                 ║\n"
                   "║                                                              ║\n"
                   "╚══════════════════════════════════════════════════════════════╝\n"));
}

void showBanner() {
  Serial.println(F(
    "     █████████               █████     ███     ██████   ███ \n"
    "    ███░░░░░███             ░░███     ░░░     ███░░███ ░░░  \n"
    "   ░███    ░███  ████████   ███████   ████   ░███ ░░░  ████ \n"
    "   ░███████████ ░░███░░███ ░░░███░   ░░███  ███████   ░░███ \n"
    "   ░███░░░░░███  ░███ ░███   ░███     ░███ ░░░███░     ░███ \n"
    "   ░███    ░███  ░███ ░███   ░███ ███ ░███   ░███      ░███ \n"
    "   █████   █████ ████ █████  ░░█████  █████  █████     █████\n"
    "  ░░░░░   ░░░░░ ░░░░ ░░░░░    ░░░░░  ░░░░░  ░░░░░     ░░░░░ \n"
    "\n"
    "                           by: dfyR433\n"
    "                               v1.0\n"));
}

#endif
