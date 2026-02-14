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

  if (packetLen > 2346) {
    Serial.println("Error: Packet too large (max 2346 bytes)");
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
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

    String injectorName;
    uint8_t packetData[MAX_PACKET_LEN];
    uint16_t packetLen = 0;
    uint8_t channel = 1;
    uint32_t pps = 0;
    uint32_t maxPackets = 0;

    if (!parseInjectCommand(cmd, injectorName,
                            packetData, packetLen,
                            channel, pps, maxPackets)) {
      Serial.println("Error: Invalid inject command syntax");
      return;
    }

    // Display packet info before starting
    Serial.println("\n=== Configuring Injector ===");
    Serial.println("Name: " + injectorName);
    Serial.println("Packet length: " + String(packetLen) + " bytes");
    Serial.println("Channel: " + String(channel));
    Serial.println("Rate: " + String(pps) + " packets/sec");
    Serial.println("Max packets: " + (maxPackets == 0 ? "Unlimited" : String(maxPackets)));

    injectorManager.startInjector(
      injectorName,
      packetData,
      packetLen,
      channel,
      pps,
      maxPackets);

    Serial.println("Injector '" + injectorName + "' started successfully");
    Serial.println("===========================\n");
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
  // ====== CAPTIVE PORTAL ======
  else if (lowerCmd.startsWith("captive_portal")) {
    handleStartCommand(lowerCmd);
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
  // ====== SD CARD INFO ======
  else if (lowerCmd == "sd_info") {
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
  }
  // ====== SD LIST FILES ======
  else if (lowerCmd.startsWith("sd_ls")) {
    // Parse arguments from original cmd (preserve case for paths)
    // Expected forms:
    //   sd_ls
    //   sd_ls /path
    //   sd_ls -h -r -e pcap /logs
    String args = "";
    int spaceIndex = cmd.indexOf(' ');
    if (spaceIndex != -1) {
      args = cmd.substring(spaceIndex + 1);
      args.trim();
    }

    // Flags
    bool humanReadable = false;
    bool recursive = false;
    String extFilter = "";  // without leading dot, e.g. "pcap"
    String path = "/";

    // Simple tokenizer
    // Note: minimal parser — treats tokens separated by spaces
    int idx = 0;
    while (idx < args.length()) {
      // get next token
      int nextSpace = args.indexOf(' ', idx);
      String token;
      if (nextSpace == -1) {
        token = args.substring(idx);
        idx = args.length();
      } else {
        token = args.substring(idx, nextSpace);
        idx = nextSpace + 1;
      }
      token.trim();
      if (token.length() == 0) continue;

      if (token == "-h" || token == "--human") {
        humanReadable = true;
      } else if (token == "-r" || token == "--recursive") {
        recursive = true;
      } else if (token == "-e" || token == "--ext") {
        // get next token as extension
        if (idx >= args.length()) {
          Serial.println("Error: -e requires an extension (e.g. -e pcap)");
          return;
        }
        int next = args.indexOf(' ', idx);
        String extTok;
        if (next == -1) {
          extTok = args.substring(idx);
          idx = args.length();
        } else {
          extTok = args.substring(idx, next);
          idx = next + 1;
        }
        extTok.trim();
        // normalize extension: remove leading dot if present, lowercase
        if (extTok.startsWith(".")) extTok = extTok.substring(1);
        extTok.toLowerCase();
        extFilter = extTok;
      } else {
        // treat token as path (last path token wins)
        path = token;
        if (!path.startsWith("/")) path = "/" + path;
      }
    }

    // helper: human-readable size
    auto hrSize = [](uint64_t bytes) -> String {
      if (bytes < 1024) {
        return String(bytes) + " B";
      } else if (bytes < (1024ULL * 1024ULL)) {
        float kb = (float)bytes / 1024.0;
        char buf[16];
        dtostrf(kb, 0, 2, buf);
        return String(buf) + " KB";
      } else {
        float mb = (float)bytes / (1024.0 * 1024.0);
        char buf[16];
        dtostrf(mb, 0, 2, buf);
        return String(buf) + " MB";
      }
    };

    // recursive listing function (lambda capturing above flags)
    const int MAX_RECURSION = 10;  // safety
    std::function<void(const String&, int)> listDir;
    listDir = [&](const String& dirPath, int depth) {
      if (depth > MAX_RECURSION) {
        Serial.println(String(depth) + ": Max recursion reached for " + dirPath);
        return;
      }

      File dir = SD.open(dirPath.c_str());
      if (!dir) {
        Serial.println("Failed to open: " + dirPath);
        return;
      }

      if (!dir.isDirectory()) {
        // If user passed a file path instead of directory, print it
        uint64_t sz = dir.size();
        String name = dir.name();
        // apply ext filter if present
        if (extFilter.length() > 0) {
          String lowerName = name;
          lowerName.toLowerCase();
          int dot = lowerName.lastIndexOf('.');
          String fileExt = (dot == -1) ? "" : lowerName.substring(dot + 1);
          if (fileExt != extFilter) {
            dir.close();
            return;
          }
        }
        // print
        String indent = "";
        for (int i = 0; i < depth; ++i) indent += "  ";
        Serial.print(indent);
        Serial.print("[FILE] ");
        Serial.print(name);
        Serial.print("  ");
        Serial.println(humanReadable ? hrSize(sz) : String(sz) + " bytes");
        dir.close();
        return;
      }

      String indent = "";
      for (int i = 0; i < depth; ++i) indent += "  ";
      Serial.println(indent + "Listing: " + dirPath);

      File entry;
      while (true) {
        entry = dir.openNextFile();
        if (!entry) break;

        String name = entry.name();
        if (entry.isDirectory()) {
          Serial.print(indent);
          Serial.print("  [DIR ] ");
          Serial.println(name);
          if (recursive) {
            // build child path (ensure single slash)
            String childPath = dirPath;
            if (!childPath.endsWith("/")) childPath += "/";
            childPath += name;
            // ensure leading slash
            if (!childPath.startsWith("/")) childPath = "/" + childPath;
            entry.close();
            listDir(childPath, depth + 1);
            continue;
          }
        } else {
          // apply extension filter if set
          if (extFilter.length() > 0) {
            String lowerName = name;
            lowerName.toLowerCase();
            int dot = lowerName.lastIndexOf('.');
            String fileExt = (dot == -1) ? "" : lowerName.substring(dot + 1);
            if (fileExt != extFilter) {
              entry.close();
              continue;
            }
          }
          uint64_t sz = entry.size();
          Serial.print(indent);
          Serial.print("  [FILE] ");
          Serial.print(name);
          Serial.print("  ");
          Serial.println(humanReadable ? hrSize(sz) : String(sz) + " bytes");
        }
        entry.close();
      }

      dir.close();
    };

    // run
    listDir(path, 0);
  }
  // ====== SD TREE ======
  else if (lowerCmd.startsWith("sd_tree")) {
    String args = "";
    int spaceIndex = cmd.indexOf(' ');
    if (spaceIndex != -1) {
      args = cmd.substring(spaceIndex + 1);
      args.trim();
    }

    bool human = false;
    int maxDepth = 16;  // default depth limit
    String path = "/";

    // parse simple tokens
    int idx = 0;
    while (idx < args.length()) {
      int next = args.indexOf(' ', idx);
      String tok;
      if (next == -1) {
        tok = args.substring(idx);
        idx = args.length();
      } else {
        tok = args.substring(idx, next);
        idx = next + 1;
      }
      tok.trim();
      if (tok.length() == 0) continue;

      if (tok == "-h" || tok == "--human") {
        human = true;
      } else if (tok == "-d" || tok == "--depth") {
        // read depth value
        if (idx >= args.length()) {
          Serial.println("Error: -d requires a depth value");
          return;
        }
        int nx = args.indexOf(' ', idx);
        String val;
        if (nx == -1) {
          val = args.substring(idx);
          idx = args.length();
        } else {
          val = args.substring(idx, nx);
          idx = nx + 1;
        }
        maxDepth = val.toInt();
        if (maxDepth <= 0) maxDepth = 1;
      } else {
        path = tok;
        if (!path.startsWith("/")) path = "/" + path;
      }
    }

    if (!SD.exists(path.c_str())) {
      Serial.println("Not found: " + path);
      return;
    }

    // human-readable helper
    auto hr = [&](uint64_t bytes) -> String {
      if (!human) return String(bytes) + " B";
      if (bytes < 1024) return String(bytes) + " B";
      if (bytes < (1024ULL * 1024ULL)) {
        char b[16];
        dtostrf((float)bytes / 1024.0, 0, 2, b);
        return String(b) + " KB";
      }
      char b[16];
      dtostrf((float)bytes / (1024.0 * 1024.0), 0, 2, b);
      return String(b) + " MB";
    };

    // recursive printer (ASCII tree)
    std::function<void(const String&, const String&, int)> printTree;
    printTree = [&](const String& dirPath, const String& prefix, int depth) {
      if (depth > maxDepth) return;

      File d = SD.open(dirPath.c_str());
      if (!d) {
        Serial.println(prefix + "Failed to open: " + dirPath);
        return;
      }

      if (!d.isDirectory()) {
        // single file path
        uint64_t s = d.size();
        Serial.println(prefix + "`-- " + d.name() + " (" + hr(s) + ")");
        d.close();
        return;
      }

      Serial.println(prefix + dirPath);
      // collect entries first (because openNextFile yields in order but we must know last)
      const int MAX_ENTRIES = 256;  // safety cap
      struct Entry {
        String name;
        bool isDir;
        uint64_t size;
      };
      std::vector<Entry> entries;
      File entry;
      while (true) {
        entry = d.openNextFile();
        if (!entry) break;
        Entry E;
        E.name = entry.name();
        E.isDir = entry.isDirectory();
        E.size = entry.size();
        entries.push_back(E);
        entry.close();
        if ((int)entries.size() >= MAX_ENTRIES) break;
      }
      d.close();

      for (size_t i = 0; i < entries.size(); ++i) {
        bool last = (i == entries.size() - 1);
        String linePrefix = prefix + (last ? "└── " : "├── ");
        if (entries[i].isDir) {
          Serial.println(linePrefix + entries[i].name + "/");
          String childPrefix = prefix + (last ? "    " : "│   ");
          // build child path
          String childPath = dirPath;
          if (!childPath.endsWith("/")) childPath += "/";
          childPath += entries[i].name;
          printTree(childPath, childPrefix, depth + 1);
        } else {
          Serial.println(linePrefix + entries[i].name + " (" + hr(entries[i].size) + ")");
        }
      }
    };

    printTree(path, "", 1);
  }
  // ====== SD REMOVE ======
  else if (lowerCmd.startsWith("sd_rm")) {
    // Parse args
    String args = "";
    int spaceIndex = cmd.indexOf(' ');
    if (spaceIndex != -1) {
      args = cmd.substring(spaceIndex + 1);
      args.trim();
    }

    bool recursive = false;
    bool confirmYes = false;  // require -y to actually delete when -r is used
    String path = "";

    // parse flags/tokens
    int idx = 0;
    while (idx < args.length()) {
      int next = args.indexOf(' ', idx);
      String tok;
      if (next == -1) {
        tok = args.substring(idx);
        idx = args.length();
      } else {
        tok = args.substring(idx, next);
        idx = next + 1;
      }
      tok.trim();
      if (tok.length() == 0) continue;

      if (tok == "-r" || tok == "--recursive") recursive = true;
      else if (tok == "-y" || tok == "--yes" || tok == "--force") confirmYes = true;
      else path = tok;  // last token wins as path
    }

    if (path.length() == 0) {
      Serial.println("Usage: sd_rm [-r] [-y] <path>");
      Serial.println("  -r    recursive (directory)");
      Serial.println("  -y    actually perform delete when using -r (otherwise dry-run)");
      return;
    }
    if (!path.startsWith("/")) path = "/" + path;
    if (path == "/") {
      Serial.println("Refusing to remove root '/'");
      return;
    }

    if (!SD.exists(path.c_str())) {
      Serial.println("Not found: " + path);
      return;
    }

    // helper: get basename (safeguard if File.name() returns full path)
    auto basenameOf = [](const String& p) -> String {
      int i = p.lastIndexOf('/');
      if (i < 0) return p;
      return p.substring(i + 1);
    };

    // helper: print or perform delete depending on confirmYes
    std::function<bool(const String&)> removeRecursive;
    removeRecursive = [&](const String& p) -> bool {
      File f = SD.open(p.c_str());
      if (!f) {
        Serial.println("Failed to open for delete: " + p);
        return false;
      }

      if (!f.isDirectory()) {
        // file
        f.close();
        if (!confirmYes) {
          Serial.println(String("[DRY-RUN] Would delete file: ") + p);
          return true;
        }
        bool ok = SD.remove(p.c_str());
        Serial.println(String(ok ? "Deleted file: " : "Failed to delete file: ") + p);
        return ok;
      }

      // directory: traverse children
      File entry;
      while (true) {
        entry = f.openNextFile();
        if (!entry) break;
        String name = entry.name();
        // if entry.name() contains '/', treat it as full path; otherwise build childPath
        String childPath;
        if (name.startsWith("/")) childPath = name;
        else {
          childPath = p;
          if (!childPath.endsWith("/")) childPath += "/";
          childPath += basenameOf(name);
        }
        bool childIsDir = entry.isDirectory();
        entry.close();

        // Recurse or delete file
        if (childIsDir) {
          if (!removeRecursive(childPath)) {
            f.close();
            return false;
          }
          if (!confirmYes) {
            Serial.println(String("[DRY-RUN] Would remove dir: ") + childPath);
          } else {
            if (!SD.rmdir(childPath.c_str())) {
              // Some SD implementations may not support rmdir; we log but continue
              Serial.println(String("Warning: rmdir failed for: ") + childPath);
            } else {
              Serial.println(String("Removed dir: ") + childPath);
            }
          }
        } else {
          if (!confirmYes) {
            Serial.println(String("[DRY-RUN] Would delete file: ") + childPath);
          } else {
            if (!SD.remove(childPath.c_str())) {
              Serial.println(String("Failed to delete file: ") + childPath);
              f.close();
              return false;
            } else {
              Serial.println(String("Deleted file: ") + childPath);
            }
          }
        }
      }
      f.close();

      // finally remove this directory itself (top-level directory)
      if (!confirmYes) {
        Serial.println(String("[DRY-RUN] Would remove directory: ") + p);
        return true;
      }
      if (!SD.rmdir(p.c_str())) {
        Serial.println(String("Failed to remove directory: ") + p);
        return false;
      }
      Serial.println(String("Removed directory: ") + p);
      return true;
    };

    // if path is file -> remove directly (honor confirmYes)
    File chk = SD.open(path.c_str());
    if (!chk) {
      Serial.println("Failed to open: " + path);
      return;
    }
    bool isDir = chk.isDirectory();
    chk.close();

    if (isDir && !recursive) {
      Serial.println("Path is a directory. Use -r to remove recursively (with -y to actually delete).");
      return;
    }

    if (!isDir) {
      if (!confirmYes) {
        Serial.println(String("[DRY-RUN] Would delete file: ") + path);
        return;
      }
      if (SD.remove(path.c_str())) {
        Serial.println("Deleted: " + path);
      } else {
        Serial.println("Failed to delete: " + path);
      }
      return;
    }

    // directory + recursive
    if (removeRecursive(path)) {
      return;
    } else {
      Serial.println("sd_rm: errors occurred while removing " + path);
    }
  }
  // ====== SD DISK USAGE ======
  else if (lowerCmd.startsWith("sd_du")) {
    String args = "";
    int spaceIndex = cmd.indexOf(' ');
    if (spaceIndex != -1) {
      args = cmd.substring(spaceIndex + 1);
      args.trim();
    }

    bool human = false;
    String path = "/";

    // parse simple flags: -h and optional path
    int idx = 0;
    while (idx < args.length()) {
      int next = args.indexOf(' ', idx);
      String tok;
      if (next == -1) {
        tok = args.substring(idx);
        idx = args.length();
      } else {
        tok = args.substring(idx, next);
        idx = next + 1;
      }
      tok.trim();
      if (tok.length() == 0) continue;
      if (tok == "-h" || tok == "--human") human = true;
      else {
        path = tok;
        if (!path.startsWith("/")) path = "/" + path;
      }
    }

    if (!SD.exists(path.c_str())) {
      Serial.println("Not found: " + path);
      return;
    }

    auto hr = [&](uint64_t b) -> String {
      if (!human) return String(b) + " B";
      if (b < 1024) return String(b) + " B";
      if (b < (1024ULL * 1024ULL)) {
        char buf[16];
        dtostrf((float)b / 1024.0, 0, 2, buf);
        return String(buf) + " KB";
      }
      char buf[16];
      dtostrf((float)b / (1024.0 * 1024.0), 0, 2, buf);
      return String(buf) + " MB";
    };

    const int MAX_DEPTH = 10;
    std::function<uint64_t(const String&, int)> duRec;
    duRec = [&](const String& p, int depth) -> uint64_t {
      if (depth > MAX_DEPTH) return 0;
      File f = SD.open(p.c_str());
      if (!f) { return 0; }
      uint64_t total = 0;
      if (!f.isDirectory()) {
        total = f.size();
        f.close();
        return total;
      }

      File entry;
      while (true) {
        entry = f.openNextFile();
        if (!entry) break;
        String name = entry.name();
        String child;
        if (name.startsWith("/")) child = name;
        else {
          child = p;
          if (!child.endsWith("/")) child += "/";
          // handle case entry.name() might be full path or base name
          int slash = name.lastIndexOf('/');
          if (slash >= 0) child += name.substring(slash + 1);
          else child += name;
        }

        if (entry.isDirectory()) {
          entry.close();
          total += duRec(child, depth + 1);
        } else {
          total += entry.size();
          entry.close();
        }
      }
      f.close();
      return total;
    };

    uint64_t totalBytes = duRec(path, 0);
    Serial.println("Path: " + path + "  Size: " + hr(totalBytes));
  }
  // ====== SD CAT ======
  else if (lowerCmd.startsWith("sd_cat")) {
    int sp = cmd.indexOf(' ');
    if (sp == -1) {
      Serial.println("Usage: sd_cat <file>");
      return;
    }
    String path = cmd.substring(sp + 1);
    path.trim();
    if (!path.startsWith("/")) path = "/" + path;

    if (!SD.exists(path.c_str())) {
      Serial.println("Not found: " + path);
      return;
    }

    File f = SD.open(path.c_str());
    if (!f) {
      Serial.println("Failed to open: " + path);
      return;
    }
    if (f.isDirectory()) {
      Serial.println("Path is a directory: " + path);
      f.close();
      return;
    }

    const size_t MAX_PRINT_BYTES = 4096;  // adjustable safety cap
    size_t toRead = f.size();
    if (toRead > MAX_PRINT_BYTES) {
      Serial.println("File too large to print fully. Printing first " + String(MAX_PRINT_BYTES) + " bytes:");
      toRead = MAX_PRINT_BYTES;
    } else {
      Serial.println("Printing " + String(toRead) + " bytes:");
    }

    // Stream to serial in chunks
    const size_t BUF = 128;
    uint8_t buf[BUF];
    size_t remaining = toRead;
    while (remaining > 0) {
      size_t r = remaining > BUF ? BUF : remaining;
      size_t n = f.read(buf, r);
      if (n == 0) break;
      Serial.write(buf, n);
      remaining -= n;
    }
    Serial.println();
    f.close();
  }
  // ====== SD MOVE/RENAME ======
  else if (lowerCmd.startsWith("sd_mv")) {
    // parse tokens: optional -f, then src and dst
    String args = "";
    int si = cmd.indexOf(' ');
    if (si != -1) {
      args = cmd.substring(si + 1);
      args.trim();
    }

    bool force = false;
    String src = "";
    String dst = "";
    int idx = 0;
    while (idx < args.length()) {
      int next = args.indexOf(' ', idx);
      String tok;
      if (next == -1) {
        tok = args.substring(idx);
        idx = args.length();
      } else {
        tok = args.substring(idx, next);
        idx = next + 1;
      }
      tok.trim();
      if (tok.length() == 0) continue;
      if (tok == "-f" || tok == "--force") {
        force = true;
        continue;
      }
      if (src.length() == 0) src = tok;
      else if (dst.length() == 0) dst = tok;
      else { /* ignore extras */ }
    }

    if (src.length() == 0 || dst.length() == 0) {
      Serial.println("Usage: sd_mv [-f] <src> <dst>");
      return;
    }

    if (!src.startsWith("/")) src = "/" + src;
    if (!dst.startsWith("/")) dst = "/" + dst;

    if (!SD.exists(src.c_str())) {
      Serial.println("Source not found: " + src);
      return;
    }

    if (SD.exists(dst.c_str())) {
      if (!force) {
        Serial.println("Destination exists. Use -f to overwrite: " + dst);
        return;
      } else {
        // attempt to remove dest (file or empty dir)
        File dchk = SD.open(dst.c_str());
        if (dchk) {
          if (dchk.isDirectory()) {
            dchk.close();
            // try rmdir; if fails, abort
            if (!SD.rmdir(dst.c_str())) {
              Serial.println("Failed to remove existing destination directory: " + dst);
              return;
            }
          } else {
            dchk.close();
            if (!SD.remove(dst.c_str())) {
              Serial.println("Failed to remove existing destination file: " + dst);
              return;
            }
          }
        }
      }
    }

    // Use SD.rename (returns true on success)
    if (SD.rename(src.c_str(), dst.c_str())) {
      Serial.println("Renamed/moved: " + src + " -> " + dst);
    } else {
      Serial.println("Failed to rename/move: " + src + " -> " + dst);
    }
  }
  // ====== SD HEAD ======
  else if (lowerCmd.startsWith("sd_head")) {
    String args = "";
    int sp = cmd.indexOf(' ');
    if (sp != -1) {
      args = cmd.substring(sp + 1);
      args.trim();
    }

    int lines = 10;
    String path = "";
    int idx = 0;
    while (idx < args.length()) {
      int next = args.indexOf(' ', idx);
      String tok;
      if (next == -1) {
        tok = args.substring(idx);
        idx = args.length();
      } else {
        tok = args.substring(idx, next);
        idx = next + 1;
      }
      tok.trim();
      if (tok.length() == 0) continue;
      if (tok == "-n") {
        if (idx >= args.length()) {
          Serial.println("Error: -n requires a number");
          return;
        }
        int nx = args.indexOf(' ', idx);
        String v;
        if (nx == -1) {
          v = args.substring(idx);
          idx = args.length();
        } else {
          v = args.substring(idx, nx);
          idx = nx + 1;
        }
        lines = v.toInt();
        if (lines <= 0) lines = 1;
      } else {
        path = tok;
        if (!path.startsWith("/")) path = "/" + path;
      }
    }

    if (path.length() == 0) {
      Serial.println("Usage: sd_head [-n <lines>] <file>");
      return;
    }
    if (!SD.exists(path.c_str())) {
      Serial.println("Not found: " + path);
      return;
    }

    File f = SD.open(path.c_str());
    if (!f) {
      Serial.println("Failed to open: " + path);
      return;
    }
    if (f.isDirectory()) {
      Serial.println("Path is a directory: " + path);
      f.close();
      return;
    }

    Serial.println("----- head " + String(lines) + " lines: " + path + " -----");
    int printed = 0;
    const size_t BUF = 128;
    char buf[BUF];
    size_t bufPos = 0;
    while (f.available() && printed < lines) {
      int c = f.read();
      if (c < 0) break;
      buf[bufPos++] = (char)c;
      if (c == '\n' || bufPos == BUF - 1) {
        buf[bufPos] = 0;
        Serial.print(buf);
        bufPos = 0;
        printed++;
      }
    }
    // flush any remaining partial line
    if (bufPos > 0 && printed < lines) {
      buf[bufPos] = 0;
      Serial.print(buf);
    }
    Serial.println();
    f.close();
  }
  // ====== SD TAIL ======
  else if (lowerCmd.startsWith("sd_tail")) {
    String args = "";
    int sp = cmd.indexOf(' ');
    if (sp != -1) {
      args = cmd.substring(sp + 1);
      args.trim();
    }

    int lines = 10;
    String path = "";
    int idx = 0;
    while (idx < args.length()) {
      int next = args.indexOf(' ', idx);
      String tok;
      if (next == -1) {
        tok = args.substring(idx);
        idx = args.length();
      } else {
        tok = args.substring(idx, next);
        idx = next + 1;
      }
      tok.trim();
      if (tok.length() == 0) continue;
      if (tok == "-n") {
        if (idx >= args.length()) {
          Serial.println("Error: -n requires a number");
          return;
        }
        int nx = args.indexOf(' ', idx);
        String v;
        if (nx == -1) {
          v = args.substring(idx);
          idx = args.length();
        } else {
          v = args.substring(idx, nx);
          idx = nx + 1;
        }
        lines = v.toInt();
        if (lines <= 0) lines = 1;
      } else {
        path = tok;
        if (!path.startsWith("/")) path = "/" + path;
      }
    }

    if (path.length() == 0) {
      Serial.println("Usage: sd_tail [-n <lines>] <file>");
      return;
    }
    if (!SD.exists(path.c_str())) {
      Serial.println("Not found: " + path);
      return;
    }

    File f = SD.open(path.c_str(), FILE_READ);
    if (!f) {
      Serial.println("Failed to open: " + path);
      return;
    }
    if (f.isDirectory()) {
      Serial.println("Path is a directory: " + path);
      f.close();
      return;
    }

    const size_t MAX_TAIL_BYTES = 8192;  // safety cap, adjust if desired
    uint64_t sz = f.size();
    size_t toRead = (sz > MAX_TAIL_BYTES) ? MAX_TAIL_BYTES : (size_t)sz;
    // Seek to last toRead bytes
    if (!f.seek((int)(sz - toRead))) {
      // fallback: read from beginning if seek fails
      f.seek(0);
      toRead = (size_t)sz;
    }

    // Read into buffer
    uint8_t* buffer = (uint8_t*)malloc(toRead + 1);
    if (!buffer) {
      Serial.println("Out of memory for tail buffer");
      f.close();
      return;
    }
    size_t r = f.read(buffer, toRead);
    buffer[r] = 0;
    f.close();

    // convert to String and split into lines from end
    String s = String((char*)buffer);
    free(buffer);

    // count lines from the end
    int found = 0;
    int pos = s.length() - 1;
    int startIdx = 0;
    for (; pos >= 0; --pos) {
      if (s.charAt(pos) == '\n') {
        found++;
        if (found == lines + 1) {
          startIdx = pos + 1;
          break;
        }
      }
    }
    if (found < lines + 1) startIdx = 0;
    Serial.println("----- tail " + String(lines) + " lines: " + path + " -----");
    Serial.print(s.substring(startIdx));
    Serial.println();
  }
  // ====== SD COPY ======
  else if (lowerCmd.startsWith("sd_cp")) {
    String args = "";
    int si = cmd.indexOf(' ');
    if (si != -1) {
      args = cmd.substring(si + 1);
      args.trim();
    }

    bool force = false;
    String src = "";
    String dst = "";
    int idx = 0;
    while (idx < args.length()) {
      int next = args.indexOf(' ', idx);
      String tok;
      if (next == -1) {
        tok = args.substring(idx);
        idx = args.length();
      } else {
        tok = args.substring(idx, next);
        idx = next + 1;
      }
      tok.trim();
      if (tok.length() == 0) continue;
      if (tok == "-f" || tok == "--force") {
        force = true;
        continue;
      }
      if (src.length() == 0) src = tok;
      else if (dst.length() == 0) dst = tok;
    }

    if (src.length() == 0 || dst.length() == 0) {
      Serial.println("Usage: sd_cp [-f] <src> <dst>");
      return;
    }
    if (!src.startsWith("/")) src = "/" + src;
    if (!dst.startsWith("/")) dst = "/" + dst;

    if (!SD.exists(src.c_str())) {
      Serial.println("Source not found: " + src);
      return;
    }
    if (SD.exists(dst.c_str())) {
      if (!force) {
        Serial.println("Destination exists. Use -f to overwrite: " + dst);
        return;
      }
      // try remove destination
      File dchk = SD.open(dst.c_str());
      if (dchk) {
        if (dchk.isDirectory()) {
          dchk.close();
          if (!SD.rmdir(dst.c_str())) {
            Serial.println("Failed to remove existing destination dir: " + dst);
            return;
          }
        } else {
          dchk.close();
          if (!SD.remove(dst.c_str())) {
            Serial.println("Failed to remove existing destination file: " + dst);
            return;
          }
        }
      }
    }

    File fr = SD.open(src.c_str(), FILE_READ);
    if (!fr) {
      Serial.println("Failed to open source: " + src);
      return;
    }
    File fw = SD.open(dst.c_str(), FILE_WRITE);
    if (!fw) {
      fr.close();
      Serial.println("Failed to create destination: " + dst);
      return;
    }

    const size_t BUF = 256;
    uint8_t buf[BUF];
    while (fr.available()) {
      size_t n = fr.read(buf, BUF);
      if (n == 0) break;
      fw.write(buf, n);
    }

    fr.close();
    fw.close();
    Serial.println("Copied: " + src + " -> " + dst);
  }
  // ====== SD FIND ======
  else if (lowerCmd.startsWith("sd_find")) {
    String args = "";
    int si = cmd.indexOf(' ');
    if (si != -1) {
      args = cmd.substring(si + 1);
      args.trim();
    }

    bool recursive = true;
    String ext = "";
    String substr = "";
    String path = "/";

    int idx = 0;
    while (idx < args.length()) {
      int next = args.indexOf(' ', idx);
      String tok;
      if (next == -1) {
        tok = args.substring(idx);
        idx = args.length();
      } else {
        tok = args.substring(idx, next);
        idx = next + 1;
      }
      tok.trim();
      if (tok.length() == 0) continue;
      if (tok == "-r") {
        recursive = true;
      } else if (tok == "--no-rec") {
        recursive = false;
      } else if (tok == "-e" || tok == "--ext") {
        if (idx >= args.length()) {
          Serial.println("Error: -e requires extension");
          return;
        }
        int nx = args.indexOf(' ', idx);
        String v;
        if (nx == -1) {
          v = args.substring(idx);
          idx = args.length();
        } else {
          v = args.substring(idx, nx);
          idx = nx + 1;
        }
        if (v.startsWith(".")) v = v.substring(1);
        v.toLowerCase();
        ext = v;
      } else if (tok.startsWith("/")) {
        path = tok;
        if (!path.startsWith("/")) path = "/" + path;
      } else {
        // if substr not set yet, use this token as substring
        if (substr.length() == 0) substr = tok;
      }
    }

    if (!SD.exists(path.c_str())) {
      Serial.println("Not found: " + path);
      return;
    }

    Serial.println("Searching in: " + path + " (ext: " + ext + ", substr: " + substr + ")");

    const int MAX_DEPTH = 12;
    std::function<void(const String&, int)> finder;
    finder = [&](const String& p, int depth) {
      if (!recursive && depth > 0) return;
      if (depth > MAX_DEPTH) return;
      File d = SD.open(p.c_str());
      if (!d) return;
      File entry;
      while (true) {
        entry = d.openNextFile();
        if (!entry) break;
        String name = entry.name();
        String display;
        if (name.startsWith("/")) display = name;
        else {
          display = p;
          if (!display.endsWith("/")) display += "/";
          display += name;
        }

        if (entry.isDirectory()) {
          // directory: optionally recurse
          if (recursive) finder(display, depth + 1);
        } else {
          String lname = name;
          lname.toLowerCase();
          bool match = false;
          if (ext.length() > 0) {
            int dot = lname.lastIndexOf('.');
            String fileExt = (dot == -1) ? "" : lname.substring(dot + 1);
            if (fileExt == ext) match = true;
          }
          if (substr.length() > 0) {
            String lowerSub = substr;
            lowerSub.toLowerCase();
            if (lname.indexOf(lowerSub) != -1) match = true;
          }
          // if no filter provided, match all files
          if (ext.length() == 0 && substr.length() == 0) match = true;

          if (match) {
            Serial.println(display);
          }
        }
        entry.close();
      }
      d.close();
    };

    finder(path, 0);
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