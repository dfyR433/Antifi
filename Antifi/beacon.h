#ifndef BEACON_FLOOD_H
#define BEACON_FLOOD_H

#include <Arduino.h>
#include <vector>

// ---------- ADVANCED CONFIGURATION STRUCTURE ----------
struct BeaconConfig {
  // SSID Generation
  uint16_t num_ssids;              // Up to 65535 SSIDs
  uint8_t min_ssid_len;
  uint8_t max_ssid_len;
  bool enable_rsn;
  bool realistic_ssids;
  
  // Transmission Control
  uint16_t dwell_ms;
  uint8_t tx_per_channel;
  uint8_t tx_power;
  
  // Advanced Features
  bool enable_vendor_elements;
  bool enable_performance_stats;
  bool enable_parallel_transmission;
  bool enable_directed_broadcast;
  
  // Performance Optimization
  uint8_t tx_queue_size;
  uint8_t wifi_mode;
  bool disable_wifi_mgmt;
  bool enable_packet_burst;
  
  // Advanced SSID Generation
  bool enable_mimicry;
  bool enable_ssid_cache;
  bool use_common_passwords;
  
  // Channel Control
  bool use_all_channels;
  uint8_t channel_bandwidth;
  
  // Custom SSIDs
  const char** custom_ssid_list;
  int custom_ssid_count;
};

// ---------- REGIONAL CHANNEL CONFIG ----------
#define REGION_US       // All 14 channels
// #define REGION_EU     // 13 channels
// #define REGION_CHINA  // 13 channels
// #define REGION_5GHZ   // 5GHz channels

// ---------- CONSTANTS ----------
#define MAX_SSID_LENGTH 32
#define MAX_CUSTOM_SSIDS 2000
#define MAX_PARALLEL_TRANSMITS 5
#define BEACON_BUFFER_SIZE 512
#define MAX_SSID_CACHE 30000

// ---------- ENUMS ----------
enum TransmissionMode {
  MODE_NORMAL = 0,
  MODE_AGGRESSIVE = 1,
  MODE_STEALTH = 2,
  MODE_TURBO = 3,
  MODE_EXPLOSIVE = 4
};

enum ChannelStrategy {
  STRAT_HOPPING = 0,
  STRAT_FOCUSED = 1,
  STRAT_SWEEP = 2,
  STRAT_RANDOM = 3
};

// ---------- FUNCTION DECLARATIONS ----------
// Core Functions
void beacon_setup();
void beacon_loop();
void stop_beacon();
void emergency_stop();
void pause_beacon();
void resume_beacon();

// Advanced configuration management
void setBeaconConfig(const BeaconConfig& newConfig);
BeaconConfig getBeaconConfig();
void resetConfigToDefaults();
void loadCustomSSIDs(const char** ssids, int count);
void setWiFiMode(uint8_t mode);
void setTxPower(uint8_t power);
void setChannelBandwidth(uint8_t bandwidth);

// Status and statistics
bool isBeaconActive();
bool isBeaconPaused();
unsigned long getTotalPacketsSent();
unsigned long getErrorCount();
float getPacketsPerSecond();
void printStatistics();
void printHeapStatus();
void printSystemStatus();
void printChannelInfo();
void printSSIDCacheStatus();

// Performance functions
void setChannelStrategy(ChannelStrategy strategy);
void setTransmissionMode(TransmissionMode mode);
void setPowerSaving(bool enable);
void setRandomizationLevel(uint8_t level);
void setTurboMode(bool enable);
void setFocusChannel(uint8_t channel);
void setPacketInterval(uint16_t interval_ms);
void setMaxPacketsPerSecond(uint32_t max_pps);
void setChannelDwellTime(uint16_t dwell_ms);

// Advanced features
void enableSSIDMimicry(bool enable);
void enablePacketBurst(bool enable);
void enableSSIDCache(bool enable);
void enableCommonPasswords(bool enable);

extern bool beacon_active;
extern bool beacon_paused;
extern uint32_t packets_per_second;
extern uint32_t max_packets_per_second;
extern TransmissionMode current_mode;

#endif  // BEACON_FLOOD_H