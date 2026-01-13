#ifndef SCAN_H
#define SCAN_H

#include <WiFi.h>
#include <vector>
#include <array>
#include <Preferences.h>
#include <map>
#include <algorithm>
#include <cstring>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_console.h"

// ===== Configuration Constants =====
#define MAX_APS 100          // Maximum number of APs to store
#define MAX_CLIENTS 300      // Maximum number of clients to store
#define MAX_SSID_HISTORY 20  // Store recent SSIDs per client
#define MAX_PROBE_CACHE 50   // Maximum probe requests to cache

// ===== WiFi Frame Types =====
#define FRAME_TYPE_MANAGEMENT 0x00
#define FRAME_TYPE_CONTROL 0x01
#define FRAME_TYPE_DATA 0x02

// ===== Management Frame Subtypes =====
#define SUBTYPE_ASSOCIATION_REQUEST 0x00
#define SUBTYPE_ASSOCIATION_RESPONSE 0x01
#define SUBTYPE_REASSOCIATION_REQUEST 0x02
#define SUBTYPE_REASSOCIATION_RESPONSE 0x03
#define SUBTYPE_PROBE_REQUEST 0x04
#define SUBTYPE_PROBE_RESPONSE 0x05
#define SUBTYPE_BEACON 0x08
#define SUBTYPE_DISASSOCIATION 0x0A
#define SUBTYPE_AUTHENTICATION 0x0B
#define SUBTYPE_DEAUTHENTICATION 0x0C

// ===== Control Frame Subtypes =====
#define SUBTYPE_CTS 0x1C
#define SUBTYPE_RTS 0x1B
#define SUBTYPE_ACK 0x1D

// ===== Data Frame Subtypes =====
#define SUBTYPE_DATA 0x00
#define SUBTYPE_DATA_CF_ACK 0x01
#define SUBTYPE_DATA_CF_POLL 0x02
#define SUBTYPE_DATA_CF_ACK_POLL 0x03
#define SUBTYPE_NULL 0x04
#define SUBTYPE_CF_ACK 0x05
#define SUBTYPE_CF_POLL 0x06
#define SUBTYPE_CF_ACK_POLL 0x07

// ===== WPS Constants =====
#define WPS_IE_ID 0xDD
#define WPS_OUI_00 0x00
#define WPS_OUI_50 0x50
#define WPS_OUI_F2 0xF2
#define WPS_OUI_TYPE 0x04
#define WPS_VERSION_1 0x10
#define WPS_VERSION_2 0x20

// ===== Frame Offsets =====
#define BEACON_SSID_OFFSET 36
#define PROBE_RESP_SSID_OFFSET 36
#define MAC_HEADER_SIZE 24
#define BEACON_FIXED_PARAMS 12

// ===== MAC Address Type =====
typedef std::array<uint8_t, 6> mac_address_t;

// ===== Enhanced Data Structures =====

// Structure to track SSID history for clients
typedef struct {
  char ssid[33];             // SSID string
  uint8_t ssid_len;          // SSID length
  unsigned long first_seen;  // When first seen
  unsigned long last_seen;   // When last seen
  uint16_t probe_count;      // How many times probed
  bool is_hidden;            // If SSID was hidden
} SSIDHistory;

// Structure for cached probe requests
typedef struct {
  mac_address_t client_mac;    // Client MAC address
  char ssid[33];               // SSID from probe request
  uint8_t ssid_len;            // SSID length
  unsigned long timestamp;     // When seen
  int rssi;                    // Signal strength
  int channel;                 // Channel where seen
  bool is_hidden;              // If SSID was hidden in probe
  mac_address_t target_bssid;  // Target AP BSSID (if directed probe)
} ProbeCache;

// Structure for client-AP associations
typedef struct {
  mac_address_t client_mac;
  mac_address_t ap_bssid;
  unsigned long first_associated;
  unsigned long last_associated;
  int association_count;
} ClientAssociation;

typedef struct {
  mac_address_t bssid;                            // MAC address of AP
  char ssid[33];                                  // SSID (max 32 chars + null)
  uint8_t ssid_len;                               // Display SSID length (8 for "[Hidden]")
  uint8_t original_ssid_len;                      // Original SSID length from frame (0-32)
  bool ssid_known;                                // True if SSID was discovered
  bool hidden;                                    // True if SSID is hidden
  int rssi;                                       // Signal strength in dBm
  int channel;                                    // WiFi channel
  wifi_auth_mode_t encryption;                    // Encryption type
  int client_count;                               // Estimated client count
  unsigned long first_seen;                       // First detection timestamp
  unsigned long last_seen;                        // Last detection timestamp
  unsigned long packet_count;                     // Number of packets seen
  bool wps_enabled;                               // WPS support detected
  int wps_version;                                // WPS version if enabled
  uint8_t vendor_oui[3];                          // Vendor OUI
  bool is_mesh;                                   // Mesh network detected
  uint8_t beacon_interval;                        // Beacon interval (ms)
  uint16_t capability_info;                       // Capability information
  int data_rate;                                  // Max data rate seen
  uint8_t country_code[3];                        // Country code
  bool is_80211n;                                 // Supports 802.11n
  bool is_80211ac;                                // Supports 802.11ac
  uint8_t primary_channel;                        // Primary channel
  uint8_t secondary_channel;                      // Secondary channel (0=none)
  bool ssid_revealed;                             // True if SSID was revealed via probe
  unsigned long ssid_revealed_time;               // When SSID was revealed
  std::vector<mac_address_t> associated_clients;  // MACs of associated clients
} APInfo;

typedef struct {
  mac_address_t mac;           // Client MAC address
  int rssi;                    // Signal strength in dBm
  int channel;                 // Channel where seen
  String ap_bssid;             // Associated AP's BSSID
  unsigned long first_seen;    // First detection timestamp
  unsigned long last_seen;     // Last detection timestamp
  unsigned long packet_count;  // Number of packets seen
  String last_frame_type;      // Type of last seen frame
  bool is_associated;          // True if associated with AP
  String manufacturer;         // MAC vendor lookup
  int data_rate;               // Data rate in Mbps
  int probe_count;             // Number of probe requests
  bool is_handshaking;         // True if in handshake process

  // Enhanced SSID tracking
  std::vector<SSIDHistory> ssid_history;  // History of SSIDs probed
  String last_probed_ssid;                // Last SSID probed
  uint8_t last_ssid_len;                  // Length of last SSID
  bool probing_active;                    // Actively probing
  String targeted_ap;                     // AP being targeted for connection
  uint16_t authentication_algo;           // Authentication algorithm
  uint16_t auth_seq;                      // Authentication sequence
  unsigned long last_probe_time;          // Last time client sent probe
  std::vector<String> probed_aps;         // List of AP BSSIDs this client has probed
} ClientInfo;

// ===== SSID Analysis Structure =====
typedef struct {
  char ssid[33];
  uint8_t ssid_len;
  mac_address_t bssid;
  unsigned long first_seen;
  unsigned long last_seen;
  int channel;
  int rssi;
  uint16_t probe_count;
  bool is_hidden;
  bool from_probe_request;   // Seen in probe request
  bool from_beacon;          // Seen in beacon
  bool from_probe_response;  // Seen in probe response
} SSIDInfo;

// ===== Vendor OUI Database (Partial) =====
typedef struct {
  uint8_t oui[3];
  const char* vendor;
} VendorOUI;

static const VendorOUI vendor_oui_list[] = {
  { { 0x00, 0x1A, 0x11 }, "Google" },
  { { 0x00, 0x0C, 0x29 }, "VMware" },
  { { 0x00, 0x1B, 0x63 }, "Apple" },
  { { 0x00, 0x1D, 0x0F }, "Apple" },
  { { 0x00, 0x23, 0xDF }, "Apple" },
  { { 0x00, 0x25, 0x00 }, "Apple" },
  { { 0x00, 0x26, 0x08 }, "Apple" },
  { { 0x00, 0x26, 0xB0 }, "Apple" },
  { { 0x00, 0x50, 0xF2 }, "Microsoft" },
  { { 0x00, 0x1E, 0x52 }, "HTC" },
  { { 0x00, 0x1B, 0x77 }, "Nintendo" },
  { { 0x00, 0x21, 0x6A }, "LG Electronics" },
  { { 0x00, 0x1F, 0x32 }, "Sony Ericsson" },
  { { 0x00, 0x00, 0xF0 }, "Samsung" },
  { { 0x00, 0x02, 0x78 }, "Samsung" },
  { { 0x00, 0x06, 0xF6 }, "Samsung" },
  { { 0x00, 0x07, 0xAB }, "Samsung" },
  { { 0x00, 0x0C, 0xF1 }, "Samsung" },
  { { 0x00, 0x0D, 0xAE }, "Samsung" },
  { { 0x00, 0x0E, 0x6D }, "Samsung" },
  { { 0x00, 0x0F, 0x59 }, "Samsung" },
  { { 0x00, 0x11, 0x2A }, "Samsung" },
  { { 0x00, 0x12, 0x47 }, "Samsung" },
  { { 0x00, 0x12, 0xFB }, "Samsung" },
  { { 0x00, 0x13, 0x77 }, "Samsung" },
  { { 0x00, 0x14, 0x7D }, "Samsung" },
  { { 0x00, 0x15, 0x99 }, "Samsung" },
  { { 0x00, 0x15, 0xB9 }, "Samsung" },
  { { 0x00, 0x16, 0x32 }, "Samsung" },
  { { 0x00, 0x16, 0x6B }, "Samsung" },
  { { 0x00, 0x16, 0x6C }, "Samsung" },
  { { 0x00, 0x16, 0xDB }, "Samsung" },
  { { 0x00, 0x17, 0x9E }, "Samsung" },
  { { 0x00, 0x18, 0xAF }, "Samsung" },
  { { 0x00, 0x0C, 0x8A }, "Huawei" },
  { { 0x00, 0x1B, 0x74 }, "Huawei" },
  { { 0x00, 0x1E, 0x10 }, "Huawei" },
  { { 0x00, 0x25, 0x68 }, "Huawei" },
  { { 0x00, 0x26, 0x5E }, "Huawei" },
  { { 0x00, 0x18, 0x82 }, "Cisco" },
  { { 0x00, 0x1B, 0xD4 }, "Cisco" },
  { { 0x00, 0x1C, 0x0E }, "Cisco" },
  { { 0x00, 0x1D, 0x45 }, "Cisco" },
  { { 0x00, 0x21, 0x1A }, "Cisco" },
  { { 0x00, 0x24, 0x14 }, "Cisco" },
  { { 0x00, 0x50, 0x43 }, "Netgear" },
  { { 0x00, 0x1F, 0x33 }, "Netgear" },
  { { 0x00, 0x22, 0x3F }, "Netgear" },
  { { 0x00, 0x24, 0xB2 }, "Netgear" },
  { { 0x00, 0x26, 0xF2 }, "Netgear" },
  { { 0x00, 0x04, 0x96 }, "TP-Link" },
  { { 0x00, 0x17, 0x66 }, "TP-Link" },
  { { 0x00, 0x1D, 0x0F }, "TP-Link" },
  { { 0x00, 0x21, 0x27 }, "TP-Link" },
  { { 0x00, 0x23, 0xCD }, "TP-Link" },
  { { 0x00, 0x14, 0x6C }, "Belkin" },
  { { 0x00, 0x17, 0x3F }, "Belkin" },
  { { 0x00, 0x1E, 0x5A }, "Belkin" },
  { { 0x00, 0x22, 0x93 }, "Belkin" },
  { { 0x00, 0x24, 0x01 }, "Belkin" },
  { { 0x00, 0x0B, 0x86 }, "ASUS" },
  { { 0x00, 0x11, 0x2F }, "ASUS" },
  { { 0x00, 0x13, 0xD4 }, "ASUS" },
  { { 0x00, 0x15, 0xF2 }, "ASUS" },
  { { 0x00, 0x1A, 0x92 }, "ASUS" },
  { { 0x00, 0x1D, 0x60 }, "ASUS" },
  { { 0x00, 0x22, 0x15 }, "ASUS" },
  { { 0x00, 0x24, 0x8C }, "ASUS" },
  { { 0x00, 0x26, 0x18 }, "ASUS" },
  { { 0x00, 0x30, 0xBD }, "Linksys" },
  { { 0x00, 0x06, 0x25 }, "Linksys" },
  { { 0x00, 0x0C, 0x41 }, "Linksys" },
  { { 0x00, 0x12, 0x17 }, "Linksys" },
  { { 0x00, 0x14, 0xBF }, "Linksys" },
  { { 0x00, 0x16, 0xB6 }, "Linksys" },
  { { 0x00, 0x18, 0xF8 }, "Linksys" },
  { { 0x00, 0x19, 0xAA }, "Linksys" },
  { { 0x00, 0x1A, 0x70 }, "Linksys" },
  { { 0x00, 0x1C, 0x10 }, "Linksys" },
  { { 0x00, 0x90, 0x4C }, "Epic Games" },
  { { 0x00, 0x14, 0xA4 }, "Google" },
  { { 0x00, 0x1A, 0x11 }, "Google" },
  { { 0x00, 0x26, 0xAB }, "Amazon" },
  { { 0x00, 0x1C, 0x62 }, "Amazon" },
  { { 0x00, 0x22, 0x69 }, "Amazon" },
  { { 0x00, 0x25, 0x9C }, "Amazon" },
  { { 0x00, 0x1D, 0x25 }, "Intel" },
  { { 0x00, 0x13, 0xCE }, "Intel" },
  { { 0x00, 0x16, 0x6F }, "Intel" },
  { { 0x00, 0x18, 0xDE }, "Intel" },
  { { 0x00, 0x1B, 0x77 }, "Intel" },
  { { 0x00, 0x1C, 0xBF }, "Intel" },
  { { 0x00, 0x1E, 0x67 }, "Intel" },
  { { 0x00, 0x21, 0x6A }, "Intel" },
  { { 0x00, 0x22, 0xFA }, "Intel" },
  { { 0x00, 0x24, 0xD6 }, "Intel" },
  { { 0x00, 0x26, 0xC7 }, "Intel" },
  { { 0x00, 0x1F, 0x5B }, "Roku" },
  { { 0x00, 0x0D, 0x4B }, "Roku" },
  { { 0x00, 0x17, 0xAB }, "Roku" },
  { { 0x00, 0x1B, 0x11 }, "Roku" },
  { { 0x00, 0x20, 0x07 }, "Sonos" },
  { { 0x00, 0x0E, 0x58 }, "Sonos" },
  { { 0x00, 0x12, 0x5E }, "Sonos" },
  { { 0x00, 0x13, 0xEF }, "Sonos" },
  { { 0x00, 0x17, 0x88 }, "Sonos" },
  { { 0x00, 0x1B, 0x66 }, "Sonos" },
  { { 0x00, 0x1C, 0xDF }, "Sonos" },
  { { 0x00, 0x22, 0x5C }, "Philips Hue" },
  { { 0x00, 0x17, 0x88 }, "Philips Hue" },
  { { 0x00, 0x1E, 0xC0 }, "Wyze" },
  { { 0x00, 0x18, 0x02 }, "D-Link" },
  { { 0x00, 0x1B, 0x11 }, "D-Link" },
  { { 0x00, 0x1C, 0xF0 }, "D-Link" },
  { { 0x00, 0x21, 0x91 }, "D-Link" },
  { { 0x00, 0x26, 0x5A }, "D-Link" },
  { { 0x00, 0x0F, 0x3D }, "Buffalo" },
  { { 0x00, 0x14, 0xA5 }, "Buffalo" },
  { { 0x00, 0x1D, 0x73 }, "Buffalo" },
  { { 0x00, 0x21, 0x91 }, "Buffalo" },
  { { 0x00, 0x24, 0x01 }, "Buffalo" },
  { { 0x00, 0x00, 0x00 }, "Unknown" }
};

// ===== Enhanced Global Scanning State Structure =====
struct ScanState {
  bool active_ap = false;
  bool active_sta = false;
  bool enhanced_scanning = false;  // Enable enhanced features
  bool client_scanning = false;
  int current_channel = 1;
  unsigned long channel_switch_time = 0;
  unsigned long last_display = 0;
  unsigned long scan_start_time = 0;
  bool wps_detection_enabled = true;
  bool mac_filtering_enabled = true;
  bool ssid_tracking_enabled = true;  // Track SSIDs from probe requests
  bool passive_only = true;           // Always passive mode
  int min_rssi = -90;
  unsigned long channel_hop_interval = 300;
  unsigned long scan_duration = 60000;   // 1 minute default
  uint8_t scan_mode = 0;                 // 0=standard, 1=enhanced, 2=deep
  bool collect_ssid_stats = true;        // Collect SSID statistics
  bool probe_sniffing = true;            // Sniff probe requests for hidden APs
  unsigned long last_probe_check = 0;    // Last time probe cache was checked
  bool probe_debug = false;              // Debug output for probe requests
  bool enhanced_client_tracking = true;  // Enhanced client association tracking
  bool track_client_ssids = true;        // Track SSIDs probed by each client
  unsigned long last_client_scan = 0;    // Last client scan display
  int client_scan_interval = 5000;       // Display clients every 5 seconds
};

// ===== Function Prototypes =====

// === MAC Address Utilities ===
String macToString(const uint8_t* mac);
String getVendorFromMAC(const uint8_t* mac);
String getManufacturerFromMAC(const uint8_t* mac);
mac_address_t arrayToMac(const uint8_t* mac);
void macToArray(const mac_address_t& mac_struct, uint8_t* mac);

// === Frame Analysis ===
void getFrameType(const uint8_t* frame_ctrl, uint8_t* type, uint8_t* subtype);
bool isBeaconFrame(const uint8_t* frame_ctrl);
bool isProbeResponseFrame(const uint8_t* frame_ctrl);
bool isProbeRequestFrame(const uint8_t* frame_ctrl);
bool isDataFrame(const uint8_t* frame_ctrl);
bool isManagementFrame(const uint8_t* frame_ctrl);
String getFrameTypeString(uint8_t frame_type, uint8_t frame_subtype);

// === SSID Handling ===
uint8_t extractSSIDFromFrame(const uint8_t* frame, uint16_t frame_len, char* ssid_out);
uint8_t extractSSIDFromFrame(const uint8_t* frame, uint16_t frame_len, char* ssid_out,
                             uint8_t frame_type, uint8_t frame_subtype, bool* is_hidden);
String formatSSID(const char* ssid_data, uint8_t ssid_len);

// === SSID Analysis & Tracking ===
void analyzeSSIDFromProbeRequest(const uint8_t* frame, uint16_t frame_len,
                                 const uint8_t* source_mac, const uint8_t* bssid, int rssi, int channel);
void analyzeProbeRequestForSSID(ClientInfo* client, const uint8_t* frame, uint16_t frame_len);
void processProbeRequestForHiddenAPs(const uint8_t* frame, uint16_t frame_len,
                                     const uint8_t* client_mac, const uint8_t* target_bssid,
                                     int rssi, int channel);

// === MAC Address Validation ===
bool isBroadcastMAC(const uint8_t* mac);
bool isZeroMAC(const uint8_t* mac);
bool isValidClientMAC(const uint8_t* mac);
bool isMulticastMAC(const uint8_t* mac);
bool isLocallyAdministeredMAC(const uint8_t* mac);
bool compareMAC(const mac_address_t& mac1, const uint8_t* mac2);

// === Encryption Detection ===
String getEncryptionType(wifi_auth_mode_t encryptionType);
wifi_auth_mode_t determineEncryptionFromFrame(const uint8_t* frame, uint16_t frame_len);
String getCompleteEncryptionType(wifi_auth_mode_t encryptionType);

// === WPS Detection ===
bool detectWPSInBeacon(const uint8_t* frame, uint16_t frame_len);
bool detectWPSInProbeResponse(const uint8_t* frame, uint16_t frame_len);
int getWPSVersion(const uint8_t* frame, uint16_t frame_len);

// === Enhanced AP Management ===
APInfo* findOrCreateAP(const uint8_t* bssid);
bool isAlreadyPrinted(const uint8_t* bssid);
void updateAPInfo(APInfo* ap, const uint8_t* frame, uint16_t frame_len, int rssi, int channel);
void updateAPWithEnhancedInfo(APInfo* ap, const uint8_t* frame, uint16_t frame_len,
                              int rssi, int channel, uint8_t frame_subtype);
int estimateClientCount(int rssi, int channel);
bool updateHiddenAPWithProbeSSID(const uint8_t* ap_bssid, const char* ssid, uint8_t ssid_len);
void checkProbeCacheForHiddenAPs();
void updateAPClientAssociation(const uint8_t* ap_bssid, const uint8_t* client_mac);
void removeClientFromAP(const uint8_t* ap_bssid, const uint8_t* client_mac);

// === Enhanced Client Management ===
ClientInfo* findClient(const uint8_t* mac);
void updateClient(ClientInfo* client, int rssi, int channel, const String& ap_bssid, const String& frame_type);
void updateClientWithSSIDInfo(ClientInfo* client, const uint8_t* frame, uint16_t frame_len,
                              int rssi, int channel, uint8_t frame_subtype);
void addNewClient(const uint8_t* mac, int rssi, int channel, const String& ap_bssid, const String& frame_type);
void addOrUpdateClient(const uint8_t* mac, int rssi, int channel, const String& ap_bssid, const String& frame_type);
void cleanupOldClients();
void displayClients();
void displayClientDetails(const uint8_t* client_mac);
void trackClientProbedAP(const uint8_t* client_mac, const uint8_t* ap_bssid);

// === Enhanced Packet Handlers ===
void passivePacketHandler(void* buf, wifi_promiscuous_pkt_type_t type);
void enhancedPacketHandler(void* buf, wifi_promiscuous_pkt_type_t type);
void promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type);
void processEnhancedClientPacket(const wifi_promiscuous_pkt_t* packet, int rssi, int channel);

// === Display Functions ===
void displayAPs();
void displayEnhancedAPs();
void displayClientSummary();
void displayProbeStatistics();

// === Scanning Control Functions ===
bool scan_setup(String mode);
bool scan_loop();
bool startAPScan();
bool startClientScan();
void stopScan();
void initWiFiPassive();

// === Configuration Functions ===
void setScanDuration(unsigned long duration);
void setChannelHopInterval(unsigned long interval);
void setMinimumRSSI(int rssi);
void enableMACFiltering(bool enable);
void enableWPSDetection(bool enable);
void enableProbeSniffing(bool enable);
void enableProbeDebug(bool enable);
void enableEnhancedClientTracking(bool enable);
void setClientScanInterval(int interval);

// === Debug & Test Functions ===
void testRevealHiddenAPs();
void dumpProbeCache();
void dumpClientAssociations();

// === Utility Functions ===
int getAPCount();
int getClientCount();
void clearAllData();
void saveAPsToPreferences();
void loadAPsFromPreferences();

// ===== Global Variable Declarations (External) =====
extern std::vector<APInfo> ap_list;
extern std::vector<ClientInfo> client_list;
extern std::vector<SSIDInfo> ssid_list;                     // Track all unique SSIDs
extern std::vector<ProbeCache> probe_cache;                 // Cache for probe requests
extern std::vector<ClientAssociation> client_associations;  // Client-AP associations
extern APInfo aps[MAX_APS];
extern int ap_count;
extern ScanState scan;

// ===== Statistics (External) =====
extern unsigned long total_probe_requests;
extern unsigned long total_beacons;
extern unsigned long total_data_frames;
extern unsigned long total_management_frames;
extern unsigned long hidden_ap_revealed;
extern unsigned long total_client_packets;
extern unsigned long total_association_frames;

#endif  // SCAN_H