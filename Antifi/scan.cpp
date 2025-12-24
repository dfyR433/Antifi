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
#include "scan.h"

using namespace std;

// ===== Global Variable Definitions =====
vector<APInfo> ap_list;
vector<ClientInfo> client_list;
vector<SSIDInfo> ssid_list;
vector<ProbeCache> probe_cache;
vector<ClientAssociation> client_associations;
APInfo aps[MAX_APS];
int ap_count = 0;
ScanState scan;

// ===== Preferences for persistent storage =====
Preferences preferences;
const char* SCAN_PREFS_NAMESPACE = "wifi_scan";
const char* AP_COUNT_KEY = "ap_count";

// ===== Track printed networks to avoid duplicates =====
vector<String> printed_bssids;
vector<String> printed_client_macs;

// ===== Timing Variables =====
unsigned long last_scan = 0;
unsigned long last_client_cleanup = 0;
unsigned long channel_switch_time = 0;

// ===== Configuration =====
const int CHANNEL_SWITCH_INTERVAL = 300;
const int TOTAL_CHANNELS = 13;
const int MAX_CLIENT_AGE_MS = 30000;
const int CLIENT_CLEANUP_INTERVAL = 5000;
const int MINIMUM_RSSI = -90;
const int MIN_PACKET_SIZE = 24;
const int PROBE_CACHE_CHECK_INTERVAL = 1000;

// ===== Statistics =====
unsigned long total_probe_requests = 0;
unsigned long total_beacons = 0;
unsigned long total_data_frames = 0;
unsigned long total_management_frames = 0;
unsigned long hidden_ap_revealed = 0;
unsigned long total_client_packets = 0;
unsigned long total_association_frames = 0;

// ===== SSID Statistics =====
std::map<String, int> ssid_probe_counts;
std::map<String, std::vector<mac_address_t>> ssid_client_map;
std::map<String, unsigned long> ssid_last_seen;

// ===== Helper Functions =====

mac_address_t arrayToMac(const uint8_t* mac) {
    mac_address_t result;
    std::copy(mac, mac + 6, result.begin());
    return result;
}

void macToArray(const mac_address_t& mac_struct, uint8_t* mac) {
    std::copy(mac_struct.begin(), mac_struct.end(), mac);
}

String macToString(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buf);
}

String getVendorFromMAC(const uint8_t* mac) {
    for (int i = 0; i < sizeof(vendor_oui_list) / sizeof(vendor_oui_list[0]); i++) {
        if (vendor_oui_list[i].oui[0] == mac[0] &&
            vendor_oui_list[i].oui[1] == mac[1] &&
            vendor_oui_list[i].oui[2] == mac[2]) {
            return String(vendor_oui_list[i].vendor);
        }
    }
    return "Unknown";
}

bool compareMAC(const mac_address_t& mac1, const uint8_t* mac2) {
    return memcmp(mac1.data(), mac2, 6) == 0;
}

// ===== Encryption Detection Functions (Compatible with older ESP32 cores) =====
String getCompleteEncryptionType(wifi_auth_mode_t encryptionType) {
    switch (encryptionType) {
        case WIFI_AUTH_OPEN: return "Open";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA_PSK";
        case WIFI_AUTH_WPA2_PSK: return "WPA2_PSK";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2_E";
        #ifdef WIFI_AUTH_WPA3_PSK
        case WIFI_AUTH_WPA3_PSK: return "WPA3_PSK";
        #endif
        #ifdef WIFI_AUTH_WPA2_WPA3_PSK
        case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
        #endif
        #ifdef WIFI_AUTH_WAPI_PSK
        case WIFI_AUTH_WAPI_PSK: return "WAPI_PSK";
        #endif
        #ifdef WIFI_AUTH_OWE
        case WIFI_AUTH_OWE: return "OWE";
        #endif
        #ifdef WIFI_AUTH_WPA3_ENTERPRISE
        case WIFI_AUTH_WPA3_ENTERPRISE: return "WPA3_E";
        #endif
        default: return "Unknown";
    }
}

String getEncryptionType(wifi_auth_mode_t encryptionType) {
    return getCompleteEncryptionType(encryptionType);
}

// ===== MAC Address Validation =====
bool isBroadcastMAC(const uint8_t* mac) {
    return (mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
            mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF);
}

bool isZeroMAC(const uint8_t* mac) {
    return (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
            mac[3] == 0 && mac[4] == 0 && mac[5] == 0);
}

bool isValidClientMAC(const uint8_t* mac) {
    if (!mac) return false;
    if (isBroadcastMAC(mac)) return false;
    if (isZeroMAC(mac)) return false;
    
    if (scan.mac_filtering_enabled && (mac[0] & 0x01)) {
        return false;
    }
    
    return true;
}

bool isMulticastMAC(const uint8_t* mac) {
    return (mac[0] & 0x01) != 0;
}

bool isLocallyAdministeredMAC(const uint8_t* mac) {
    return (mac[0] & 0x02) != 0;
}

// ===== Frame Analysis =====
void getFrameType(const uint8_t* frame_ctrl, uint8_t* type, uint8_t* subtype) {
    *type = (frame_ctrl[0] & 0x0C) >> 2;
    *subtype = (frame_ctrl[0] & 0xF0) >> 4;
}

bool isBeaconFrame(const uint8_t* frame_ctrl) {
    uint8_t type, subtype;
    getFrameType(frame_ctrl, &type, &subtype);
    return (type == FRAME_TYPE_MANAGEMENT && subtype == SUBTYPE_BEACON);
}

bool isProbeResponseFrame(const uint8_t* frame_ctrl) {
    uint8_t type, subtype;
    getFrameType(frame_ctrl, &type, &subtype);
    return (type == FRAME_TYPE_MANAGEMENT && subtype == SUBTYPE_PROBE_RESPONSE);
}

bool isProbeRequestFrame(const uint8_t* frame_ctrl) {
    uint8_t type, subtype;
    getFrameType(frame_ctrl, &type, &subtype);
    return (type == FRAME_TYPE_MANAGEMENT && subtype == SUBTYPE_PROBE_REQUEST);
}

bool isDataFrame(const uint8_t* frame_ctrl) {
    uint8_t type, subtype;
    getFrameType(frame_ctrl, &type, &subtype);
    return (type == FRAME_TYPE_DATA);
}

bool isManagementFrame(const uint8_t* frame_ctrl) {
    uint8_t type, subtype;
    getFrameType(frame_ctrl, &type, &subtype);
    return (type == FRAME_TYPE_MANAGEMENT);
}

String getFrameTypeString(uint8_t frame_type, uint8_t frame_subtype) {
    if (frame_type == FRAME_TYPE_MANAGEMENT) {
        switch(frame_subtype) {
            case SUBTYPE_PROBE_REQUEST: return "PROBE_REQ";
            case SUBTYPE_PROBE_RESPONSE: return "PROBE_RESP";
            case SUBTYPE_BEACON: return "BEACON";
            case SUBTYPE_ASSOCIATION_REQUEST: return "ASSOC_REQ";
            case SUBTYPE_ASSOCIATION_RESPONSE: return "ASSOC_RESP";
            case SUBTYPE_AUTHENTICATION: return "AUTH";
            case SUBTYPE_DEAUTHENTICATION: return "DEAUTH";
            case SUBTYPE_DISASSOCIATION: return "DISASSOC";
            case SUBTYPE_REASSOCIATION_REQUEST: return "REASSOC_REQ";
            case SUBTYPE_REASSOCIATION_RESPONSE: return "REASSOC_RESP";
            default: return "MGMT";
        }
    } else if (frame_type == FRAME_TYPE_DATA) {
        return "DATA";
    } else if (frame_type == FRAME_TYPE_CONTROL) {
        return "CTRL";
    }
    return "UNKNOWN";
}

// ===== Enhanced SSID Extraction =====
uint8_t extractSSIDFromFrame(const uint8_t* frame, uint16_t frame_len, char* ssid_out, 
                           uint8_t frame_type, uint8_t frame_subtype, bool* is_hidden) {
    uint8_t ssid_len = 0;
    if (is_hidden) *is_hidden = false;
    
    if (frame_len < 36) return 0;
    
    uint16_t tagged_params_offset = 36;
    
    if (frame_subtype == SUBTYPE_BEACON) {
        tagged_params_offset = MAC_HEADER_SIZE + BEACON_FIXED_PARAMS;
    } 
    else if (frame_subtype == SUBTYPE_PROBE_RESPONSE) {
        tagged_params_offset = MAC_HEADER_SIZE + 12;
    }
    else if (frame_subtype == SUBTYPE_PROBE_REQUEST) {
        tagged_params_offset = MAC_HEADER_SIZE + 12;
    }
    
    if (frame_len < tagged_params_offset) return 0;
    
    const uint8_t* tagged_params = frame + tagged_params_offset;
    uint16_t remaining_len = frame_len - tagged_params_offset;
    const uint8_t* ptr = tagged_params;
    
    while (ptr < tagged_params + remaining_len && ptr[0] != 0xFF) {
        uint8_t element_id = ptr[0];
        uint8_t element_len = ptr[1];
        
        if (element_id == 0) { // SSID element
            ssid_len = element_len;
            
            if (element_len == 0) {
                // Empty SSID = hidden network
                if (is_hidden) *is_hidden = true;
                if (ssid_out) {
                    strcpy(ssid_out, "[Hidden]");
                }
                return 0;
            } else if (element_len <= 32) {
                if (ssid_out) {
                    memcpy(ssid_out, ptr + 2, element_len);
                    ssid_out[element_len] = '\0';
                    
                    // Check if SSID is all zeros (hidden network)
                    bool all_zeros = true;
                    for (int i = 0; i < element_len; i++) {
                        if (ssid_out[i] != 0) {
                            all_zeros = false;
                            break;
                        }
                    }
                    
                    if (all_zeros) {
                        // Hidden network - SSID with all zeros
                        if (is_hidden) *is_hidden = true;
                        strcpy(ssid_out, "[Hidden]");
                        return element_len;
                    }
                    
                    // Check for broadcast probe requests
                    if (frame_subtype == SUBTYPE_PROBE_REQUEST && 
                        element_len == 1 && ssid_out[0] == 0) {
                        if (is_hidden) *is_hidden = true;
                        strcpy(ssid_out, "[Hidden]");
                        return 1; // Actual length is 1
                    }
                }
                return element_len;
            }
            break;
        }
        
        if (element_len == 0 || element_len > 255) {
            break;
        }
        ptr += 2 + element_len;
        
        if (ptr > tagged_params + remaining_len) {
            break;
        }
    }
    
    return 0;
}

// Overload for backward compatibility
uint8_t extractSSIDFromFrame(const uint8_t* frame, uint16_t frame_len, char* ssid_out) {
    bool is_hidden = false;
    return extractSSIDFromFrame(frame, frame_len, ssid_out, FRAME_TYPE_MANAGEMENT, SUBTYPE_BEACON, &is_hidden);
}

String formatSSID(const char* ssid_data, uint8_t ssid_len) {
    if (ssid_len == 0 || ssid_data == NULL) {
        return "[Hidden]";
    }
    
    // Check if all bytes are zero
    bool all_zeros = true;
    for (int i = 0; i < ssid_len && i < 32; i++) {
        if (ssid_data[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    
    if (all_zeros) {
        return "[Hidden]";
    }
    
    // Check if all characters are printable ASCII (32-126)
    bool printable = true;
    for (int i = 0; i < ssid_len && i < 32; i++) {
        if (ssid_data[i] < 32 || ssid_data[i] > 126) {
            printable = false;
            break;
        }
    }
    
    if (printable) {
        char printable_str[33] = {0};
        memcpy(printable_str, ssid_data, min((int)ssid_len, 32));
        return String(printable_str);
    }
    
    // Show hex representation for non-printable SSIDs
    char hex_str[65] = {0};
    int len_to_show = min((int)ssid_len, 4);
    for (int i = 0; i < len_to_show; i++) {
        sprintf(hex_str + (i * 2), "%02X", (uint8_t)ssid_data[i]);
    }
    if (ssid_len > 4) {
        strcat(hex_str, "..");
    }
    
    return String(hex_str);
}

// ===== Complete Encryption Detection (Compatible) =====
wifi_auth_mode_t determineEncryptionFromFrame(const uint8_t* frame, uint16_t frame_len) {
    if (frame_len < BEACON_SSID_OFFSET) return WIFI_AUTH_OPEN;
    
    const uint8_t* tagged_params = frame + BEACON_SSID_OFFSET;
    uint16_t remaining_len = frame_len - BEACON_SSID_OFFSET;
    const uint8_t* ptr = tagged_params;
    
    // Skip the SSID element (element ID 0)
    if (remaining_len >= 2 && ptr[0] == 0) {
        uint8_t ssid_len = ptr[1];
        ptr += 2 + ssid_len;
        remaining_len -= (2 + ssid_len);
    }
    
    bool has_wpa = false;
    bool has_rsn = false;
    bool has_wep = false;
    bool has_wpa3 = false;
    bool has_wpa2_enterprise = false;
    bool has_wapi = false;
    
    while (ptr < tagged_params + remaining_len && ptr[0] != 0xFF) {
        uint8_t element_id = ptr[0];
        uint8_t element_len = ptr[1];
        
        if (element_len == 0 || element_len > 255 || ptr + 2 + element_len > frame + frame_len) {
            break;
        }
        
        // RSN element (0x30)
        if (element_id == 0x30 && element_len >= 2) {
            has_rsn = true;
            
            if (element_len >= 22) {
                const uint8_t* rsn_data = ptr + 2;
                uint16_t rsn_len = element_len;
                
                if (rsn_len >= 10) {
                    uint16_t akm_count = (rsn_data[8] << 8) | rsn_data[9];
                    if (rsn_len >= 10 + akm_count * 4) {
                        for (int i = 0; i < akm_count; i++) {
                            uint32_t akm_oui = (rsn_data[10 + i*4] << 16) | 
                                              (rsn_data[11 + i*4] << 8) | 
                                               rsn_data[12 + i*4];
                            uint8_t akm_type = rsn_data[13 + i*4];
                            
                            if (akm_oui == 0x000FAC) {
                                if (akm_type == 1 || akm_type == 2 || akm_type == 6) {
                                    has_wpa2_enterprise = true;
                                } else if (akm_type == 8) {
                                    has_wpa3 = true; // SAE
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Vendor specific (0xDD)
        if (element_id == 0xDD && element_len >= 8) {
            uint32_t oui = (ptr[2] << 16) | (ptr[3] << 8) | ptr[4];
            
            // WPA (00:50:F2:01)
            if (oui == 0x0050F2 && ptr[5] == 0x01) {
                has_wpa = true;
            }
            
            // WAPI (00:14:72:01) - check if supported
            #ifdef WIFI_AUTH_WAPI_PSK
            else if (oui == 0x001472 && ptr[5] == 0x01) {
                has_wapi = true;
            }
            #endif
        }
        
        ptr += 2 + element_len;
        
        if (ptr > tagged_params + remaining_len) {
            break;
        }
    }
    
    // Check for WEP in capability info (fixed parameters)
    if (frame_len >= MAC_HEADER_SIZE + 12) {
        const uint8_t* fixed_params = frame + MAC_HEADER_SIZE;
        if (fixed_params[10] & 0x10) {
            has_wep = true;
        }
    }
    
    // Determine encryption type with priority (most secure first)
    #ifdef WIFI_AUTH_WPA2_WPA3_PSK
    if (has_wpa3 && has_rsn) return WIFI_AUTH_WPA2_WPA3_PSK;
    #endif
    
    #ifdef WIFI_AUTH_WPA3_PSK
    if (has_wpa3) return WIFI_AUTH_WPA3_PSK;
    #endif
    
    if (has_wpa2_enterprise) return WIFI_AUTH_WPA2_ENTERPRISE;
    if (has_rsn && has_wpa) return WIFI_AUTH_WPA_WPA2_PSK;
    if (has_rsn) return WIFI_AUTH_WPA2_PSK;
    if (has_wpa) return WIFI_AUTH_WPA_PSK;
    
    #ifdef WIFI_AUTH_WAPI_PSK
    if (has_wapi) return WIFI_AUTH_WAPI_PSK;
    #endif
    
    if (has_wep) return WIFI_AUTH_WEP;
    
    return WIFI_AUTH_OPEN;
}

// ===== Enhanced Probe Request Handling for Hidden APs =====
void processProbeRequestForHiddenAPs(const uint8_t* frame, uint16_t frame_len,
                                   const uint8_t* client_mac, const uint8_t* target_bssid,
                                   int rssi, int channel) {
    if (!scan.probe_sniffing) return;
    
    char ssid[33] = {0};
    bool is_hidden = false;
    uint8_t ssid_len = extractSSIDFromFrame(frame, frame_len, ssid,
                                          FRAME_TYPE_MANAGEMENT, SUBTYPE_PROBE_REQUEST, &is_hidden);
    
    // Debug output
    if (scan.probe_debug && !is_hidden && ssid_len > 0) {
        String target_str = isBroadcastMAC(target_bssid) ? "Broadcast" : macToString(target_bssid);
        Serial.printf("[Probe] Client: %s -> SSID: %s (Len: %d) -> Target: %s (RSSI: %d, Ch: %d)\n",
                     macToString(client_mac).c_str(),
                     ssid,
                     ssid_len,
                     target_str.c_str(),
                     rssi,
                     channel);
    }
    
    // Skip if SSID is hidden in probe request
    if (is_hidden || ssid_len == 0 || strcmp(ssid, "[Hidden]") == 0) {
        return;
    }
    
    // Cache the probe request
    ProbeCache probe;
    probe.client_mac = arrayToMac(client_mac);
    strncpy(probe.ssid, ssid, 32);
    probe.ssid_len = ssid_len;
    probe.timestamp = millis();
    probe.rssi = rssi;
    probe.channel = channel;
    probe.is_hidden = false;
    probe.target_bssid = arrayToMac(target_bssid);
    
    // Check if this probe is directed to a specific AP
    if (!isBroadcastMAC(target_bssid) && !isZeroMAC(target_bssid)) {
        // Directed probe - try to update AP directly
        if (updateHiddenAPWithProbeSSID(target_bssid, ssid, ssid_len)) {
            if (scan.probe_debug) {
                Serial.printf("[Direct Reveal] AP %s -> SSID: %s via directed probe from %s\n",
                            macToString(target_bssid).c_str(),
                            ssid,
                            macToString(client_mac).c_str());
            }
        }
    }
    
    // Add to cache
    probe_cache.push_back(probe);
    
    // Limit cache size
    if (probe_cache.size() > MAX_PROBE_CACHE) {
        probe_cache.erase(probe_cache.begin());
    }
    
    // Track client probed AP
    trackClientProbedAP(client_mac, target_bssid);
}

// ===== Update Hidden AP with SSID from Probe Request =====
bool updateHiddenAPWithProbeSSID(const uint8_t* ap_bssid, const char* ssid, uint8_t ssid_len) {
    for (int i = 0; i < ap_count; ++i) {
        if (memcmp(aps[i].bssid.data(), ap_bssid, 6) == 0) {
            // Found the AP, check if it's hidden
            if (aps[i].hidden) {
                // Update AP with revealed SSID
                strncpy(aps[i].ssid, ssid, 32);
                aps[i].ssid_len = ssid_len;
                aps[i].original_ssid_len = ssid_len;
                aps[i].hidden = false;
                aps[i].ssid_known = true;
                aps[i].ssid_revealed = true;
                aps[i].ssid_revealed_time = millis();
                
                // Update AP list if exists
                for (auto& ap : ap_list) {
                    if (memcmp(ap.bssid.data(), ap_bssid, 6) == 0) {
                        strncpy(ap.ssid, ssid, 32);
                        ap.ssid_len = ssid_len;
                        ap.original_ssid_len = ssid_len;
                        ap.hidden = false;
                        ap.ssid_known = true;
                        break;
                    }
                }
                
                hidden_ap_revealed++;
                
                // Print reveal message
                Serial.printf("[+] Hidden AP %s revealed -> SSID: %s (Len: %d)\n",
                            macToString(ap_bssid).c_str(),
                            ssid,
                            ssid_len);
                return true;
            }
            break;
        }
    }
    return false;
}

// ===== Check Probe Cache for Hidden APs =====
void checkProbeCacheForHiddenAPs() {
    unsigned long current_time = millis();
    
    // Remove old cache entries (older than 30 seconds)
    probe_cache.erase(
        remove_if(probe_cache.begin(), probe_cache.end(),
            [current_time](const ProbeCache& probe) {
                return (current_time - probe.timestamp) > 30000;
            }),
        probe_cache.end()
    );
    
    // Check if any hidden APs match cached probe SSIDs
    for (int i = 0; i < ap_count; ++i) {
        if (aps[i].hidden && (current_time - aps[i].last_seen) <= 30000) {
            String ap_bssid_str = macToString(aps[i].bssid.data());
            
            // Method 1: Check if any client is associated with this AP
            for (const auto& client : client_list) {
                if (client.is_associated && client.ap_bssid == ap_bssid_str) {
                    // Check probe cache for this client
                    for (const auto& probe : probe_cache) {
                        if (compareMAC(probe.client_mac, client.mac.data())) {
                            if (!probe.is_hidden && probe.ssid_len > 0) {
                                if (updateHiddenAPWithProbeSSID(aps[i].bssid.data(), probe.ssid, probe.ssid_len)) {
                                    if (scan.probe_debug) {
                                        Serial.printf("[Assoc Reveal] AP %s -> SSID: %s via client %s\n",
                                                    ap_bssid_str.c_str(),
                                                    probe.ssid,
                                                    macToString(client.mac.data()).c_str());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // Method 2: Check broadcast probes that might be for this AP
            // Some clients send broadcast probes when scanning
            for (const auto& probe : probe_cache) {
                // If probe target is broadcast (FF:FF:FF:FF:FF:FF) or zero
                uint8_t target_bssid[6];
                macToArray(probe.target_bssid, target_bssid);
                if (isBroadcastMAC(target_bssid) || isZeroMAC(target_bssid)) {
                    // Check if we have any clue this might be for our hidden AP
                    // For now, just store for potential matching
                    if (!probe.is_hidden && probe.ssid_len > 0) {
                        if (scan.probe_debug) {
                            Serial.printf("[Broadcast Probe] Client: %s -> SSID: %s (might be for hidden APs)\n",
                                         macToString(probe.client_mac.data()).c_str(),
                                         probe.ssid);
                        }
                    }
                }
            }
        }
    }
}

// ===== Analyze SSID from Probe Request =====
void analyzeSSIDFromProbeRequest(const uint8_t* frame, uint16_t frame_len, 
                               const uint8_t* source_mac, const uint8_t* bssid, int rssi, int channel) {
    if (!scan.ssid_tracking_enabled) return;
    
    char ssid[33] = {0};
    bool is_hidden = false;
    uint8_t ssid_len = extractSSIDFromFrame(frame, frame_len, ssid, 
                                          FRAME_TYPE_MANAGEMENT, SUBTYPE_PROBE_REQUEST, &is_hidden);
    
    if (ssid_len == 0 && strlen(ssid) == 0) {
        strcpy(ssid, "[Hidden]");
        is_hidden = true;
    }
    
    String ssid_str = String(ssid);
    
    // Update probe count for this SSID
    if (ssid_probe_counts.find(ssid_str) == ssid_probe_counts.end()) {
        ssid_probe_counts[ssid_str] = 1;
    } else {
        ssid_probe_counts[ssid_str]++;
    }
    
    ssid_last_seen[ssid_str] = millis();
    
    // Track which clients are probing this SSID
    mac_address_t client_mac = arrayToMac(source_mac);
    if (ssid_client_map.find(ssid_str) == ssid_client_map.end()) {
        std::vector<mac_address_t> clients;
        clients.push_back(client_mac);
        ssid_client_map[ssid_str] = clients;
    } else {
        bool found = false;
        std::vector<mac_address_t>& clients = ssid_client_map[ssid_str];
        for (const auto& existing_mac : clients) {
            if (compareMAC(existing_mac, source_mac)) {
                found = true;
                break;
            }
        }
        if (!found) {
            clients.push_back(client_mac);
        }
    }
    
    // Update SSID list
    bool ssid_found = false;
    for (auto& ssid_info : ssid_list) {
        if (strcmp(ssid_info.ssid, ssid) == 0 && ssid_info.ssid_len == ssid_len) {
            ssid_info.last_seen = millis();
            ssid_info.probe_count++;
            ssid_info.from_probe_request = true;
            ssid_found = true;
            break;
        }
    }
    
    if (!ssid_found) {
        SSIDInfo new_ssid;
        strncpy(new_ssid.ssid, ssid, 32);
        new_ssid.ssid_len = ssid_len;
        new_ssid.bssid = arrayToMac(bssid);
        new_ssid.first_seen = millis();
        new_ssid.last_seen = millis();
        new_ssid.channel = channel;
        new_ssid.rssi = rssi;
        new_ssid.probe_count = 1;
        new_ssid.is_hidden = is_hidden;
        new_ssid.from_probe_request = true;
        new_ssid.from_beacon = false;
        new_ssid.from_probe_response = false;
        
        ssid_list.push_back(new_ssid);
        
        if (ssid_list.size() > 100) {
            unsigned long oldest = millis();
            size_t oldest_idx = 0;
            for (size_t i = 0; i < ssid_list.size(); i++) {
                if (ssid_list[i].last_seen < oldest) {
                    oldest = ssid_list[i].last_seen;
                    oldest_idx = i;
                }
            }
            ssid_list.erase(ssid_list.begin() + oldest_idx);
        }
    }
}

// ===== WPS Detection =====
bool detectWPSInBeacon(const uint8_t* frame, uint16_t frame_len) {
    if (frame_len < BEACON_SSID_OFFSET) return false;
    
    const uint8_t* tagged_params = frame + BEACON_SSID_OFFSET;
    uint16_t remaining_len = frame_len - BEACON_SSID_OFFSET;
    const uint8_t* ptr = tagged_params;
    
    // Skip the SSID element (element ID 0)
    if (remaining_len >= 2 && ptr[0] == 0) {
        uint8_t ssid_len = ptr[1];
        ptr += 2 + ssid_len;
        remaining_len -= (2 + ssid_len);
    }
    
    while (ptr < tagged_params + remaining_len && ptr[0] != 0xFF) {
        uint8_t element_id = ptr[0];
        uint8_t element_len = ptr[1];
        
        if (element_len == 0 || element_len > 255 || ptr + 2 + element_len > frame + frame_len) {
            break;
        }
        
        if (element_id == 0xDD && element_len >= 8) {
            // Check for WPS OUI: 00:50:F2
            if (ptr[2] == 0x00 && ptr[3] == 0x50 && ptr[4] == 0xF2) {
                // Type 0x04 = WPS, Type 0x05 = P2P (which also indicates WPS)
                if (ptr[5] == 0x04 || ptr[5] == 0x05) {
                    return true;
                }
            }
        }
        
        ptr += 2 + element_len;
        
        if (ptr > tagged_params + remaining_len) {
            break;
        }
    }
    
    return false;
}

bool detectWPSInProbeResponse(const uint8_t* frame, uint16_t frame_len) {
    return detectWPSInBeacon(frame, frame_len);
}

int getWPSVersion(const uint8_t* frame, uint16_t frame_len) {
    if (frame_len < BEACON_SSID_OFFSET) return 0;
    
    const uint8_t* tagged_params = frame + BEACON_SSID_OFFSET;
    uint16_t remaining_len = frame_len - BEACON_SSID_OFFSET;
    const uint8_t* ptr = tagged_params;
    
    // Skip the SSID element (element ID 0)
    if (remaining_len >= 2 && ptr[0] == 0) {
        uint8_t ssid_len = ptr[1];
        ptr += 2 + ssid_len;
        remaining_len -= (2 + ssid_len);
    }
    
    while (ptr < tagged_params + remaining_len && ptr[0] != 0xFF) {
        uint8_t element_id = ptr[0];
        uint8_t element_len = ptr[1];
        
        if (element_len == 0 || element_len > 255 || ptr + 2 + element_len > frame + frame_len) {
            break;
        }
        
        if (element_id == 0xDD && element_len >= 10) {
            if (ptr[2] == 0x00 && ptr[3] == 0x50 && ptr[4] == 0xF2) {
                if (ptr[5] == 0x04 || ptr[5] == 0x05) {
                    for (int i = 6; i < element_len - 1; i += 2) {
                        if (ptr[i] == 0x10 && ptr[i+1] == 0x4A) {
                            if (i + 4 < element_len) {
                                uint16_t version = (ptr[i+2] << 8) | ptr[i+3];
                                if (version >= 0x20) return 2;
                                if (version >= 0x10) return 1;
                            }
                        }
                    }
                    return 1;
                }
            }
        }
        
        ptr += 2 + element_len;
        
        if (ptr > tagged_params + remaining_len) {
            break;
        }
    }
    
    return 0;
}

// ===== AP Management =====
APInfo* findOrCreateAP(const uint8_t* bssid) {
    for (int i = 0; i < ap_count; ++i) {
        if (memcmp(aps[i].bssid.data(), bssid, 6) == 0) {
            return &aps[i];
        }
    }
    
    if (ap_count >= MAX_APS) {
        unsigned long oldest_time = millis();
        int oldest_index = -1;
        
        for (int i = 0; i < ap_count; ++i) {
            if (aps[i].last_seen < oldest_time) {
                oldest_time = aps[i].last_seen;
                oldest_index = i;
            }
        }
        
        if (oldest_index >= 0) {
            aps[oldest_index].bssid = arrayToMac(bssid);
            APInfo* new_ap = &aps[oldest_index];
            
            memset(new_ap->ssid, 0, 33);
            new_ap->ssid_len = 0;
            new_ap->original_ssid_len = 0;
            new_ap->ssid_known = false;
            new_ap->hidden = false;
            new_ap->rssi = INT_MIN;
            new_ap->channel = 0;
            new_ap->encryption = WIFI_AUTH_OPEN;
            new_ap->client_count = 0;
            new_ap->first_seen = millis();
            new_ap->last_seen = millis();
            new_ap->packet_count = 0;
            new_ap->wps_enabled = false;
            new_ap->wps_version = 0;
            memset(new_ap->vendor_oui, 0, 3);
            new_ap->is_mesh = false;
            new_ap->beacon_interval = 0;
            new_ap->capability_info = 0;
            new_ap->data_rate = 0;
            memset(new_ap->country_code, 0, 3);
            new_ap->is_80211n = false;
            new_ap->is_80211ac = false;
            new_ap->primary_channel = 0;
            new_ap->secondary_channel = 0;
            new_ap->ssid_revealed = false;
            new_ap->ssid_revealed_time = 0;
            new_ap->associated_clients.clear();
            
            return new_ap;
        }
        return nullptr;
    }
    
    APInfo* new_ap = &aps[ap_count++];
    new_ap->bssid = arrayToMac(bssid);
    memset(new_ap->ssid, 0, 33);
    new_ap->ssid_len = 0;
    new_ap->original_ssid_len = 0;
    new_ap->ssid_known = false;
    new_ap->hidden = false;
    new_ap->rssi = INT_MIN;
    new_ap->channel = 0;
    new_ap->encryption = WIFI_AUTH_OPEN;
    new_ap->client_count = 0;
    new_ap->first_seen = millis();
    new_ap->last_seen = millis();
    new_ap->packet_count = 0;
    new_ap->wps_enabled = false;
    new_ap->wps_version = 0;
    memset(new_ap->vendor_oui, 0, 3);
    new_ap->is_mesh = false;
    new_ap->beacon_interval = 0;
    new_ap->capability_info = 0;
    new_ap->data_rate = 0;
    memset(new_ap->country_code, 0, 3);
    new_ap->is_80211n = false;
    new_ap->is_80211ac = false;
    new_ap->primary_channel = 0;
    new_ap->secondary_channel = 0;
    new_ap->ssid_revealed = false;
    new_ap->ssid_revealed_time = 0;
    new_ap->associated_clients.clear();
    
    return new_ap;
}

bool isAlreadyPrinted(const uint8_t* bssid) {
    String current_bssid = macToString(bssid);
    return find(printed_bssids.begin(), printed_bssids.end(), current_bssid) != printed_bssids.end();
}

// ===== Fixed: Correct SSID Handling for Hidden APs =====
void updateAPInfo(APInfo* ap, const uint8_t* frame, uint16_t frame_len, int rssi, int channel) {
    if (rssi > 0) {
        if (rssi > 127) {
            rssi = -((int8_t)rssi);
        } else {
            rssi = -rssi;
        }
    }
    
    if (rssi > 0) rssi = -30;
    if (rssi < -100) rssi = -100;
    
    if (ap->packet_count == 0) {
        ap->rssi = rssi;
    } else {
        // Weighted average for RSSI
        ap->rssi = (ap->rssi * 4 + rssi) / 5;
    }
    
    ap->channel = channel;
    ap->last_seen = millis();
    ap->packet_count++;
    
    // Extract SSID with hidden detection
    bool is_hidden = false;
    uint8_t extracted_len = extractSSIDFromFrame(frame, frame_len, ap->ssid, 
                                               FRAME_TYPE_MANAGEMENT, SUBTYPE_BEACON, &is_hidden);
    
    // Store the original extracted length
    ap->original_ssid_len = extracted_len;
    
    // Check if SSID is all zeros (but has length)
    bool all_zeros = false;
    if (extracted_len > 0) {
        all_zeros = true;
        for (int i = 0; i < extracted_len; i++) {
            if (ap->ssid[i] != 0) {
                all_zeros = false;
                break;
            }
        }
    }
    
    // Mark as hidden if empty, all zeros, or detected as hidden
    if (extracted_len == 0 || all_zeros || is_hidden) {
        ap->hidden = true;
        strncpy(ap->ssid, "[Hidden]", 32);
        ap->ssid_len = 8;  // Length of "[Hidden]" placeholder
    } else {
        ap->hidden = false;
        ap->ssid_known = true;
        ap->ssid_len = extracted_len;
        ap->ssid[extracted_len] = '\0';  // Ensure null termination
    }
    
    // Check for WPS if enabled
    if (scan.wps_detection_enabled) {
        ap->wps_enabled = detectWPSInBeacon(frame, frame_len);
        if (ap->wps_enabled) {
            ap->wps_version = getWPSVersion(frame, frame_len);
        }
    }
    
    ap->encryption = determineEncryptionFromFrame(frame, frame_len);
    
    // Extract vendor OUI from MAC
    memcpy(ap->vendor_oui, ap->bssid.data(), 3);
}

// ===== Enhanced AP Scanning =====
void updateAPWithEnhancedInfo(APInfo* ap, const uint8_t* frame, uint16_t frame_len, 
                            int rssi, int channel, uint8_t frame_subtype) {
    updateAPInfo(ap, frame, frame_len, rssi, channel);
    
    if (frame_subtype == SUBTYPE_BEACON || frame_subtype == SUBTYPE_PROBE_RESPONSE) {
        // Additional beacon/probe response analysis
        if (frame_len >= MAC_HEADER_SIZE + 12) {
            const uint8_t* fixed_params = frame + MAC_HEADER_SIZE;
            ap->beacon_interval = (fixed_params[0] << 8) | fixed_params[1];
            ap->capability_info = (fixed_params[2] << 8) | fixed_params[3];
        }
    }
    
    ap->data_rate = max(ap->data_rate, 54);
}

// ===== Client-AP Association Management =====
void updateAPClientAssociation(const uint8_t* ap_bssid, const uint8_t* client_mac) {
    mac_address_t ap_mac = arrayToMac(ap_bssid);
    mac_address_t client_mac_struct = arrayToMac(client_mac);
    
    // Find the AP
    for (int i = 0; i < ap_count; ++i) {
        if (compareMAC(aps[i].bssid, ap_bssid)) {
            // Check if client already in list
            bool found = false;
            for (const auto& client : aps[i].associated_clients) {
                if (compareMAC(client, client_mac)) {
                    found = true;
                    break;
                }
            }
            
            // Add client if not found
            if (!found) {
                aps[i].associated_clients.push_back(client_mac_struct);
                
                // Limit associated clients
                if (aps[i].associated_clients.size() > 20) {
                    aps[i].associated_clients.erase(aps[i].associated_clients.begin());
                }
            }
            break;
        }
    }
    
    // Update client association list
    bool found_assoc = false;
    for (auto& assoc : client_associations) {
        if (compareMAC(assoc.client_mac, client_mac)) {
            assoc.ap_bssid = ap_mac;
            assoc.last_associated = millis();
            assoc.association_count++;
            found_assoc = true;
            break;
        }
    }
    
    if (!found_assoc) {
        ClientAssociation new_assoc;
        new_assoc.client_mac = client_mac_struct;
        new_assoc.ap_bssid = ap_mac;
        new_assoc.first_associated = millis();
        new_assoc.last_associated = millis();
        new_assoc.association_count = 1;
        client_associations.push_back(new_assoc);
    }
}

void removeClientFromAP(const uint8_t* ap_bssid, const uint8_t* client_mac) {
    for (int i = 0; i < ap_count; ++i) {
        if (compareMAC(aps[i].bssid, ap_bssid)) {
            // Remove client from AP's list
            auto& clients = aps[i].associated_clients;
            clients.erase(
                remove_if(clients.begin(), clients.end(),
                    [client_mac](const mac_address_t& client) {
                        return compareMAC(client, client_mac);
                    }),
                clients.end()
            );
            break;
        }
    }
}

// ===== Client Management =====
ClientInfo* findClient(const uint8_t* mac) {
    for (auto& client : client_list) {
        if (compareMAC(client.mac, mac)) {
            return &client;
        }
    }
    return nullptr;
}

void trackClientProbedAP(const uint8_t* client_mac, const uint8_t* ap_bssid) {
    ClientInfo* client = findClient(client_mac);
    if (client) {
        String ap_str = macToString(ap_bssid);
        if (ap_str != "00:00:00:00:00:00" && ap_str != "FF:FF:FF:FF:FF:FF") {
            // Check if already in list
            bool found = false;
            for (const auto& probed : client->probed_aps) {
                if (probed == ap_str) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                client->probed_aps.push_back(ap_str);
                // Keep only last 10 probed APs
                if (client->probed_aps.size() > 10) {
                    client->probed_aps.erase(client->probed_aps.begin());
                }
            }
        }
    }
}

void updateClient(ClientInfo* client, int rssi, int channel, 
                  const String& ap_bssid, const String& frame_type) {
    if (rssi > 0) {
        if (rssi > 127) {
            rssi = -((int8_t)rssi);
        } else {
            rssi = -rssi;
        }
    }
    
    if (rssi > 0) rssi = -30;
    if (rssi < -100) rssi = -100;
    
    if (client->packet_count < 5) {
        client->rssi = (client->rssi + rssi) / 2;
    } else {
        client->rssi = (client->rssi * 7 + rssi * 3) / 10;
    }
    
    client->channel = channel;
    client->last_seen = millis();
    
    if (ap_bssid != "00:00:00:00:00:00" && ap_bssid != "N/A") {
        // Update client-AP association
        if (client->ap_bssid != ap_bssid) {
            // Client changed APs
            if (client->is_associated && client->ap_bssid != "N/A") {
                // Remove from old AP
                uint8_t old_ap_bssid[6];
                sscanf(client->ap_bssid.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                      &old_ap_bssid[0], &old_ap_bssid[1], &old_ap_bssid[2],
                      &old_ap_bssid[3], &old_ap_bssid[4], &old_ap_bssid[5]);
                removeClientFromAP(old_ap_bssid, client->mac.data());
            }
            
            // Add to new AP
            client->ap_bssid = ap_bssid;
            client->is_associated = true;
            
            uint8_t new_ap_bssid[6];
            sscanf(ap_bssid.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &new_ap_bssid[0], &new_ap_bssid[1], &new_ap_bssid[2],
                  &new_ap_bssid[3], &new_ap_bssid[4], &new_ap_bssid[5]);
            updateAPClientAssociation(new_ap_bssid, client->mac.data());
        }
    }
    
    if (!frame_type.isEmpty()) {
        client->last_frame_type = frame_type;
    }
    
    client->packet_count++;
    client->manufacturer = getVendorFromMAC(client->mac.data());
    
    if (frame_type == "PROBE_REQ") {
        client->probe_count++;
        client->last_probe_time = millis();
    }
}

void updateClientWithSSIDInfo(ClientInfo* client, const uint8_t* frame, uint16_t frame_len,
                            int rssi, int channel, uint8_t frame_subtype) {
    updateClient(client, rssi, channel, "N/A", "PROBE_REQ");
    
    if (frame_subtype == SUBTYPE_PROBE_REQUEST) {
        analyzeProbeRequestForSSID(client, frame, frame_len);
    }
}

void analyzeProbeRequestForSSID(ClientInfo* client, const uint8_t* frame, uint16_t frame_len) {
    char ssid[33] = {0};
    bool is_hidden = false;
    uint8_t ssid_len = extractSSIDFromFrame(frame, frame_len, ssid,
                                          FRAME_TYPE_MANAGEMENT, SUBTYPE_PROBE_REQUEST, &is_hidden);
    
    if (ssid_len == 0 && strlen(ssid) == 0) {
        strcpy(ssid, "[Hidden]");
        is_hidden = true;
    }
    
    client->last_probed_ssid = String(ssid);
    client->last_ssid_len = ssid_len;
    client->probing_active = true;
    client->last_probe_time = millis();
    
    bool ssid_in_history = false;
    for (auto& history : client->ssid_history) {
        if (strcmp(history.ssid, ssid) == 0 && history.ssid_len == ssid_len) {
            history.last_seen = millis();
            history.probe_count++;
            ssid_in_history = true;
            break;
        }
    }
    
    if (!ssid_in_history) {
        SSIDHistory new_history;
        strncpy(new_history.ssid, ssid, 32);
        new_history.ssid_len = ssid_len;
        new_history.first_seen = millis();
        new_history.last_seen = millis();
        new_history.probe_count = 1;
        new_history.is_hidden = is_hidden;
        
        client->ssid_history.push_back(new_history);
        
        if (client->ssid_history.size() > MAX_SSID_HISTORY) {
            unsigned long oldest = millis();
            size_t oldest_idx = 0;
            for (size_t i = 0; i < client->ssid_history.size(); i++) {
                if (client->ssid_history[i].last_seen < oldest) {
                    oldest = client->ssid_history[i].last_seen;
                    oldest_idx = i;
                }
            }
            client->ssid_history.erase(client->ssid_history.begin() + oldest_idx);
        }
    }
}

void addNewClient(const uint8_t* mac, int rssi, int channel, 
                  const String& ap_bssid, const String& frame_type) {
    if (client_list.size() >= MAX_CLIENTS) {
        unsigned long oldest_time = millis();
        vector<ClientInfo>::iterator oldest = client_list.end();
        
        for (auto it = client_list.begin(); it != client_list.end(); ++it) {
            if (it->last_seen < oldest_time) {
                oldest_time = it->last_seen;
                oldest = it;
            }
        }
        
        if (oldest != client_list.end()) {
            client_list.erase(oldest);
        } else {
            return;
        }
    }
    
    if (rssi > 0) {
        if (rssi > 127) {
            rssi = -((int8_t)rssi);
        } else {
            rssi = -rssi;
        }
    }
    
    if (rssi > 0) rssi = -30;
    if (rssi < -100) rssi = -100;
    
    ClientInfo new_client;
    new_client.mac = arrayToMac(mac);
    new_client.rssi = rssi;
    new_client.channel = channel;
    new_client.ap_bssid = ap_bssid;
    new_client.first_seen = millis();
    new_client.last_seen = millis();
    new_client.packet_count = 1;
    new_client.last_frame_type = frame_type;
    new_client.is_associated = (ap_bssid != "N/A" && ap_bssid != "00:00:00:00:00:00");
    new_client.manufacturer = getVendorFromMAC(mac);
    new_client.data_rate = 0;
    new_client.probe_count = (frame_type == "PROBE_REQ") ? 1 : 0;
    new_client.is_handshaking = false;
    new_client.last_probed_ssid = "";
    new_client.last_ssid_len = 0;
    new_client.probing_active = false;
    new_client.targeted_ap = "";
    new_client.authentication_algo = 0;
    new_client.auth_seq = 0;
    new_client.last_probe_time = 0;
    
    if (new_client.is_associated && ap_bssid != "00:00:00:00:00:00") {
        uint8_t ap_bssid_bytes[6];
        sscanf(ap_bssid.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
              &ap_bssid_bytes[0], &ap_bssid_bytes[1], &ap_bssid_bytes[2],
              &ap_bssid_bytes[3], &ap_bssid_bytes[4], &ap_bssid_bytes[5]);
        updateAPClientAssociation(ap_bssid_bytes, mac);
    }
    
    client_list.push_back(new_client);
    total_client_packets++;
}

void addOrUpdateClient(const uint8_t* mac, int rssi, int channel, 
                       const String& ap_bssid, const String& frame_type) {
    if (!isValidClientMAC(mac)) return;
    
    ClientInfo* existing = findClient(mac);
    
    if (existing) {
        updateClient(existing, rssi, channel, ap_bssid, frame_type);
    } else {
        addNewClient(mac, rssi, channel, ap_bssid, frame_type);
    }
}

void cleanupOldClients() {
    unsigned long current_time = millis();
    
    client_list.erase(
        remove_if(client_list.begin(), client_list.end(),
            [current_time](const ClientInfo& client) {
                return (current_time - client.last_seen) > MAX_CLIENT_AGE_MS;
            }),
        client_list.end()
    );
    
    // Clean up old associations
    client_associations.erase(
        remove_if(client_associations.begin(), client_associations.end(),
            [current_time](const ClientAssociation& assoc) {
                return (current_time - assoc.last_associated) > MAX_CLIENT_AGE_MS;
            }),
        client_associations.end()
    );
}

String getManufacturerFromMAC(const uint8_t* mac) {
    return getVendorFromMAC(mac);
}

// ===== Enhanced Client Packet Processing =====
void processEnhancedClientPacket(const wifi_promiscuous_pkt_t* packet, int rssi, int channel) {
    const uint8_t* frame_ctrl = packet->payload;
    uint8_t frame_type, frame_subtype;
    getFrameType(frame_ctrl, &frame_type, &frame_subtype);
    
    const uint8_t* source_mac = &packet->payload[10];
    const uint8_t* destination_mac = &packet->payload[4];
    const uint8_t* bssid_mac = &packet->payload[16];
    
    String frame_type_str = getFrameTypeString(frame_type, frame_subtype);
    String ap_bssid_str = "N/A";
    
    if (!isBroadcastMAC(bssid_mac) && !isZeroMAC(bssid_mac)) {
        ap_bssid_str = macToString(bssid_mac);
    }
    
    // Process association frames
    if (frame_type == FRAME_TYPE_MANAGEMENT) {
        if (frame_subtype == SUBTYPE_ASSOCIATION_REQUEST ||
            frame_subtype == SUBTYPE_ASSOCIATION_RESPONSE ||
            frame_subtype == SUBTYPE_REASSOCIATION_REQUEST ||
            frame_subtype == SUBTYPE_REASSOCIATION_RESPONSE) {
            total_association_frames++;
            
            if (scan.enhanced_client_tracking) {
                // Update client-AP association
                if (frame_subtype == SUBTYPE_ASSOCIATION_REQUEST ||
                    frame_subtype == SUBTYPE_REASSOCIATION_REQUEST) {
                    // Client is requesting association
                    if (isValidClientMAC(source_mac) && !isBroadcastMAC(bssid_mac)) {
                        updateAPClientAssociation(bssid_mac, source_mac);
                    }
                } else if (frame_subtype == SUBTYPE_ASSOCIATION_RESPONSE ||
                          frame_subtype == SUBTYPE_REASSOCIATION_RESPONSE) {
                    // AP is responding to association
                    if (isValidClientMAC(destination_mac) && !isBroadcastMAC(bssid_mac)) {
                        updateAPClientAssociation(bssid_mac, destination_mac);
                    }
                }
            }
        }
        
        // Process authentication frames
        if (frame_subtype == SUBTYPE_AUTHENTICATION ||
            frame_subtype == SUBTYPE_DEAUTHENTICATION) {
            if (scan.enhanced_client_tracking) {
                if (frame_subtype == SUBTYPE_DEAUTHENTICATION) {
                    // Client is being deauthenticated
                    if (isValidClientMAC(destination_mac) && !isBroadcastMAC(bssid_mac)) {
                        removeClientFromAP(bssid_mac, destination_mac);
                    }
                }
            }
        }
    }
    
    // Update clients
    if (isValidClientMAC(source_mac)) {
        addOrUpdateClient(source_mac, rssi, channel, ap_bssid_str, frame_type_str);
    }
    if (isValidClientMAC(destination_mac)) {
        addOrUpdateClient(destination_mac, rssi, channel, ap_bssid_str, frame_type_str);
    }
}

// ===== Enhanced Packet Handlers =====
void enhancedPacketHandler(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    
    const wifi_promiscuous_pkt_t* packet = (wifi_promiscuous_pkt_t*)buf;
    
    if (packet->rx_ctrl.rssi < scan.min_rssi) return;
    if (packet->rx_ctrl.sig_len < 24) return;
    
    int rssi = packet->rx_ctrl.rssi;
    if (rssi > 1000) rssi = (int8_t)rssi;
    
    const uint8_t* frame_ctrl = packet->payload;
    uint8_t frame_type, frame_subtype;
    getFrameType(frame_ctrl, &frame_type, &frame_subtype);
    
    const uint8_t* source_mac = &packet->payload[10];
    const uint8_t* destination_mac = &packet->payload[4];
    const uint8_t* bssid_mac = &packet->payload[16];
    
    int current_channel = scan.current_channel;
    
    if (frame_type == FRAME_TYPE_MANAGEMENT) {
        total_management_frames++;
        if (frame_subtype == SUBTYPE_BEACON) total_beacons++;
        else if (frame_subtype == SUBTYPE_PROBE_REQUEST) total_probe_requests++;
    } else if (frame_type == FRAME_TYPE_DATA) {
        total_data_frames++;
    }
    
    if (scan.active_ap) {
        if (frame_subtype == SUBTYPE_BEACON || frame_subtype == SUBTYPE_PROBE_RESPONSE) {
            APInfo* ap = findOrCreateAP(bssid_mac);
            if (ap) {
                updateAPWithEnhancedInfo(ap, packet->payload, packet->rx_ctrl.sig_len,
                                       rssi, current_channel, frame_subtype);
            }
        }
        
        if (frame_subtype == SUBTYPE_PROBE_REQUEST) {
            // Process probe request for SSID tracking
            analyzeSSIDFromProbeRequest(packet->payload, packet->rx_ctrl.sig_len,
                                      source_mac, bssid_mac, rssi, current_channel);
            
            // Process probe request for hidden AP detection
            processProbeRequestForHiddenAPs(packet->payload, packet->rx_ctrl.sig_len,
                                          source_mac, bssid_mac, rssi, current_channel);
        }
    }
    
    if (scan.active_sta) {
        processEnhancedClientPacket(packet, rssi, current_channel);
    }
}

void passivePacketHandler(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    
    const wifi_promiscuous_pkt_t* packet = (wifi_promiscuous_pkt_t*)buf;
    
    if (packet->rx_ctrl.rssi < scan.min_rssi) return;
    if (packet->rx_ctrl.sig_len < MIN_PACKET_SIZE) return;
    
    int rssi = packet->rx_ctrl.rssi;
    if (rssi > 1000) rssi = (int8_t)rssi;
    
    const uint8_t* frame_ctrl = packet->payload;
    uint8_t frame_type, frame_subtype;
    getFrameType(frame_ctrl, &frame_type, &frame_subtype);
    
    const uint8_t* source_mac = &packet->payload[10];
    const uint8_t* destination_mac = &packet->payload[4];
    const uint8_t* bssid_mac = &packet->payload[16];
    
    int current_channel = scan.current_channel;
    
    String frame_type_str = getFrameTypeString(frame_type, frame_subtype);
    
    String ap_bssid_str = "N/A";
    if (!isBroadcastMAC(bssid_mac) && !isZeroMAC(bssid_mac)) {
        ap_bssid_str = macToString(bssid_mac);
    }
    
    String extracted_ssid = "";
    bool has_ssid_in_frame = false;
    bool is_hidden_ssid = false;
    uint8_t ssid_len = 0;
    
    if (frame_type == FRAME_TYPE_MANAGEMENT && packet->rx_ctrl.sig_len > 36) {
        const uint8_t* tagged_params = packet->payload + 36;
        uint16_t remaining_len = packet->rx_ctrl.sig_len - 36;
        const uint8_t* ptr = tagged_params;
        
        while (ptr < packet->payload + packet->rx_ctrl.sig_len && ptr[0] != 0xFF) {
            uint8_t element_id = ptr[0];
            uint8_t element_len = ptr[1];
            
            if (element_id == 0 && element_len <= 32) {
                ssid_len = element_len;
                char ssid_buf[33] = {0};
                if (element_len > 0) {
                    memcpy(ssid_buf, ptr + 2, element_len);
                    
                    // Check if SSID is all zeros (hidden)
                    bool all_zeros = true;
                    for (int i = 0; i < element_len; i++) {
                        if (ssid_buf[i] != 0) {
                            all_zeros = false;
                            break;
                        }
                    }
                    
                    if (all_zeros || element_len == 0) {
                        is_hidden_ssid = true;
                        extracted_ssid = "[Hidden]";
                    } else {
                        extracted_ssid = String(ssid_buf);
                    }
                } else {
                    is_hidden_ssid = true;
                    extracted_ssid = "[Hidden]";
                }
                has_ssid_in_frame = true;
                break;
            }
            
            if (element_len == 0 || element_len > 255) break;
            ptr += 2 + element_len;
            
            if (ptr > packet->payload + packet->rx_ctrl.sig_len) break;
        }
    }
    
    if (scan.active_ap) {
        if (isBeaconFrame(frame_ctrl)) {
            APInfo* ap = findOrCreateAP(bssid_mac);
            if (ap) {
                int ap_rssi = rssi;
                if (ap_rssi > 1000) ap_rssi = (int8_t)ap_rssi;
                updateAPInfo(ap, packet->payload, packet->rx_ctrl.sig_len, 
                            ap_rssi, current_channel);
            }
        }
        
        if (isProbeResponseFrame(frame_ctrl)) {
            APInfo* ap = findOrCreateAP(bssid_mac);
            if (ap) {
                char temp_ssid[33] = {0};
                bool is_hidden = false;
                uint8_t ssid_len = extractSSIDFromFrame(packet->payload, packet->rx_ctrl.sig_len, temp_ssid,
                                                      frame_type, frame_subtype, &is_hidden);
                
                if (ssid_len > 0 && !ap->ssid_known && !is_hidden) {
                    ap->ssid_len = ssid_len;
                    ap->original_ssid_len = ssid_len;
                    strncpy(ap->ssid, temp_ssid, 32);
                    ap->hidden = false;
                    ap->ssid_known = true;
                }
                
                int ap_rssi = rssi;
                if (ap_rssi > 1000) ap_rssi = (int8_t)ap_rssi;
                
                ap->rssi = ap_rssi;
                ap->channel = current_channel;
                ap->last_seen = millis();
                ap->packet_count++;
                
                if (scan.wps_detection_enabled) {
                    ap->wps_enabled = detectWPSInProbeResponse(packet->payload, 
                                                              packet->rx_ctrl.sig_len);
                    if (ap->wps_enabled) {
                        ap->wps_version = getWPSVersion(packet->payload, packet->rx_ctrl.sig_len);
                    }
                }
            }
        }
        
        if (frame_subtype == SUBTYPE_PROBE_REQUEST) {
            // Process probe request for SSID tracking
            if (scan.ssid_tracking_enabled) {
                analyzeSSIDFromProbeRequest(packet->payload, packet->rx_ctrl.sig_len,
                                          source_mac, bssid_mac, rssi, current_channel);
            }
            
            // Process probe request for hidden AP detection
            if (scan.probe_sniffing) {
                processProbeRequestForHiddenAPs(packet->payload, packet->rx_ctrl.sig_len,
                                              source_mac, bssid_mac, rssi, current_channel);
            }
        }
    }
    
    if (scan.active_sta) {
        processEnhancedClientPacket(packet, rssi, current_channel);
    }
}

void promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (scan.enhanced_scanning) {
        enhancedPacketHandler(buf, type);
    } else {
        passivePacketHandler(buf, type);
    }
}

// ===== Enhanced Display Functions =====
void displayEnhancedAPs() {
    unsigned long current_time = millis();
    
    // Only display every 2 seconds to prevent serial flooding
    if (current_time - scan.last_display < 2000 && ap_count > 0) {
        return;
    }
    scan.last_display = current_time;
    
    // Sort APs by RSSI (strongest first)
    for (int i = 0; i < ap_count - 1; i++) {
        for (int j = i + 1; j < ap_count; j++) {
            if (aps[i].rssi < aps[j].rssi) {
                APInfo temp = aps[i];
                aps[i] = aps[j];
                aps[j] = temp;
            }
        }
    }
    
    // Enhanced display format with revealed SSIDs
    Serial.println("\n============================================================================================================================================");
    Serial.println("Nr | SSID                           | Len | Orig | H | RSSI | Chan | Clients | Encryption               | WPS | Revealed | BSSID");
    Serial.println("============================================================================================================================================");
    
    int displayed_count = 0;
    int active_ap_count = 0;
    int hidden_count = 0;
    int hidden_revealed_count = 0;
    
    printed_bssids.clear();
    
    for (int i = 0; i < ap_count; ++i) {
        APInfo& ap = aps[i];
        
        // Skip APs not seen recently (30 seconds)
        if (current_time - ap.last_seen > 30000) {
            continue;
        }
        active_ap_count++;
        
        if (ap.hidden) hidden_count++;
        if (ap.ssid_revealed) hidden_revealed_count++;
        
        // Limit display to 25 APs at once
        if (displayed_count >= 25) {
            Serial.println("... more APs not displayed ...");
            break;
        }
        
        // Format SSID
        String ssid = String(ap.ssid);
        
        // For revealed hidden APs, show actual SSID with indicator
        if (ap.ssid_revealed && ap.ssid_known && !ap.hidden) {
            ssid = String(ap.ssid) + " [R]";
        }
        
        // Truncate SSID if too long for display
        if (ssid.length() > 30) {
            ssid = ssid.substring(0, 27) + "...";
        }
        
        // Display lengths
        int display_length = ap.ssid_len;  // Display length (8 for "[Hidden]")
        int original_length = ap.original_ssid_len;  // Original frame length
        
        // Get actual client count from associations
        int actual_clients = ap.associated_clients.size();
        if (actual_clients == 0) {
            // Estimate if no associations tracked
            actual_clients = estimateClientCount(ap.rssi, ap.channel);
        }
        
        // Get WPS status
        String wps_status = "No";
        if (ap.wps_enabled) {
            wps_status = (ap.wps_version == 2) ? "v2" : "v1";
        }
        
        // Get complete encryption string
        String enc_str = getCompleteEncryptionType(ap.encryption);
        if (enc_str.length() > 24) {
            enc_str = enc_str.substring(0, 21) + "...";
        }
        
        // Display revealed status
        String revealed_status = ap.ssid_revealed ? "Yes" : "-";
        
        // Display AP info with all details
        Serial.printf("%-2d | %-30s | %3d | %4d | %1s | %4d | %4d | %7d | %-24s | %3s | %8s | %s\n",
                     displayed_count + 1,
                     ssid.c_str(),
                     display_length,
                     original_length,
                     (ap.hidden ? "H" : " "),
                     ap.rssi,
                     ap.channel,
                     actual_clients,
                     enc_str.c_str(),
                     wps_status.c_str(),
                     revealed_status.c_str(),
                     macToString(ap.bssid.data()).c_str());
        
        displayed_count++;
        printed_bssids.push_back(macToString(ap.bssid.data()));
    }
    
    Serial.println("============================================================================================================================================");
    Serial.printf("Active APs: %d | Hidden: %d | Revealed: %d | Total Reveals: %d | Channel: %d | Time: %lu s\n",
                 active_ap_count, hidden_count, hidden_revealed_count, hidden_ap_revealed,
                 scan.current_channel, (millis() - scan.scan_start_time) / 1000);
    
    // Display probe cache statistics
    if (scan.probe_sniffing) {
        Serial.printf("Probe Cache: %d requests | Clients: %d | Assoc Frames: %d\n",
                     probe_cache.size(), client_list.size(), total_association_frames);
    }
}

void displayClients() {
    unsigned long current_time = millis();
    
    // Only display every client_scan_interval milliseconds
    if (current_time - scan.last_client_scan < scan.client_scan_interval) {
        return;
    }
    scan.last_client_scan = current_time;
    
    // Sort clients by RSSI (strongest first)
    std::sort(client_list.begin(), client_list.end(),
        [](const ClientInfo& a, const ClientInfo& b) {
            return a.rssi > b.rssi;
        });
    
    Serial.println("\n==========================================================================================================");
    Serial.println("Nr | Client MAC        | RSSI | Chan | Packets | Probes | Associated AP        | Manufacturer");
    Serial.println("==========================================================================================================");
    
    int displayed = 0;
    int active_clients = 0;
    
    for (size_t i = 0; i < client_list.size(); i++) {
        const ClientInfo& client = client_list[i];
        
        // Skip clients not seen recently
        if (current_time - client.last_seen > 30000) {
            continue;
        }
        active_clients++;
        
        // Limit display
        if (displayed >= 15) {
            Serial.println("... more clients not displayed ...");
            break;
        }
        
        String ap_display = client.ap_bssid;
        if (ap_display.length() > 20) {
            ap_display = ap_display.substring(0, 17) + "...";
        }
        
        Serial.printf("%-2d | %s | %4d | %4d | %7d | %6d | %-20s | %s\n",
                     displayed + 1,
                     macToString(client.mac.data()).c_str(),
                     client.rssi,
                     client.channel,
                     client.packet_count,
                     client.probe_count,
                     ap_display.c_str(),
                     client.manufacturer.c_str());
        
        displayed++;
    }
    
    Serial.println("==========================================================================================================");
    Serial.printf("Active Clients: %d | Total Clients: %d | Total Packets: %d\n",
                 active_clients, client_list.size(), total_client_packets);
    
    // Show probing activity
    int probing_clients = 0;
    for (const auto& client : client_list) {
        if (client.probing_active && (current_time - client.last_probe_time) < 10000) {
            probing_clients++;
        }
    }
    
    if (probing_clients > 0) {
        Serial.printf("Active Probers: %d | Probe Requests: %d\n",
                     probing_clients, total_probe_requests);
    }
}

void displayAPs() {
    displayEnhancedAPs();
}

// ===== Scanning Functions =====
void initWiFiPassive() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_stop();
    
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
}

bool startAPScan() {
    initWiFiPassive();
    
    ap_count = 0;
    printed_bssids.clear();
    ap_list.clear();
    ssid_list.clear();
    ssid_probe_counts.clear();
    ssid_client_map.clear();
    ssid_last_seen.clear();
    probe_cache.clear();
    client_associations.clear();
    hidden_ap_revealed = 0;
    total_association_frames = 0;
    
    total_probe_requests = 0;
    total_beacons = 0;
    total_data_frames = 0;
    total_management_frames = 0;
    
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback);
    esp_wifi_set_channel(scan.current_channel, WIFI_SECOND_CHAN_NONE);
    
    scan.active_ap = true;
    scan.active_sta = false;
    scan.channel_switch_time = millis();
    scan.scan_start_time = millis();
    scan.last_probe_check = millis();
    
    return true;
}

bool startClientScan() {
    initWiFiPassive();
    
    client_list.clear();
    client_associations.clear();
    probe_cache.clear();
    total_client_packets = 0;
    total_association_frames = 0;
    
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback);
    esp_wifi_set_channel(scan.current_channel, WIFI_SECOND_CHAN_NONE);
    
    scan.active_ap = false;
    scan.active_sta = true;
    scan.channel_switch_time = millis();
    scan.scan_start_time = millis();
    scan.last_probe_check = millis();
    scan.last_client_scan = millis();
    
    return true;
}

bool scan_setup(String mode) {
    if (mode == "ap") {
        return startAPScan();
    } else if (mode == "sta") {
        return startClientScan();
    } else if (mode == "stop") {
        scan.active_ap = false;
        scan.active_sta = false;
        esp_wifi_set_promiscuous(false);
        Serial.println("Scan stopped");
        return true;
    }
    return false;
}

// ===== Main Scanning Loops =====
bool scanAPs() {
    unsigned long current_time = millis();
    
    if (scan.scan_duration > 0 && (current_time - scan.scan_start_time) > scan.scan_duration) {
        Serial.println("\n=== AP SCAN DURATION EXPIRED ===");
        scan_setup("stop");
        return false;
    }
    
    if (current_time - scan.channel_switch_time >= scan.channel_hop_interval) {
        scan.current_channel++;
        
        if (scan.current_channel > TOTAL_CHANNELS) {
            scan.current_channel = 1;
            displayAPs();
        }
        
        esp_wifi_set_channel(scan.current_channel, WIFI_SECOND_CHAN_NONE);
        scan.channel_switch_time = current_time;
    }
    
    // Check probe cache for hidden APs
    if (scan.probe_sniffing && (current_time - scan.last_probe_check) >= PROBE_CACHE_CHECK_INTERVAL) {
        checkProbeCacheForHiddenAPs();
        scan.last_probe_check = current_time;
    }
    
    return true;
}

bool scanClients() {
    unsigned long current_time = millis();
    
    if (scan.scan_duration > 0 && (current_time - scan.scan_start_time) > scan.scan_duration) {
        Serial.println("\n=== CLIENT SCAN DURATION EXPIRED ===");
        scan_setup("stop");
        return false;
    }
    
    if (current_time - scan.channel_switch_time >= scan.channel_hop_interval) {
        scan.current_channel++;
        
        if (scan.current_channel > TOTAL_CHANNELS) {
            scan.current_channel = 1;
            displayClients();
        }
        
        esp_wifi_set_channel(scan.current_channel, WIFI_SECOND_CHAN_NONE);
        scan.channel_switch_time = current_time;
    }
    
    // Display clients periodically
    if (current_time - scan.last_client_scan >= scan.client_scan_interval) {
        displayClients();
        scan.last_client_scan = current_time;
    }
    
    return true;
}

bool scan_loop() {
    if (scan.active_ap) {
        return scanAPs();
    } else if (scan.active_sta) {
        return scanClients();
    }
    
    return true;
}

// ===== Configuration Functions =====
void setScanDuration(unsigned long duration) {
    scan.scan_duration = duration;
}

void setChannelHopInterval(unsigned long interval) {
    scan.channel_hop_interval = interval;
}

void setMinimumRSSI(int rssi) {
    scan.min_rssi = rssi;
}

void enableMACFiltering(bool enable) {
    scan.mac_filtering_enabled = enable;
}

void enableWPSDetection(bool enable) {
    scan.wps_detection_enabled = enable;
}

void enableProbeSniffing(bool enable) {
    scan.probe_sniffing = enable;
}

void enableProbeDebug(bool enable) {
    scan.probe_debug = enable;
}

void enableEnhancedClientTracking(bool enable) {
    scan.enhanced_client_tracking = enable;
}

void setClientScanInterval(int interval) {
    scan.client_scan_interval = interval;
}

// ===== Debug & Test Functions =====
void testRevealHiddenAPs() {
    Serial.println("\n=== Testing Hidden AP Reveal ===");
    
    int hidden_count = 0;
    for (int i = 0; i < ap_count; ++i) {
        if (aps[i].hidden) {
            hidden_count++;
            Serial.printf("Hidden AP %d: BSSID=%s, OrigLen=%d, Channel=%d, RSSI=%d\n",
                         i + 1,
                         macToString(aps[i].bssid.data()).c_str(),
                         aps[i].original_ssid_len,
                         aps[i].channel,
                         aps[i].rssi);
        }
    }
    
    Serial.printf("Total Hidden APs: %d\n", hidden_count);
    
    if (probe_cache.size() > 0) {
        Serial.println("\nProbe Cache Contents:");
        for (size_t i = 0; i < probe_cache.size(); i++) {
            uint8_t target_bssid[6];
            macToArray(probe_cache[i].target_bssid, target_bssid);
            String target = isBroadcastMAC(target_bssid) ? 
                          "Broadcast" : macToString(target_bssid);
            Serial.printf("  [%d] Client: %s -> SSID: %s (Len: %d) -> Target: %s\n",
                         i + 1,
                         macToString(probe_cache[i].client_mac.data()).c_str(),
                         probe_cache[i].ssid,
                         probe_cache[i].ssid_len,
                         target.c_str());
        }
    }
}

void dumpProbeCache() {
    Serial.println("\n=== Probe Cache Dump ===");
    Serial.printf("Total probes: %d\n", probe_cache.size());
    
    for (size_t i = 0; i < probe_cache.size(); i++) {
        const ProbeCache& probe = probe_cache[i];
        uint8_t target_bssid[6];
        macToArray(probe.target_bssid, target_bssid);
        String target = isBroadcastMAC(target_bssid) ? 
                      "Broadcast" : macToString(target_bssid);
        Serial.printf("[%d] %s -> %s -> %s (Age: %lu ms)\n",
                     i + 1,
                     macToString(probe.client_mac.data()).c_str(),
                     target.c_str(),
                     probe.ssid,
                     millis() - probe.timestamp);
    }
}

void dumpClientAssociations() {
    Serial.println("\n=== Client Associations Dump ===");
    Serial.printf("Total associations: %d\n", client_associations.size());
    
    for (size_t i = 0; i < client_associations.size(); i++) {
        const ClientAssociation& assoc = client_associations[i];
        Serial.printf("[%d] Client: %s -> AP: %s (Count: %d, Age: %lu ms)\n",
                     i + 1,
                     macToString(assoc.client_mac.data()).c_str(),
                     macToString(assoc.ap_bssid.data()).c_str(),
                     assoc.association_count,
                     millis() - assoc.last_associated);
    }
}

// ===== Utility Functions =====
int getAPCount() {
    return ap_count;
}

int getClientCount() {
    return client_list.size();
}

void clearAllData() {
    ap_count = 0;
    client_list.clear();
    ssid_list.clear();
    printed_bssids.clear();
    printed_client_macs.clear();
    ap_list.clear();
    ssid_probe_counts.clear();
    ssid_client_map.clear();
    ssid_last_seen.clear();
    probe_cache.clear();
    client_associations.clear();
    hidden_ap_revealed = 0;
    total_association_frames = 0;
    total_client_packets = 0;
    
    total_probe_requests = 0;
    total_beacons = 0;
    total_data_frames = 0;
    total_management_frames = 0;
    
    Serial.println("All scan data cleared.");
}

void saveAPsToPreferences() {
    preferences.begin(SCAN_PREFS_NAMESPACE, false);
    preferences.putUInt(AP_COUNT_KEY, ap_count);
    
    for (int i = 0; i < ap_count; i++) {
        String key = "ap_" + String(i);
        preferences.putBytes(key.c_str(), &aps[i], sizeof(APInfo));
    }
    
    preferences.end();
    Serial.printf("Saved %d APs to preferences\n", ap_count);
}

void loadAPsFromPreferences() {
    preferences.begin(SCAN_PREFS_NAMESPACE, true);
    ap_count = preferences.getUInt(AP_COUNT_KEY, 0);
    
    for (int i = 0; i < min(ap_count, MAX_APS); i++) {
        String key = "ap_" + String(i);
        preferences.getBytes(key.c_str(), &aps[i], sizeof(APInfo));
    }
    
    preferences.end();
    Serial.printf("Loaded %d APs from preferences\n", ap_count);
}

int estimateClientCount(int rssi, int channel) {
    if (rssi > -50) return random(3, 15);
    else if (rssi > -60) return random(2, 8);
    else if (rssi > -70) return random(1, 4);
    else if (rssi > -80) return random(0, 2);
    else return 0;
}