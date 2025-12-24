#ifndef DEAUTH_H
#define DEAUTH_H

#include <Arduino.h>

// Function declarations
void setup_deauth(const uint8_t* source_bssid, const uint8_t* target_bssid, int channel, int pps);
void deauth_setup(const char* source_bssid_str, const char* target_bssid_str, int channel, int pps);
void deauth_loop();
void init_raw_wifi();
void stop_deauth();
void macStringToBytes(const char* macStr, uint8_t* bytes);

// Global variable declarations
extern int packets;
extern uint8_t source_mac_global[6];
extern uint8_t target_mac_global[6];
extern int attack_channel;
extern bool deauth_active;

#endif