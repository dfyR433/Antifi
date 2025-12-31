#ifndef BEACON_H
#define BEACON_H

#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"

// Configuration
#define BEACON_FRAME_SIZE 128
#define MAX_SSID_LEN 32

// Global variables
extern bool beacon_active;
extern uint8_t beacon_frame[BEACON_FRAME_SIZE];
extern uint8_t current_channel;
extern uint32_t packet_counter;
extern uint32_t start_time;
extern const int NUM_SSIDS;

// Function declarations
void beacon_setup();
void beacon_loop();
void start_beacon();
void stop_beacon();
bool is_beacon_active();
void send_beacon(int ssid_index);
void generate_mac(uint8_t* mac, int index);

#endif