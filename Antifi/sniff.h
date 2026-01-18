#ifndef SNIFF_H
#define SNIFF_H

#include <Arduino.h>
#include <WiFi.h>
#include <cstring>
#include "esp_wifi.h"
#include "esp_timer.h"

#ifndef LINKTYPE_IEEE802_11_RADIOTAP
#define LINKTYPE_IEEE802_11_RADIOTAP 127
#endif

#ifndef SNIFF_START_CHANNEL
#define SNIFF_START_CHANNEL 1
#endif

#ifndef SNIFF_END_CHANNEL
#define SNIFF_END_CHANNEL 13
#endif

#ifndef SNIFF_HOP_INTERVAL_MS
#define SNIFF_HOP_INTERVAL_MS 100
#endif

#ifndef SNIFF_MAX_SNAPLEN
#define SNIFF_MAX_SNAPLEN 2346
#endif

class WiFiSniffer {
public:
  WiFiSniffer();
  bool begin(uint8_t startChannel = SNIFF_START_CHANNEL, uint8_t endChannel = SNIFF_END_CHANNEL, uint16_t hopIntervalMs = SNIFF_HOP_INTERVAL_MS);
  bool start(uint8_t fixedChannel = 0);
  void stop();
  void update();

  void sendSHB();
  void sendIDB(uint16_t linktype, uint32_t snaplen);
  void sendEPB(uint32_t interface_id, uint64_t ts_us, const uint8_t* payload, uint32_t len, const wifi_pkt_rx_ctrl_t* rx_ctrl);

  void setHopping(bool enable);
  void setHopInterval(uint16_t interval_ms);

  bool isRunning() const { return isPromiscuous; }
  uint8_t getCurrentChannel() const { return currentChannel; }

private:
  static WiFiSniffer* instance;

  void writeU8(uint8_t v);
  void writeU16(uint16_t v);
  void writeU32(uint32_t v);
  void writeU64(uint64_t v);

  void processPacket(void* buf, wifi_promiscuous_pkt_type_t type);
  static void promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type);

  uint8_t currentChannel;
  uint8_t targetChannel;
  uint8_t startChannel;
  uint8_t endChannel;
  uint32_t hopInterval;
  unsigned long lastHop;
  bool isPromiscuous;
};

extern WiFiSniffer sniffer;

#endif