#ifndef INJECT_H
#define INJECT_H

#include <Arduino.h>
#include <vector>
#include <WiFi.h>
#include "esp_wifi.h"

#define MAX_PACKET_LEN 512

struct PacketInjector {
  bool active;
  String name;
  uint8_t channel;
  uint32_t pps;
  uint32_t maxPackets;
  uint32_t packetCount;
  uint8_t packetData[MAX_PACKET_LEN];
  uint16_t packetLen;
  unsigned long lastSendTime;
  unsigned long startTime;

  PacketInjector()
    : active(false), name(""), channel(1), pps(0), maxPackets(0),
      packetCount(0), packetLen(0), lastSendTime(0), startTime(0) {
    memset(packetData, 0, sizeof(packetData));
  }
};

class injectorManager {
private:
  std::vector<PacketInjector> injectors;
  uint32_t totalPacketsAllTime;

  PacketInjector* findInjector(String injectorName);
  PacketInjector* createInjector(String injectorName);

public:
  injectorManager()
    : totalPacketsAllTime(0) {}

  void startInjector(String injectorName, uint8_t* data, uint16_t len, uint8_t channel, uint32_t pps, uint32_t maxPackets);
  void stopInjector(String injectorName);
  void stopAllInjectors();
  void clearAllInjectors();

  void updateInjectors(int& currentChannel);
  void listInjectors();

  int getInjectorCount() {
    return injectors.size();
  }
  int getActiveInjectorCount();
  uint32_t getTotalPacketsSent() {
    return totalPacketsAllTime;
  }
};

#endif