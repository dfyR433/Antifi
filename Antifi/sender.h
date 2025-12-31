#ifndef SENDER_H
#define SENDER_H

#include <Arduino.h>
#include <vector>
#include <WiFi.h>
#include "esp_wifi.h"

// Structure to store packet sender configuration
struct PacketSender {
  bool active;
  String name;
  uint8_t channel;
  uint32_t pps;  // Packets per second
  uint32_t maxPackets;
  uint32_t packetCount;
  uint8_t packetData[512];
  uint16_t packetLen;
  unsigned long lastSendTime;
  unsigned long startTime;
  
  // Constructor for initialization
  PacketSender() : active(false), name(""), channel(1), pps(0), maxPackets(0), 
                   packetCount(0), packetLen(0), lastSendTime(0), startTime(0) {
    memset(packetData, 0, sizeof(packetData));
  }
};

// Class to manage multiple packet senders
class SenderManager {
private:
  std::vector<PacketSender> senders;
  uint32_t totalPacketsAllTime;
  
  PacketSender* findSender(String senderName);
  PacketSender* createSender(String senderName);
  
public:
  SenderManager() : totalPacketsAllTime(0) {}
  
  // Sender management
  void startSender(String senderName, uint8_t* data, uint16_t len, uint8_t channel, uint32_t pps, uint32_t maxPackets);
  void stopSender(String senderName);
  void stopAllSenders();
  void clearAllSenders();
  
  // Update and list
  void updateSenders(int& currentChannel);
  void listSenders();
  
  // Getters
  int getSenderCount() { return senders.size(); }
  int getActiveSenderCount();
  uint32_t getTotalPacketsSent() { return totalPacketsAllTime; }
};

#endif