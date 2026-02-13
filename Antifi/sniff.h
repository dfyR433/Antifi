#ifndef SNIFF_H
#define SNIFF_H

/*
  sniff.h — WiFiSniffer PCAPNG writer (nanosecond timestamps)
  - Designed for ESP32 (esp_wifi, esp_timer)
  - Writes PCAPNG to SD and/or Serial as configured
  - IDB uses if_tsresol = 9 (nanoseconds). sendEPB expects timestamps in nanoseconds.
*/

#include <Arduino.h>
#include <WiFi.h>
#include <cstring>
#include <SD.h>
#include <SPI.h>
#include "esp_wifi.h"
#include "esp_timer.h"

// Enable/disable outputs
#define USE_SD 1         // SD card writes
#define SERIAL_OUTPUT 1  // Serial output

// EXTENDED_RADIOTAP: set to 1 only if you can populate all extended fields correctly
#ifndef EXTENDED_RADIOTAP
#define EXTENDED_RADIOTAP 0
#endif

// Sniffer configuration defaults
#define LINKTYPE_IEEE802_11_RADIOTAP 127
#define SNIFF_START_CHANNEL 1
#define SNIFF_END_CHANNEL 14
#define SNIFF_HOP_INTERVAL_MS 100
#define SNIFF_MAX_SNAPLEN 2346

#if !USE_SD && !SERIAL_OUTPUT
#error "At least one output (USE_SD or SERIAL_OUTPUT) must be enabled"
#endif

class WiFiSniffer {
public:
  WiFiSniffer();

#if USE_SD
  bool openPCAPNGFile(const char* filename);
  void closePCAPNGFile();
  bool createNewPCAPNGFile();
  String getCurrentFileName() const {
    return currentFileName;
  }
  uint32_t getFileSize() const {
    return fileSize;
  }
  uint32_t getPacketCount() const {
    return packetCount;
  }
#endif

  bool begin(uint8_t startChannel = SNIFF_START_CHANNEL,
             uint8_t endChannel = SNIFF_END_CHANNEL,
             uint16_t hopIntervalMs = SNIFF_HOP_INTERVAL_MS);
  bool start(uint8_t fixedChannel = 0);
  void stop();
  void update();

  void sendSHB();
  void sendIDB(uint16_t linktype, uint32_t snaplen);
  void sendEPB(uint32_t interface_id, uint64_t ts_ns, const uint8_t* payload,
               uint32_t len, const wifi_pkt_rx_ctrl_t* rx_ctrl = nullptr);

  void setHopping(bool enable);
  void setHopInterval(uint16_t interval_ms);

  bool isRunning() const {
    return isPromiscuous;
  }
  uint8_t getCurrentChannel() const {
    return currentChannel;
  }

#if USE_SD
  bool isPCAPNGFileOpen() const {
    return pcapngFileOpen;
  }
#else
  bool isPCAPNGFileOpen() const {
    return false;
  }
#endif

  static uint16_t channelToFrequency(uint8_t channel);

private:
  static WiFiSniffer* instance;

#if USE_SD
  File pcapngFile;
  String currentFileName;
  bool pcapngFileOpen;
  uint32_t fileSize;
  uint32_t packetCount;

  void writeU8(uint8_t v);
  void writeU16(uint16_t v);
  void writeU32(uint32_t v);
  void writeU64(uint64_t v);
  String generateFileName();
#endif

#if SERIAL_OUTPUT
  void serialWriteU8(uint8_t v);
  void serialWriteU16(uint16_t v);
  void serialWriteU32(uint32_t v);
  void serialWriteU64(uint64_t v);
  void serialWriteBuffer(const uint8_t* buffer, size_t len);
#endif

  void processPacket(void* buf, wifi_promiscuous_pkt_type_t type);
  static void promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type);

  // Channel hopping variables (volatile for cross-context access)
  volatile uint8_t currentChannel;
  volatile uint8_t targetChannel;
  volatile uint8_t startChannel;
  volatile uint8_t endChannel;
  volatile uint32_t hopInterval;
  volatile unsigned long lastHop;
  volatile bool isPromiscuous;

  // Persistent packet buffer to avoid per-packet malloc
  static constexpr size_t EPB_BUFFER_HEADROOM = 512;  // radiotap + headroom
  uint8_t* epbBuffer;
  size_t epbBufferSize;
};

extern WiFiSniffer sniffer;

#endif  // SNIFF_H