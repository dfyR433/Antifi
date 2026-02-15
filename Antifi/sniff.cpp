#include "sniff.h"

// Instance definition
WiFiSniffer* WiFiSniffer::instance = nullptr;
WiFiSniffer sniffer;

static inline size_t pad4(size_t len) {
  return (4 - (len & 3)) & 3;
}

// Helper: identical write to SD (if open) and Serial
static void write_to_outputs(const uint8_t* buf, size_t len, File* file, bool fileOpen) {
#if USE_SD
  if (fileOpen && file) {
    file->write(buf, len);
  }
#endif
#if SERIAL_OUTPUT
  Serial.write(buf, len);
#endif
}

uint16_t WiFiSniffer::channelToFrequency(uint8_t channel) {
  switch (channel) {
    case 1: return 2412;
    case 2: return 2417;
    case 3: return 2422;
    case 4: return 2427;
    case 5: return 2432;
    case 6: return 2437;
    case 7: return 2442;
    case 8: return 2447;
    case 9: return 2452;
    case 10: return 2457;
    case 11: return 2462;
    case 12: return 2467;
    case 13: return 2472;
    case 14: return 2484;
    default: return 2412;
  }
}

WiFiSniffer::WiFiSniffer()
  :
#if USE_SD
    pcapngFileOpen(false),
    fileSize(0),
    packetCount(0),
#endif
    currentChannel(SNIFF_START_CHANNEL),
    targetChannel(SNIFF_START_CHANNEL),
    startChannel(SNIFF_START_CHANNEL),
    endChannel(SNIFF_END_CHANNEL),
    hopInterval(SNIFF_HOP_INTERVAL_MS),
    lastHop(0),
    isPromiscuous(false),
    epbBuffer(nullptr),
    epbBufferSize(0) {
  instance = this;
}

#if USE_SD
String WiFiSniffer::generateFileName() {
  struct tm timeinfo;
  if (!getLocalTime(&timeinfo)) {
    static int counter = 0;
    char filename[32];
    snprintf(filename, sizeof(filename), "/sniff_%04d.pcapng", counter++);
    return String(filename);
  }
  char filename[32];
  strftime(filename, sizeof(filename), "/sniff_%Y%m%d_%H%M%S.pcapng", &timeinfo);
  return String(filename);
}

bool WiFiSniffer::createNewPCAPNGFile() {
  if (pcapngFileOpen) closePCAPNGFile();
  currentFileName = generateFileName();
  int counter = 1;
  while (SD.exists(currentFileName.c_str())) {
    if (counter > 100) break;
    char newName[32];
    snprintf(newName, sizeof(newName), "/sniff_%04d.pcapng", counter++);
    currentFileName = String(newName);
  }
  return openPCAPNGFile(currentFileName.c_str());
}

bool WiFiSniffer::openPCAPNGFile(const char* filename) {
  pcapngFile = SD.open(filename, FILE_WRITE);
  if (!pcapngFile) {
    pcapngFileOpen = false;
    return false;
  }
  currentFileName = String(filename);
  fileSize = 0;
  packetCount = 0;
  pcapngFileOpen = true;
  sendSHB();
  sendIDB((uint16_t)LINKTYPE_IEEE802_11_RADIOTAP, SNIFF_MAX_SNAPLEN);
  return true;
}

void WiFiSniffer::closePCAPNGFile() {
  if (pcapngFileOpen && pcapngFile) {
    pcapngFile.flush();
    pcapngFile.close();
    pcapngFileOpen = false;
  }
}

void WiFiSniffer::writeU8(uint8_t v) {
  if (pcapngFileOpen && pcapngFile) {
    pcapngFile.write(&v, 1);
    fileSize += 1;
  }
}
void WiFiSniffer::writeU16(uint16_t v) {
  uint8_t b[2] = { (uint8_t)(v & 0xFF), (uint8_t)((v >> 8) & 0xFF) };
  if (pcapngFileOpen && pcapngFile) {
    pcapngFile.write(b, 2);
    fileSize += 2;
  }
}
void WiFiSniffer::writeU32(uint32_t v) {
  uint8_t b[4] = { (uint8_t)(v & 0xFF), (uint8_t)((v >> 8) & 0xFF), (uint8_t)((v >> 16) & 0xFF), (uint8_t)((v >> 24) & 0xFF) };
  if (pcapngFileOpen && pcapngFile) {
    pcapngFile.write(b, 4);
    fileSize += 4;
  }
}
void WiFiSniffer::writeU64(uint64_t v) {
  uint8_t b[8];
  for (int i = 0; i < 8; ++i) b[i] = (uint8_t)((v >> (8 * i)) & 0xFF);
  if (pcapngFileOpen && pcapngFile) {
    pcapngFile.write(b, 8);
    fileSize += 8;
  }
}
#endif

#if SERIAL_OUTPUT
void WiFiSniffer::serialWriteU8(uint8_t v) {
  Serial.write(v);
}
void WiFiSniffer::serialWriteU16(uint16_t v) {
  uint8_t b[2] = { (uint8_t)(v & 0xFF), (uint8_t)((v >> 8) & 0xFF) };
  Serial.write(b, 2);
}
void WiFiSniffer::serialWriteU32(uint32_t v) {
  uint8_t b[4] = { (uint8_t)(v & 0xFF), (uint8_t)((v >> 8) & 0xFF), (uint8_t)((v >> 16) & 0xFF), (uint8_t)((v >> 24) & 0xFF) };
  Serial.write(b, 4);
}
void WiFiSniffer::serialWriteU64(uint64_t v) {
  uint8_t b[8];
  for (int i = 0; i < 8; ++i) b[i] = (uint8_t)((v >> (8 * i)) & 0xFF);
  Serial.write(b, 8);
}
void WiFiSniffer::serialWriteBuffer(const uint8_t* buffer, size_t len) {
  Serial.write(buffer, len);
}
#endif

// PCAPNG: SHB (minimal little-endian)
void WiFiSniffer::sendSHB() {
  const uint32_t block_type = 0x0A0D0D0Au;
  const uint32_t byte_order_magic = 0x1A2B3C4Du;
  const uint16_t major = 1;
  const uint16_t minor = 0;
  const uint64_t section_length = 0xFFFFFFFFFFFFFFFFULL;  // unspecified
  const uint32_t total_len = 28;
  uint8_t buf[28];
  size_t o = 0;
  // block_type
  buf[o++] = (uint8_t)(block_type & 0xFF);
  buf[o++] = (uint8_t)((block_type >> 8) & 0xFF);
  buf[o++] = (uint8_t)((block_type >> 16) & 0xFF);
  buf[o++] = (uint8_t)((block_type >> 24) & 0xFF);
  // total_len
  buf[o++] = (uint8_t)(total_len & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 8) & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 16) & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 24) & 0xFF);
  // byte-order magic
  buf[o++] = (uint8_t)(byte_order_magic & 0xFF);
  buf[o++] = (uint8_t)((byte_order_magic >> 8) & 0xFF);
  buf[o++] = (uint8_t)((byte_order_magic >> 16) & 0xFF);
  buf[o++] = (uint8_t)((byte_order_magic >> 24) & 0xFF);
  // major/minor
  buf[o++] = (uint8_t)(major & 0xFF);
  buf[o++] = (uint8_t)((major >> 8) & 0xFF);
  buf[o++] = (uint8_t)(minor & 0xFF);
  buf[o++] = (uint8_t)((minor >> 8) & 0xFF);
  // section_length
  for (int i = 0; i < 8; ++i) buf[o++] = (uint8_t)((section_length >> (8 * i)) & 0xFF);
  // trailer total_len
  buf[o++] = (uint8_t)(total_len & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 8) & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 16) & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 24) & 0xFF);
#if USE_SD
  write_to_outputs(buf, total_len, &pcapngFile, pcapngFileOpen);
#else
  write_to_outputs(buf, total_len, nullptr, false);
#endif
#if USE_SD
  if (pcapngFileOpen) fileSize += total_len;
#endif
}

// PCAPNG: IDB (if_tsresol = 9 ns)
void WiFiSniffer::sendIDB(uint16_t linktype, uint32_t snaplen) {
  const uint32_t block_type = 0x00000001u;
  const uint16_t opt_if_tsresol = 0x0009;
  const uint8_t if_tsresol_val = 0x09;  // ns
  size_t if_val_pad = pad4(1);
  size_t opts_len = 2 + 2 + 1 + if_val_pad;  // option header + value + pad
  opts_len += 4;                             // end-of-options
  const uint32_t payload_len = 2 + 2 + 4 + (uint32_t)opts_len;
  const uint32_t total_len = 8 + payload_len + 4;
  uint8_t* buf = (uint8_t*)malloc(total_len);
  if (!buf) return;
  size_t o = 0;
  // block_type
  buf[o++] = (uint8_t)(block_type & 0xFF);
  buf[o++] = (uint8_t)((block_type >> 8) & 0xFF);
  buf[o++] = (uint8_t)((block_type >> 16) & 0xFF);
  buf[o++] = (uint8_t)((block_type >> 24) & 0xFF);
  // total_len
  buf[o++] = (uint8_t)(total_len & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 8) & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 16) & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 24) & 0xFF);
  // linktype
  buf[o++] = (uint8_t)(linktype & 0xFF);
  buf[o++] = (uint8_t)((linktype >> 8) & 0xFF);
  // reserved
  buf[o++] = 0x00;
  buf[o++] = 0x00;
  // snaplen
  buf[o++] = (uint8_t)(snaplen & 0xFF);
  buf[o++] = (uint8_t)((snaplen >> 8) & 0xFF);
  buf[o++] = (uint8_t)((snaplen >> 16) & 0xFF);
  buf[o++] = (uint8_t)((snaplen >> 24) & 0xFF);
  // if_tsresol option
  buf[o++] = (uint8_t)(opt_if_tsresol & 0xFF);
  buf[o++] = (uint8_t)((opt_if_tsresol >> 8) & 0xFF);
  buf[o++] = 1;
  buf[o++] = 0;  // len=1, pad slot
  buf[o++] = if_tsresol_val;
  for (size_t i = 0; i < if_val_pad; ++i) buf[o++] = 0x00;
  // end-of-options
  buf[o++] = 0x00;
  buf[o++] = 0x00;
  buf[o++] = 0x00;
  buf[o++] = 0x00;
  // trailer
  buf[o++] = (uint8_t)(total_len & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 8) & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 16) & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 24) & 0xFF);
#if USE_SD
  write_to_outputs(buf, total_len, &pcapngFile, pcapngFileOpen);
#else
  write_to_outputs(buf, total_len, nullptr, false);
#endif
#if USE_SD
  if (pcapngFileOpen) fileSize += total_len;
#endif
  free(buf);
}

// EPB: writes radiotap+802.11 bytes as provided by payload pointer. len == length of payload.
void WiFiSniffer::sendEPB(uint32_t interface_id, uint64_t ts_ns, const uint8_t* payload, uint32_t len, const wifi_pkt_rx_ctrl_t* /*rx_ctrl*/) {
  if (!payload || len == 0) return;
  uint32_t captured_len = len > SNIFF_MAX_SNAPLEN + 512 ? (SNIFF_MAX_SNAPLEN + 512) : len;  // allow radiotap headroom
  size_t pad_packet = pad4(captured_len);
  size_t options_len = 4;  // end-of-options
  size_t payload_area = (size_t)captured_len + pad_packet + options_len;
  uint32_t total_len = (uint32_t)(8 + 20 + payload_area + 4);
  uint8_t* buf = (uint8_t*)malloc(total_len);
  if (!buf) return;
  size_t o = 0;
  const uint32_t block_type = 0x00000006u;
  // block_type
  buf[o++] = (uint8_t)(block_type & 0xFF);
  buf[o++] = (uint8_t)((block_type >> 8) & 0xFF);
  buf[o++] = (uint8_t)((block_type >> 16) & 0xFF);
  buf[o++] = (uint8_t)((block_type >> 24) & 0xFF);
  // total_len
  buf[o++] = (uint8_t)(total_len & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 8) & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 16) & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 24) & 0xFF);
  // interface_id
  buf[o++] = (uint8_t)(interface_id & 0xFF);
  buf[o++] = (uint8_t)((interface_id >> 8) & 0xFF);
  buf[o++] = (uint8_t)((interface_id >> 16) & 0xFF);
  buf[o++] = (uint8_t)((interface_id >> 24) & 0xFF);
  // ts high/low (ns)
  uint32_t ts_high = (uint32_t)((ts_ns >> 32) & 0xFFFFFFFFULL);
  uint32_t ts_low = (uint32_t)(ts_ns & 0xFFFFFFFFULL);
  buf[o++] = (uint8_t)(ts_high & 0xFF);
  buf[o++] = (uint8_t)((ts_high >> 8) & 0xFF);
  buf[o++] = (uint8_t)((ts_high >> 16) & 0xFF);
  buf[o++] = (uint8_t)((ts_high >> 24) & 0xFF);
  buf[o++] = (uint8_t)(ts_low & 0xFF);
  buf[o++] = (uint8_t)((ts_low >> 8) & 0xFF);
  buf[o++] = (uint8_t)((ts_low >> 16) & 0xFF);
  buf[o++] = (uint8_t)((ts_low >> 24) & 0xFF);
  // caplen
  buf[o++] = (uint8_t)(captured_len & 0xFF);
  buf[o++] = (uint8_t)((captured_len >> 8) & 0xFF);
  buf[o++] = (uint8_t)((captured_len >> 16) & 0xFF);
  buf[o++] = (uint8_t)((captured_len >> 24) & 0xFF);
  // orig len (we report original bytes we provided)
  uint32_t packet_len = len;
  buf[o++] = (uint8_t)(packet_len & 0xFF);
  buf[o++] = (uint8_t)((packet_len >> 8) & 0xFF);
  buf[o++] = (uint8_t)((packet_len >> 16) & 0xFF);
  buf[o++] = (uint8_t)((packet_len >> 24) & 0xFF);
  // payload copy (up to captured_len)
  memcpy(buf + o, payload, (size_t)captured_len);
  o += captured_len;
  // pad packet
  for (size_t i = 0; i < pad_packet; ++i) buf[o++] = 0x00;
  // end-of-options
  buf[o++] = 0x00;
  buf[o++] = 0x00;
  buf[o++] = 0x00;
  buf[o++] = 0x00;
  // trailer
  buf[o++] = (uint8_t)(total_len & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 8) & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 16) & 0xFF);
  buf[o++] = (uint8_t)((total_len >> 24) & 0xFF);
#if USE_SD
  write_to_outputs(buf, total_len, &pcapngFile, pcapngFileOpen);
#else
  write_to_outputs(buf, total_len, nullptr, false);
#endif
#if USE_SD
  if (pcapngFileOpen) {
    fileSize += total_len;
    packetCount++;
    if ((packetCount & 0x3F) == 0) pcapngFile.flush();
  }
#endif
  free(buf);
}

bool WiFiSniffer::begin(uint8_t startCh, uint8_t endCh, uint16_t hopIntervalMs) {
  if (startCh < 1 || startCh > 14 || endCh < 1 || endCh > 14) return false;
  if (startCh > endCh) return false;
  startChannel = startCh;
  endChannel = endCh;
  hopInterval = hopIntervalMs;
  currentChannel = startChannel;
  targetChannel = startChannel;
  return true;
}

bool WiFiSniffer::start(uint8_t fixedChannel) {
  if (isPromiscuous) return true;
#if USE_SD
  if (!createNewPCAPNGFile()) {
// If SD fails, but serial is enabled, still continue
#if !SERIAL_OUTPUT
    return false;
#endif
  }
#endif
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  delay(100);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&WiFiSniffer::promiscuousCallback);
  isPromiscuous = true;
#if SERIAL_OUTPUT
#if USE_SD
  if (!pcapngFileOpen) {
    sendSHB();
    sendIDB((uint16_t)LINKTYPE_IEEE802_11_RADIOTAP, SNIFF_MAX_SNAPLEN);
  }
#else
  sendSHB();
  sendIDB((uint16_t)LINKTYPE_IEEE802_11_RADIOTAP, SNIFF_MAX_SNAPLEN);
#endif
#endif
  if (fixedChannel >= 1 && fixedChannel <= 14) {
    currentChannel = fixedChannel;
    targetChannel = fixedChannel;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  } else {
    targetChannel = 0;
    currentChannel = startChannel;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  }
  lastHop = millis();
  // allocate persistent epb buffer
  if (!epbBuffer) {
    epbBufferSize = (size_t)SNIFF_MAX_SNAPLEN + EPB_BUFFER_HEADROOM;
    epbBuffer = (uint8_t*)malloc(epbBufferSize);
    if (!epbBuffer) {
#if SERIAL_OUTPUT
      Serial.println("Warning: epbBuffer allocation failed; falling back to transient malloc in RX");
#endif
    }
  }
  return true;
}

void WiFiSniffer::stop() {
  if (!isPromiscuous) return;
  isPromiscuous = false;
#if USE_SD
  closePCAPNGFile();
#endif
  if (epbBuffer) {
    free(epbBuffer);
    epbBuffer = nullptr;
    epbBufferSize = 0;
  }
}

void WiFiSniffer::promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (instance) instance->processPacket(buf, type);
}

// Helper to safely fetch a channel number from rx_ctrl (0 -> fallback)
static inline uint8_t safe_channel(const wifi_pkt_rx_ctrl_t& rc, uint8_t fallback) {
  if (rc.channel >= 1 && rc.channel <= 14) return rc.channel;
  return fallback;
}

void WiFiSniffer::processPacket(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* p = (wifi_promiscuous_pkt_t*)buf;
  if (!p) return;

  // Determine length conservatively. Use a larger fallback to avoid truncating beacons.
  uint32_t len = p->rx_ctrl.sig_len;
  if (len == 0) {
    const uint32_t FALLBACK_LEN = 2048;  // larger fallback to avoid TLV truncation
    len = FALLBACK_LEN;
    if (type == WIFI_PKT_MGMT && len >= 24) len = 24;
  }
  uint32_t original_len = len;
  uint32_t capture_len = len > SNIFF_MAX_SNAPLEN ? SNIFF_MAX_SNAPLEN : len;
  if (capture_len == 0) return;

  // Build minimal radiotap header into local buffer (then copy into epbBuffer)
  // Fields: Channel (bit 3), dBm Antenna Signal (bit 5), Antenna (bit 11)
  uint8_t rt_tmp[64];
  memset(rt_tmp, 0, sizeof(rt_tmp));
  size_t rt_o = 0;
  rt_tmp[rt_o++] = 0x00;
  rt_tmp[rt_o++] = 0x00;  // it_version, it_pad
  rt_o += 2;              // placeholder for it_len
  uint32_t present = (1u << 3) | (1u << 5) | (1u << 11);
  rt_tmp[rt_o++] = (uint8_t)(present & 0xFF);
  rt_tmp[rt_o++] = (uint8_t)((present >> 8) & 0xFF);
  rt_tmp[rt_o++] = (uint8_t)((present >> 16) & 0xFF);
  rt_tmp[rt_o++] = (uint8_t)((present >> 24) & 0xFF);

  // Channel: align to 2 bytes
  if (rt_o & 1) rt_tmp[rt_o++] = 0x00;
  uint8_t ch = safe_channel(p->rx_ctrl, (uint8_t)currentChannel);
  uint16_t freq = channelToFrequency(ch);
  uint16_t chan_flags = 0x0080;  // 2.4 GHz
  if (ch == 14) chan_flags |= 0x0010;
  rt_tmp[rt_o++] = (uint8_t)(freq & 0xFF);
  rt_tmp[rt_o++] = (uint8_t)((freq >> 8) & 0xFF);
  rt_tmp[rt_o++] = (uint8_t)(chan_flags & 0xFF);
  rt_tmp[rt_o++] = (uint8_t)((chan_flags >> 8) & 0xFF);

  // dBm Antenna Signal (1 byte signed)
  int8_t dbm = p->rx_ctrl.rssi;
  rt_tmp[rt_o++] = (uint8_t)dbm;

  // Antenna index (if known)
  uint8_t antenna_idx = 0;
  rt_tmp[rt_o++] = antenna_idx;

  // pad to 4 bytes
  while (rt_o & 3) rt_tmp[rt_o++] = 0x00;

  // write it_len
  uint16_t it_len = (uint16_t)rt_o;
  rt_tmp[2] = (uint8_t)(it_len & 0xFF);
  rt_tmp[3] = (uint8_t)((it_len >> 8) & 0xFF);

  // Sanity: ensure it_len isn't larger than available combined area (protect against programming errors)
  size_t combined_len = (size_t)it_len + (size_t)capture_len;
  if (it_len == 0 || it_len > 1024 || combined_len == 0) {
    // fallback: minimal radiotap header (8 bytes) to avoid desync
    it_len = 8;
    rt_tmp[2] = (uint8_t)(it_len & 0xFF);
    rt_tmp[3] = (uint8_t)((it_len >> 8) & 0xFF);
    combined_len = (size_t)it_len + (size_t)capture_len;
  }

  // Use persistent buffer if available
  if (epbBuffer && epbBufferSize >= combined_len) {
    memcpy(epbBuffer, rt_tmp, it_len);
    memcpy(epbBuffer + it_len, p->payload, capture_len);
    uint64_t ts_ns = (uint64_t)esp_timer_get_time() * 1000ULL;
    sendEPB(0, ts_ns, epbBuffer, (uint32_t)combined_len, &p->rx_ctrl);
  } else {
    // transient allocation fallback
    uint8_t* tmp = (uint8_t*)malloc(combined_len);
    if (!tmp) return;
    memcpy(tmp, rt_tmp, it_len);
    memcpy(tmp + it_len, p->payload, capture_len);
    uint64_t ts_ns = (uint64_t)esp_timer_get_time() * 1000ULL;
    sendEPB(0, ts_ns, tmp, (uint32_t)combined_len, &p->rx_ctrl);
    free(tmp);
  }
}

void WiFiSniffer::update() {
  if (!isPromiscuous) return;
  if (targetChannel != 0) return;
  unsigned long now = millis();
  if (now - lastHop >= hopInterval) {
    currentChannel++;
    if (currentChannel > endChannel) currentChannel = startChannel;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    lastHop = now;
  }
}

void WiFiSniffer::setHopping(bool enable) {
  if (enable) targetChannel = 0;
  else targetChannel = currentChannel;
}
void WiFiSniffer::setHopInterval(uint16_t interval_ms) {
  hopInterval = interval_ms;
}