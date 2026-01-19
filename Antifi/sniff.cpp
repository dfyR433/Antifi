#include "sniff.h"

WiFiSniffer* WiFiSniffer::instance = nullptr;
WiFiSniffer sniffer;

void WiFiSniffer::writeU8(uint8_t v) {
  Serial.write(&v, 1);
}

void WiFiSniffer::writeU16(uint16_t v) {
  uint8_t b[2] = { (uint8_t)(v & 0xFF), (uint8_t)((v >> 8) & 0xFF) };
  Serial.write(b, 2);
}

void WiFiSniffer::writeU32(uint32_t v) {
  uint8_t b[4] = {
    (uint8_t)(v & 0xFF),
    (uint8_t)((v >> 8) & 0xFF),
    (uint8_t)((v >> 16) & 0xFF),
    (uint8_t)((v >> 24) & 0xFF)
  };
  Serial.write(b, 4);
}

void WiFiSniffer::writeU64(uint64_t v) {
  uint8_t b[8];
  for (int i = 0; i < 8; ++i) b[i] = (uint8_t)((v >> (8 * i)) & 0xFF);
  Serial.write(b, 8);
}

void WiFiSniffer::sendSHB() {
  const uint32_t block_type = 0x0A0D0D0A;
  const uint32_t byte_order_magic = 0x1A2B3C4D;
  const uint16_t major = 1;
  const uint16_t minor = 0;
  const int64_t section_length = -1;

  const uint32_t block_total_length = 28;

  writeU32(block_type);
  writeU32(block_total_length);
  writeU32(byte_order_magic);
  writeU16(major);
  writeU16(minor);
  writeU64((uint64_t)section_length);
  writeU32(block_total_length);
}

void WiFiSniffer::sendIDB(uint16_t linktype, uint32_t snaplen) {
  const uint32_t block_type = 0x00000001;
  const uint32_t block_total_length = 20;

  writeU32(block_type);
  writeU32(block_total_length);
  writeU16(linktype);
  writeU16(0);
  writeU32(snaplen);
  writeU32(block_total_length);
}

void WiFiSniffer::sendEPB(uint32_t interface_id, uint64_t ts_us, const uint8_t* payload, uint32_t len, const wifi_pkt_rx_ctrl_t* rx_ctrl) {
  const uint32_t block_type = 0x00000006;

  if (len == 0) {
    uint32_t cap_len = 0;
    uint32_t orig_len = 0;
    uint32_t padded = 0;
    uint32_t block_total_length = 32 + padded;

    writeU32(block_type);
    writeU32(block_total_length);
    writeU32(interface_id);
    uint32_t ts_high = (uint32_t)(ts_us >> 32);
    uint32_t ts_low  = (uint32_t)(ts_us & 0xFFFFFFFFUL);
    writeU32(ts_high);
    writeU32(ts_low);
    writeU32(cap_len);
    writeU32(orig_len);
    writeU32(block_total_length);
    return;
  }

  uint8_t rt_buf[64];
  memset(rt_buf, 0, sizeof(rt_buf));
  size_t rt_len = 0;
  rt_buf[0] = 0x00;
  rt_buf[1] = 0x00;
  uint32_t present = (1u<<2) | (1u<<3) | (1u<<5) | (1u<<11);
  rt_buf[4] = (uint8_t)(present & 0xFF);
  rt_buf[5] = (uint8_t)((present >> 8) & 0xFF);
  rt_buf[6] = (uint8_t)((present >> 16) & 0xFF);
  rt_buf[7] = (uint8_t)((present >> 24) & 0xFF);
  rt_len = 8;

  uint8_t rate_val = 0;
  if (rx_ctrl) {
    rate_val = (uint8_t)(rx_ctrl->rate);
  }
  rt_buf[rt_len++] = rate_val;

  uint16_t freq = 0;
  uint16_t chan_flags = 0;
  if (rx_ctrl && rx_ctrl->channel) {
    uint8_t ch = rx_ctrl->channel;
    if (ch >= 1 && ch <= 13) {
      freq = 2412 + 5 * (ch - 1);
    } else {
      freq = 2412 + 5 * (currentChannel - 1);
    }
  } else {
    freq = 2412 + 5 * (currentChannel - 1);
  }
  rt_buf[rt_len++] = (uint8_t)(freq & 0xFF);
  rt_buf[rt_len++] = (uint8_t)((freq >> 8) & 0xFF);
  rt_buf[rt_len++] = (uint8_t)(chan_flags & 0xFF);
  rt_buf[rt_len++] = (uint8_t)((chan_flags >> 8) & 0xFF);

  int8_t dbm = 0;
  if (rx_ctrl) dbm = rx_ctrl->rssi;
  rt_buf[rt_len++] = (uint8_t)dbm;

  uint8_t ant = 0;
  if (rx_ctrl) ant = rx_ctrl->ant;
  rt_buf[rt_len++] = ant;

  size_t rt_padded = (rt_len + 3) & ~3u;

  rt_buf[2] = (uint8_t)(rt_padded & 0xFF);
  rt_buf[3] = (uint8_t)((rt_padded >> 8) & 0xFF);

  uint32_t cap_len = rt_padded + len;
  uint32_t orig_len = cap_len;
  uint32_t padded = (cap_len + 3) & ~3u;

  uint32_t block_total_length = 32 + padded;

  writeU32(block_type);
  writeU32(block_total_length);

  writeU32(interface_id);

  uint32_t ts_high = (uint32_t)(ts_us >> 32);
  uint32_t ts_low  = (uint32_t)(ts_us & 0xFFFFFFFFUL);
  writeU32(ts_high);
  writeU32(ts_low);

  writeU32(cap_len);
  writeU32(orig_len);

  Serial.write(rt_buf, rt_len);
  if (rt_padded > rt_len) {
    uint8_t zero = 0;
    for (size_t i = 0; i < rt_padded - rt_len; ++i) Serial.write(&zero, 1);
  }

  uint32_t payload_bytes_to_write = len;
  if (payload_bytes_to_write > (cap_len - rt_padded)) payload_bytes_to_write = cap_len - rt_padded;
  if (payload_bytes_to_write) Serial.write(payload, payload_bytes_to_write);

  if (padded > cap_len) {
    uint8_t zero = 0;
    for (uint32_t i = 0; i < padded - cap_len; ++i) Serial.write(&zero, 1);
  }

  writeU32(block_total_length);
}

WiFiSniffer::WiFiSniffer() : 
  currentChannel(SNIFF_START_CHANNEL),
  targetChannel(SNIFF_START_CHANNEL),
  startChannel(SNIFF_START_CHANNEL),
  endChannel(SNIFF_END_CHANNEL),
  hopInterval(SNIFF_HOP_INTERVAL_MS),
  lastHop(0),
  isPromiscuous(false)
{
  instance = this;
}

bool WiFiSniffer::begin(uint8_t startCh, uint8_t endCh, uint16_t hopIntervalMs) {
  startChannel = startCh;
  endChannel = endCh;
  hopInterval = hopIntervalMs;
  currentChannel = startChannel;
  targetChannel = startChannel;
  return true;
}

bool WiFiSniffer::start(uint8_t fixedChannel) {
  if (isPromiscuous) return true;

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();

  delay(100);

  sendSHB();
  sendIDB((uint16_t)LINKTYPE_IEEE802_11_RADIOTAP, SNIFF_MAX_SNAPLEN);

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&WiFiSniffer::promiscuousCallback);

  isPromiscuous = true;

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
  return true;
}

void WiFiSniffer::stop() {
  isPromiscuous = false;
}

void WiFiSniffer::promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (instance) {
    instance->processPacket(buf, type);
  }
}

void WiFiSniffer::processPacket(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t*)buf;
  if (!p) return;

  uint32_t len = p->rx_ctrl.sig_len;

  if (len == 0) {
    const uint32_t FALLBACK_LEN = 256;
    len = FALLBACK_LEN;
  }

  uint32_t capture_len = len > SNIFF_MAX_SNAPLEN ? SNIFF_MAX_SNAPLEN : len;

  uint64_t us = (uint64_t)esp_timer_get_time();

  sendEPB(0, us, p->payload, capture_len, &p->rx_ctrl);
}

void WiFiSniffer::update() {
  if (targetChannel != 0) {
    return;
  }

  unsigned long now = millis();
  if (now - lastHop >= hopInterval) {
    currentChannel++;
    if (currentChannel > endChannel) currentChannel = startChannel;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    lastHop = now;
  }
}

void WiFiSniffer::setHopping(bool enable) {
  if (enable) {
    targetChannel = 0;
  } else {
    targetChannel = currentChannel;
  }
}

void WiFiSniffer::setHopInterval(uint16_t interval_ms) {
  hopInterval = interval_ms;
}