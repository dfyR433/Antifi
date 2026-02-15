#include "inject.h"

bool compareMAC(uint8_t* mac1, uint8_t* mac2) {
  for (int i = 0; i < 6; i++) {
    if (mac1[i] != mac2[i]) return false;
  }
  return true;
}

PacketInjector* injectorManager::findInjector(String injectorName) {
  for (size_t i = 0; i < injectors.size(); i++) {
    if (injectors[i].name == injectorName) {
      return &injectors[i];
    }
  }
  return nullptr;
}

PacketInjector* injectorManager::createInjector(String injectorName) {
  PacketInjector newInjector;
  newInjector.active = false;
  newInjector.name = injectorName;
  newInjector.packetCount = 0;
  newInjector.pps = 0;
  newInjector.channel = 1;
  newInjector.maxPackets = 0;
  newInjector.packetLen = 0;
  newInjector.lastSendTime = 0;
  newInjector.startTime = 0;
  memset(newInjector.packetData, 0, sizeof(newInjector.packetData));

  injectors.push_back(newInjector);
  return &injectors.back();
}

void injectorManager::startInjector(String injectorName, uint8_t* data, uint16_t len, uint8_t channel, uint32_t pps, uint32_t maxPackets) {
  PacketInjector* injector = findInjector(injectorName);

  if (injector) {
    if (injector->active) {
      Serial.println("Warning: Injector " + injectorName + " is already active. Restarting...");
      stopInjector(injectorName);
    }
  } else {
    injector = createInjector(injectorName);
    if (!injector) {
      Serial.println("Error: Failed to create injector - memory limit reached");
      return;
    }
  }

  injector->active = true;
  injector->channel = channel;
  injector->pps = pps;
  injector->maxPackets = maxPackets;
  injector->packetCount = 0;
  injector->packetLen = (len <= 512) ? len : 512;
  injector->lastSendTime = 0;
  injector->startTime = millis();

  if (len > 0 && len <= 512) {
    memcpy(injector->packetData, data, len);
  } else if (len > 512) {
    memcpy(injector->packetData, data, 512);
    Serial.println("Warning: Packet truncated to 512 bytes");
  }
}

void injectorManager::stopInjector(String injectorName) {
  PacketInjector* injector = findInjector(injectorName);
  if (injector) {
    if (injector->active) {
      injector->active = false;
      unsigned long runtime = 0;
      float avgRate = 0;

      if (injector->startTime > 0) {
        runtime = (millis() - injector->startTime) / 1000;
        avgRate = (runtime > 0) ? (float)injector->packetCount / runtime : 0;
      }

      Serial.println("\n=== Injector Stopped ===");
      Serial.println("Name: " + injectorName);
      Serial.println("Packets sent: " + String(injector->packetCount));
      if (runtime > 0) {
        Serial.println("Runtime: " + String(runtime) + " seconds");
        Serial.println("Average rate: " + String(avgRate, 1) + " packets/sec");
      }

      if (injector->maxPackets > 0) {
        int percent = (injector->packetCount * 100) / injector->maxPackets;
        Serial.println("Target: " + String(injector->packetCount) + "/" + String(injector->maxPackets) + " (" + String(percent) + "%)");
      }
      Serial.println("======================\n");
    } else {
      Serial.println("Injector " + injectorName + " is already inactive");
      if (injector->packetCount > 0) {
        Serial.println("Previously sent: " + String(injector->packetCount) + " packets");
      }
    }
  } else {
    Serial.println("Error: Injector " + injectorName + " not found");
  }
}

void injectorManager::stopAllInjectors() {
  bool anyActive = false;
  uint32_t totalPackets = 0;
  int activeCount = 0;

  for (size_t i = 0; i < injectors.size(); i++) {
    if (injectors[i].active) {
      anyActive = true;
      activeCount++;
      totalPackets += injectors[i].packetCount;
      injectors[i].active = false;
    }
  }
}

void injectorManager::updateInjectors(int& currentChannel) {
  unsigned long currentTime = millis();

  for (size_t i = 0; i < injectors.size(); i++) {
    if (injectors[i].active && injectors[i].packetLen > 0) {
      unsigned long interval = 0;
      if (injectors[i].pps > 0) {
        interval = 1000 / injectors[i].pps;
      }

      if (interval > 0 && (currentTime - injectors[i].lastSendTime >= interval)) {
        if (injectors[i].maxPackets > 0 && injectors[i].packetCount >= injectors[i].maxPackets) {
          Serial.println("\nInjector " + injectors[i].name + " completed");
          Serial.println("Target reached: " + String(injectors[i].maxPackets) + " packets");
          injectors[i].active = false;
          continue;
        }

        if (injectors[i].channel != currentChannel) {
          esp_wifi_set_channel(injectors[i].channel, WIFI_SECOND_CHAN_NONE);
          currentChannel = injectors[i].channel;
        }

        esp_wifi_80211_tx(WIFI_IF_STA, injectors[i].packetData, injectors[i].packetLen, false);

        injectors[i].packetCount++;
        totalPacketsAllTime++;
        injectors[i].lastSendTime = currentTime;
      }
    }
  }
}

void injectorManager::listInjectors() {
  int activeCount = 0;
  int inactiveCount = 0;
  uint32_t totalActivePackets = 0;

  Serial.println("\n=== Active Injectors ===");
  for (size_t i = 0; i < injectors.size(); i++) {
    if (injectors[i].active) {
      activeCount++;
      totalActivePackets += injectors[i].packetCount;

      String status = "  " + injectors[i].name + " [";
      status += "CH:" + String(injectors[i].channel);
      status += ", RATE:" + String(injectors[i].pps) + "pps";
      status += ", SENT:" + String(injectors[i].packetCount);

      if (injectors[i].maxPackets > 0) {
        int percent = (injectors[i].packetCount * 100) / injectors[i].maxPackets;
        status += "/" + String(injectors[i].maxPackets) + " (" + String(percent) + "%)";
      } else {
        status += "/∞";
      }
      status += "]";
      Serial.println(status);
    }
  }
  if (activeCount == 0) {
    Serial.println("  No active injectors");
  } else {
    Serial.println("  Total active: " + String(activeCount) + " injectors, " + String(totalActivePackets) + " packets");
  }

  Serial.println("\n=== Inactive Injectors ===");
  for (size_t i = 0; i < injectors.size(); i++) {
    if (!injectors[i].active) {
      inactiveCount++;
      String info = "  " + injectors[i].name;
      if (injectors[i].packetCount > 0) {
        info += " [Stopped, Sent: " + String(injectors[i].packetCount) + " packets]";
      } else {
        info += " [Never started]";
      }
      Serial.println(info);
    }
  }
  if (inactiveCount == 0) {
    Serial.println("  No inactive injectors");
  }

  Serial.println("\n=== Summary ===");
  Serial.println("  Total injectors: " + String(injectors.size()));
  Serial.println("  Active: " + String(activeCount));
  Serial.println("  Inactive: " + String(inactiveCount));
  Serial.println("  All-time packets: " + String(totalPacketsAllTime));
  Serial.println("======================\n");
}

int injectorManager::getActiveInjectorCount() {
  int count = 0;
  for (size_t i = 0; i < injectors.size(); i++) {
    if (injectors[i].active) {
      count++;
    }
  }
  return count;
}

void injectorManager::clearAllInjectors() {
  int totalInjectors = injectors.size();
  injectors.clear();
  Serial.println("\nCleared " + String(totalInjectors) + " injectors from memory");
  Serial.println("Total packets sent (all-time): " + String(totalPacketsAllTime));
  Serial.println("================================\n");
}