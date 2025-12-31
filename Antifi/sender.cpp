#include "sender.h"

// ===== Helper function for MAC address comparison =====
bool compareMAC(uint8_t* mac1, uint8_t* mac2) {
  for (int i = 0; i < 6; i++) {
    if (mac1[i] != mac2[i]) return false;
  }
  return true;
}

// ===== SenderManager Implementation =====

// Find a sender by name (returns pointer to sender or nullptr)
PacketSender* SenderManager::findSender(String senderName) {
  for (size_t i = 0; i < senders.size(); i++) {
    if (senders[i].name == senderName) {
      return &senders[i];
    }
  }
  return nullptr;
}

// Create a new sender with the given name
PacketSender* SenderManager::createSender(String senderName) {
  PacketSender newSender;
  newSender.active = false;
  newSender.name = senderName;
  newSender.packetCount = 0;
  newSender.pps = 0;
  newSender.channel = 1;
  newSender.maxPackets = 0;
  newSender.packetLen = 0;
  newSender.lastSendTime = 0;
  newSender.startTime = 0;
  memset(newSender.packetData, 0, sizeof(newSender.packetData));
  
  senders.push_back(newSender);
  return &senders.back();
}

// Start a sender with the given parameters
void SenderManager::startSender(String senderName, uint8_t* data, uint16_t len, uint8_t channel, uint32_t pps, uint32_t maxPackets) {
  // Find existing sender
  PacketSender* sender = findSender(senderName);
  
  if (sender) {
    // Stop if already active
    if (sender->active) {
      Serial.println("Warning: Sender " + senderName + " is already active. Restarting...");
      stopSender(senderName);
    }
  } else {
    // Create new sender
    sender = createSender(senderName);
    if (!sender) {
      Serial.println("Error: Failed to create sender - memory limit reached");
      return;
    }
  }
  
  // Configure sender
  sender->active = true;
  sender->channel = channel;
  sender->pps = pps;
  sender->maxPackets = maxPackets;
  sender->packetCount = 0;
  sender->packetLen = (len <= 512) ? len : 512;  // Ensure we don't exceed buffer
  sender->lastSendTime = 0;
  sender->startTime = millis();
  
  // Copy packet data
  if (len > 0 && len <= 512) {
    memcpy(sender->packetData, data, len);
  } else if (len > 512) {
    memcpy(sender->packetData, data, 512);
    Serial.println("Warning: Packet truncated to 512 bytes");
  }
}

// Stop a specific sender by name
void SenderManager::stopSender(String senderName) {
  PacketSender* sender = findSender(senderName);
  if (sender) {
    if (sender->active) {
      sender->active = false;
      unsigned long runtime = 0;
      float avgRate = 0;
      
      if (sender->startTime > 0) {
        runtime = (millis() - sender->startTime) / 1000;
        avgRate = (runtime > 0) ? (float)sender->packetCount / runtime : 0;
      }
      
      Serial.println("\n=== Sender Stopped ===");
      Serial.println("Name: " + senderName);
      Serial.println("Packets sent: " + String(sender->packetCount));
      if (runtime > 0) {
        Serial.println("Runtime: " + String(runtime) + " seconds");
        Serial.println("Average rate: " + String(avgRate, 1) + " packets/sec");
      }
      
      if (sender->maxPackets > 0) {
        int percent = (sender->packetCount * 100) / sender->maxPackets;
        Serial.println("Target: " + String(sender->packetCount) + "/" + String(sender->maxPackets) + 
                      " (" + String(percent) + "%)");
      }
      Serial.println("======================\n");
    } else {
      Serial.println("Sender " + senderName + " is already inactive");
      if (sender->packetCount > 0) {
        Serial.println("Previously sent: " + String(sender->packetCount) + " packets");
      }
    }
  } else {
    Serial.println("Error: Sender " + senderName + " not found");
  }
}

// Stop all active senders
void SenderManager::stopAllSenders() {
  bool anyActive = false;
  uint32_t totalPackets = 0;
  int activeCount = 0;
  
  for (size_t i = 0; i < senders.size(); i++) {
    if (senders[i].active) {
      anyActive = true;
      activeCount++;
      totalPackets += senders[i].packetCount;
      senders[i].active = false;
    }
  }
  
  Serial.println("Senders Stopped");
}

// Update all active senders (call this in main loop)
void SenderManager::updateSenders(int& currentChannel) {
  unsigned long currentTime = millis();
  
  for (size_t i = 0; i < senders.size(); i++) {
    if (senders[i].active && senders[i].packetLen > 0) {
      // Calculate time interval based on packets per second
      unsigned long interval = 0;
      if (senders[i].pps > 0) {
        interval = 1000 / senders[i].pps;
      }
      
      // Check if it's time to send next packet
      if (interval > 0 && (currentTime - senders[i].lastSendTime >= interval)) {
        // Check max packets limit
        if (senders[i].maxPackets > 0 && senders[i].packetCount >= senders[i].maxPackets) {
          Serial.println("\nSender " + senders[i].name + " completed");
          Serial.println("Target reached: " + String(senders[i].maxPackets) + " packets");
          senders[i].active = false;
          continue;
        }
        
        // Set channel if needed
        if (senders[i].channel != currentChannel) {
          esp_wifi_set_channel(senders[i].channel, WIFI_SECOND_CHAN_NONE);
          currentChannel = senders[i].channel;
        }
        
        // Send packet (sanity check bypass is active)
        esp_wifi_80211_tx(WIFI_IF_STA, senders[i].packetData, senders[i].packetLen, false);
        
        // Update counters and timers
        senders[i].packetCount++;
        totalPacketsAllTime++;
        senders[i].lastSendTime = currentTime;
      }
    }
  }
}

// List all senders with detailed status
void SenderManager::listSenders() {
  int activeCount = 0;
  int inactiveCount = 0;
  uint32_t totalActivePackets = 0;
  
  Serial.println("\n=== Active Senders ===");
  for (size_t i = 0; i < senders.size(); i++) {
    if (senders[i].active) {
      activeCount++;
      totalActivePackets += senders[i].packetCount;
      
      String status = "  " + senders[i].name + " [";
      status += "CH:" + String(senders[i].channel);
      status += ", RATE:" + String(senders[i].pps) + "pps";
      status += ", SENT:" + String(senders[i].packetCount);
      
      if (senders[i].maxPackets > 0) {
        int percent = (senders[i].packetCount * 100) / senders[i].maxPackets;
        status += "/" + String(senders[i].maxPackets) + " (" + String(percent) + "%)";
      } else {
        status += "/∞";
      }
      status += "]";
      Serial.println(status);
    }
  }
  if (activeCount == 0) {
    Serial.println("  No active senders");
  } else {
    Serial.println("  Total active: " + String(activeCount) + " senders, " + 
                  String(totalActivePackets) + " packets");
  }
  
  Serial.println("\n=== Inactive Senders ===");
  for (size_t i = 0; i < senders.size(); i++) {
    if (!senders[i].active) {
      inactiveCount++;
      String info = "  " + senders[i].name;
      if (senders[i].packetCount > 0) {
        info += " [Stopped, Sent: " + String(senders[i].packetCount) + " packets]";
      } else {
        info += " [Never started]";
      }
      Serial.println(info);
    }
  }
  if (inactiveCount == 0) {
    Serial.println("  No inactive senders");
  }
  
  Serial.println("\n=== Summary ===");
  Serial.println("  Total senders: " + String(senders.size()));
  Serial.println("  Active: " + String(activeCount));
  Serial.println("  Inactive: " + String(inactiveCount));
  Serial.println("  All-time packets: " + String(totalPacketsAllTime));
  Serial.println("======================\n");
}

// Get count of active senders
int SenderManager::getActiveSenderCount() {
  int count = 0;
  for (size_t i = 0; i < senders.size(); i++) {
    if (senders[i].active) {
      count++;
    }
  }
  return count;
}

// Clear all senders from memory
void SenderManager::clearAllSenders() {
  int totalSenders = senders.size();
  senders.clear();
  Serial.println("\nCleared " + String(totalSenders) + " senders from memory");
  Serial.println("Total packets sent (all-time): " + String(totalPacketsAllTime));
  Serial.println("================================\n");
}