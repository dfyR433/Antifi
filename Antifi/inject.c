#include "inject.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include "esp_timer.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"

int ieee80211_raw_frame_sanity_check(int32_t arg1, int32_t arg2, int32_t arg3)
{
    return 0;
}

static inline int64_t now_us(void)
{
    return esp_timer_get_time();
}

/* -------------------- Helpers -------------------- */

static PacketInjector* findInjector(injectorManager *mgr, const char *name)
{
    if (!mgr || !name) return NULL;
    for (int i = 0; i < mgr->injectorCount; ++i) {
        if (strcmp(mgr->injectors[i].name, name) == 0) {
            return &mgr->injectors[i];
        }
    }
    return NULL;
}

/* createInjector - does not print errors; caller should decide */
static PacketInjector* createInjector(injectorManager *mgr, const char *name)
{
    if (!mgr || !name) return NULL;
    if (mgr->injectorCount >= MAX_INJECTORS) {
        return NULL;
    }

    PacketInjector *inj = &mgr->injectors[mgr->injectorCount];
    memset(inj, 0, sizeof(PacketInjector));
    strncpy(inj->name, name, MAX_INJECTOR_NAME - 1);
    inj->name[MAX_INJECTOR_NAME - 1] = '\0';

    inj->channel = 1;
    inj->txPower = -1;      // -1 == leave unchanged / not set
    inj->pps = 0;
    inj->maxPackets = 0;
    inj->packetLen = 0;
    inj->packetCount = 0;
    inj->startTime = 0;
    inj->lastSendTime = 0;

    mgr->injectorCount++;
    return inj;
}

/* -------------------- Public API -------------------- */

void injectorManager_init(injectorManager *mgr)
{
    if (!mgr) return;
    mgr->injectorCount = 0;
    mgr->totalPacketsAllTime = 0;
    mgr->currentTxPower = -1;
}

void injectorManager_startInjector(injectorManager *mgr, const char *injectorName,
                                   uint8_t *data, uint16_t len, uint8_t channel,
                                   uint32_t pps, uint32_t maxPackets,
                                   int8_t txPower)
{
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_ps(WIFI_PS_NONE);
    esp_wifi_start();
    esp_wifi_set_max_tx_power(84);
    
    if (!mgr || !injectorName) {
        printf("Error: invalid args to injectorManager_startInjector\n");
        return;
    }
    if (len > 0 && !data) {
        printf("Error: packet data is NULL but len > 0\n");
        return;
    }

    PacketInjector *inj = findInjector(mgr, injectorName);
    if (inj) {
        if (inj->active) {
            injectorManager_stopInjector(mgr, injectorName);
            inj = findInjector(mgr, injectorName);
            if (!inj) {
                inj = createInjector(mgr, injectorName);
                if (!inj) {
                    printf("Error: cannot (re)create injector %s: limit reached\n", injectorName);
                    return;
                }
            }
        }
    } else {
        inj = createInjector(mgr, injectorName);
        if (!inj) {
            printf("Error: cannot create injector %s: maximum limit (%d) reached\n", injectorName, MAX_INJECTORS);
            return;
        }
    }

    /* Populate injector */
    inj->active = true;
    inj->channel = channel;
    inj->pps = pps;
    inj->maxPackets = maxPackets;
    inj->packetCount = 0;
    inj->packetLen = (len <= MAX_PACKET_LEN) ? len : MAX_PACKET_LEN;
    inj->lastSendTime = 0;
    inj->startTime = now_us();
    inj->txPower = txPower;

    if (len > 0) {
        size_t copyLen = (len <= MAX_PACKET_LEN) ? len : MAX_PACKET_LEN;
        memcpy(inj->packetData, data, copyLen);
        if (len > MAX_PACKET_LEN) {
            printf("Warning: Packet for injector %s truncated to %d bytes\n", injectorName, MAX_PACKET_LEN);
        }
    }
}

void injectorManager_stopInjector(injectorManager *mgr, const char *injectorName)
{
    if (!mgr || !injectorName) return;

    PacketInjector *inj = findInjector(mgr, injectorName);
    if (!inj) {
        printf("Error: Injector %s not found\n", injectorName);
        return;
    }

    if (!inj->active) {
        printf("Injector %s already inactive\n", injectorName);
        return;
    }

    inj->active = false;

    if (inj->startTime > 0) {
        int64_t elapsed_us = now_us() - inj->startTime;
        double elapsed_s = (double)elapsed_us / 1000000.0;
        double avg_rate = (elapsed_s > 0.0) ? ((double)inj->packetCount / elapsed_s) : 0.0;
    }
}

void injectorManager_stopAllInjectors(injectorManager *mgr)
{
    if (!mgr) return;
    for (int i = 0; i < mgr->injectorCount; ++i) {
        if (mgr->injectors[i].active) {
            mgr->injectors[i].active = false;
        }
    }
}

void injectorManager_clearAllInjectors(injectorManager *mgr)
{
    if (!mgr) return;
    int total = mgr->injectorCount;
    mgr->injectorCount = 0;
}

void injectorManager_updateInjectors(injectorManager *mgr, int *currentChannel)
{
    if (!mgr || !currentChannel) return;

    int64_t now = now_us();

    for (int i = 0; i < mgr->injectorCount; ++i) {
        PacketInjector *inj = &mgr->injectors[i];
        if (!inj->active || inj->packetLen == 0) continue;

        /* Compute per-injector interval in microseconds */
        int64_t interval_us = 0;
        if (inj->pps > 0) {
            /* guard against division by zero and extreme values */
            if (inj->pps > 1000000U) {
                interval_us = 1; // at most 1 us interval (theoretical)
            } else {
                interval_us = (int64_t)1000000 / (int64_t)inj->pps;
            }
        }

        if (interval_us <= 0) continue;
        if ((now - inj->lastSendTime) < interval_us) continue; /* not yet time */

        /* Enforce maxPackets limit */
        if (inj->maxPackets > 0 && inj->packetCount >= inj->maxPackets) {
            inj->active = false;
            continue;
        }

        /* Switch channel if needed (single radio) */
        if (inj->channel != *currentChannel) {
            esp_err_t ch_err = esp_wifi_set_channel(inj->channel, WIFI_SECOND_CHAN_NONE);
            if (ch_err != ESP_OK) {
                printf("Warning: failed set channel %d (err %s) — skipping this send\n",
                       inj->channel, esp_err_to_name(ch_err));
                /* skip this send attempt; leave lastSendTime unchanged */
                continue;
            } else {
                *currentChannel = inj->channel;
            }
        }

        /* Set TX power if requested: convert dBm -> quarter-dBm SDK units */
        if (inj->txPower != -1 && inj->txPower != mgr->currentTxPower) {
            int dbm = (int)inj->txPower;
            if (dbm < 0) dbm = 0;
            if (dbm > 21) dbm = 21; /* clamp to 21 dBm => SDK 84 units */
            int8_t sdkPower = (int8_t)(dbm * 4);
            if (sdkPower > 84) sdkPower = 84;
            esp_err_t p_err = esp_wifi_set_max_tx_power(sdkPower);
            if (p_err != ESP_OK) {
                printf("Warning: failed to set TX power to %d dBm (sdk=%d) err %s\n",
                       dbm, (int)sdkPower, esp_err_to_name(p_err));
                /* do not change mgr->currentTxPower on failure */
            } else {
                mgr->currentTxPower = inj->txPower;
            }
        }

        /* Transmit packet and check return */
        esp_err_t tx_err = esp_wifi_80211_tx(WIFI_IF_STA, inj->packetData, inj->packetLen, false);
        if (tx_err != ESP_OK) {
            printf("Warning: esp_wifi_80211_tx failed (err %s) — injector %s\n",
                   esp_err_to_name(tx_err), inj->name);
            /* skip counters and timestamp update on failure */
            continue;
        }

        /* Successful transmit */
        inj->packetCount++;
        mgr->totalPacketsAllTime++;
        inj->lastSendTime = now;
    }
}

int injectorManager_getActiveInjectorCount(injectorManager *mgr)
{
    if (!mgr) return 0;
    int count = 0;
    for (int i = 0; i < mgr->injectorCount; ++i) {
        if (mgr->injectors[i].active) ++count;
    }
    return count;
}

uint32_t injectorManager_getTotalPacketsSent(injectorManager *mgr)
{
    if (!mgr) return 0;
    return mgr->totalPacketsAllTime;
}