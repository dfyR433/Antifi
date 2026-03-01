#ifndef INJECT_H
#define INJECT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#define MAX_INJECTORS        16
#define MAX_INJECTOR_NAME    32
#define MAX_PACKET_LEN       512

typedef struct {
    char     name[MAX_INJECTOR_NAME]; /* NUL-terminated name */
    bool     active;                  /* true if injector is active */
    uint8_t  channel;                 /* Wi-Fi channel desired (1..14) */
    uint32_t pps;                     /* target packets-per-second (0 == disabled) */
    uint32_t maxPackets;              /* max packets to send (0 == unlimited) */
    uint32_t packetCount;             /* packets sent so far */
    uint16_t packetLen;               /* length of valid bytes in packetData */
    uint8_t  packetData[MAX_PACKET_LEN]; /* packet buffer (raw 802.11 payload) */

    /* timing in microseconds (esp_timer_get_time()) */
    int64_t  startTime;               /* time when injector started (us), 0 if never started */
    int64_t  lastSendTime;            /* last successful send timestamp in us */
    int8_t   txPower;
} PacketInjector;

typedef struct {
    PacketInjector injectors[MAX_INJECTORS];
    int            injectorCount;       /* number of valid injectors in the array */
    int8_t         currentTxPower;      /* last-applied tx power (dBm), -1 if unknown */
    uint32_t       totalPacketsAllTime; /* all-time counter (wraps at 32 bits) */
} injectorManager;

void injectorManager_init(injectorManager *mgr);
void injectorManager_startInjector(injectorManager *mgr, const char *injectorName,
                                   uint8_t *data, uint16_t len, uint8_t channel,
                                   uint32_t pps, uint32_t maxPackets,
                                   int8_t txPower);
void injectorManager_stopInjector(injectorManager *mgr, const char *injectorName);
void injectorManager_stopAllInjectors(injectorManager *mgr);
void injectorManager_clearAllInjectors(injectorManager *mgr);
void injectorManager_updateInjectors(injectorManager *mgr, int *currentChannel);

/* Query helpers */
int     injectorManager_getActiveInjectorCount(injectorManager *mgr);
uint32_t injectorManager_getTotalPacketsSent(injectorManager *mgr);

#ifdef __cplusplus
}
#endif

#endif /* INJECT_H */