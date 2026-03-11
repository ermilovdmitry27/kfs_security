#ifndef RELAY_DISCOVERY_H
#define RELAY_DISCOVERY_H

#include <stdint.h>

#define RELAY_DISCOVERY_CHANNEL 146
#define RELAY_DISCOVERY_BEACON_SEC 1
#define RELAY_DISCOVERY_TIMEOUT_SEC 4

#define RELAY_FLAG_FORWARDER 0x01

typedef struct {
  uint8_t ver;
  uint8_t relay_id;
  uint8_t channel;
  uint8_t flags;
} relay_discovery_msg_t;

#endif
