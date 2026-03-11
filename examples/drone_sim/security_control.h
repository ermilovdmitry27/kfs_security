#ifndef SECURITY_CONTROL_H
#define SECURITY_CONTROL_H

#include <stdint.h>

#define CTRL_CMD_HOP 1
#define CTRL_CMD_RATE_LIMIT 2
#define CTRL_CMD_QUARANTINE 3
#define CTRL_CMD_REROUTE 4
#define CTRL_CMD_ISOLATE_RELAY 5
#define CTRL_CMD_RELAY_BLACKHOLE 6
#define CTRL_CMD_RELAY_SELECTIVE 7
#define CTRL_CMD_RELAY_NORMAL 8

typedef struct {
  uint8_t ver;
  uint8_t cmd;
  uint8_t value;
  uint8_t duration;
  uint32_t t;
  uint32_t mac;
} control_msg_t;

#endif
