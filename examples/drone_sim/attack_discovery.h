#ifndef DRONE_SIM_ATTACK_DISCOVERY_H_
#define DRONE_SIM_ATTACK_DISCOVERY_H_

#include "contiki.h"

#define ATTACK_TARGET_SINK_ID 1
#define ATTACK_TARGET_ATTACKER_ID_BASE 200
#define ATTACK_DISCOVERY_CHANNEL 180

typedef struct {
  uint8_t ver;
  uint8_t drone_id;
  uint16_t seq;
  uint16_t temp;
  uint16_t vib;
  uint16_t gas;
  uint16_t batt_mv;
  uint32_t t;
  uint32_t mac;
} attack_sensor_msg_t;

typedef struct {
  uint8_t ver;
  uint8_t channel;
  uint8_t reserved0;
  uint8_t reserved1;
  attack_sensor_msg_t sensor;
} attack_discovery_msg_t;

#endif
