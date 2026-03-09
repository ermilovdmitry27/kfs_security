#ifndef DRONE_SIM_ATTACK_TARGETING_H_
#define DRONE_SIM_ATTACK_TARGETING_H_

#include "contiki.h"
#include "net/rime/broadcast.h"
#include "attack_discovery.h"
#include <string.h>

#define ATTACK_TARGET_MAX 16
#define ATTACK_TARGET_TIMEOUT_SEC 8

#if defined(__GNUC__)
#define ATTACK_TARGET_UNUSED __attribute__((unused))
#else
#define ATTACK_TARGET_UNUSED
#endif

typedef struct {
  uint8_t used;
  uint8_t drone_id;
  uint8_t channel;
  uint16_t last_seen_seq;
  uint32_t last_seen_t;
  uint16_t forged_seq;
  attack_sensor_msg_t last_seen_msg;
} attack_target_t;

typedef void (*attack_target_visit_fn)(attack_target_t *target, void *ctx);

static attack_target_t attack_targets[ATTACK_TARGET_MAX];
static struct broadcast_conn attack_target_discovery_conn;
static uint8_t attack_targets_started;

static uint8_t
attack_target_is_active(const attack_target_t *target, uint32_t now)
{
  if(!target->used) {
    return 0;
  }
  return (uint8_t)((now - target->last_seen_t) <= ATTACK_TARGET_TIMEOUT_SEC);
}

static attack_target_t *
attack_target_prepare_slot(uint8_t drone_id, uint32_t now)
{
  int i;
  int free_index;
  int stale_index;
  int oldest_index;
  uint32_t oldest_t;

  free_index = -1;
  stale_index = -1;
  oldest_index = -1;
  oldest_t = 0;

  for(i = 0; i < ATTACK_TARGET_MAX; i++) {
    if(attack_targets[i].used && attack_targets[i].drone_id == drone_id) {
      return &attack_targets[i];
    }
    if(!attack_targets[i].used && free_index < 0) {
      free_index = i;
      continue;
    }
    if(attack_targets[i].used && !attack_target_is_active(&attack_targets[i], now) &&
       stale_index < 0) {
      stale_index = i;
    }
    if(attack_targets[i].used &&
       (oldest_index < 0 || attack_targets[i].last_seen_t < oldest_t)) {
      oldest_index = i;
      oldest_t = attack_targets[i].last_seen_t;
    }
  }

  if(free_index < 0) {
    free_index = stale_index;
  }
  if(free_index < 0) {
    free_index = oldest_index;
  }
  if(free_index < 0) {
    return NULL;
  }

  memset(&attack_targets[free_index], 0, sizeof(attack_targets[free_index]));
  attack_targets[free_index].used = 1;
  attack_targets[free_index].drone_id = drone_id;
  return &attack_targets[free_index];
}

static void
attack_targets_recv_discovery(struct broadcast_conn *c, const linkaddr_t *from)
{
  attack_discovery_msg_t msg;
  attack_target_t *target;
  uint32_t now;
  uint8_t sender_id;
  (void)c;

  if(packetbuf_datalen() != sizeof(msg)) {
    return;
  }

  memcpy(&msg, packetbuf_dataptr(), sizeof(msg));
  if(msg.ver != 1 || msg.sensor.ver != 1) {
    return;
  }

  sender_id = from->u8[0];
  if(msg.sensor.drone_id <= ATTACK_TARGET_SINK_ID ||
     msg.sensor.drone_id >= ATTACK_TARGET_ATTACKER_ID_BASE ||
     sender_id != msg.sensor.drone_id) {
    return;
  }

  now = clock_seconds();
  target = attack_target_prepare_slot(msg.sensor.drone_id, now);
  if(target == NULL) {
    return;
  }

  target->drone_id = msg.sensor.drone_id;
  target->channel = msg.channel;
  target->last_seen_seq = msg.sensor.seq;
  target->last_seen_t = now;
  target->last_seen_msg = msg.sensor;
  if(target->forged_seq < msg.sensor.seq) {
    target->forged_seq = msg.sensor.seq;
  }
}

static const struct broadcast_callbacks attack_target_discovery_cb = {
  attack_targets_recv_discovery
};

static void
attack_targets_init(void)
{
  memset(attack_targets, 0, sizeof(attack_targets));
  broadcast_open(&attack_target_discovery_conn,
                 ATTACK_DISCOVERY_CHANNEL,
                 &attack_target_discovery_cb);
  attack_targets_started = 1;
}

static void
attack_targets_shutdown(void)
{
  if(attack_targets_started) {
    broadcast_close(&attack_target_discovery_conn);
    attack_targets_started = 0;
  }
}

static uint16_t ATTACK_TARGET_UNUSED
attack_target_next_seq(attack_target_t *target)
{
  uint16_t next_seq;

  next_seq = target->forged_seq;
  if(next_seq < target->last_seen_seq) {
    next_seq = target->last_seen_seq;
  }
  next_seq++;
  if(next_seq == 0) {
    next_seq = 1;
  }
  target->forged_seq = next_seq;
  return next_seq;
}

static uint16_t ATTACK_TARGET_UNUSED
attack_target_replay_seq(const attack_target_t *target)
{
  if(target->last_seen_seq == 0) {
    return 1;
  }
  return target->last_seen_seq;
}

static uint8_t
attack_targets_for_each(attack_target_visit_fn visit, void *ctx)
{
  int i;
  uint8_t count;
  uint32_t now;

  count = 0;
  now = clock_seconds();

  for(i = 0; i < ATTACK_TARGET_MAX; i++) {
    if(!attack_target_is_active(&attack_targets[i], now)) {
      if(attack_targets[i].used) {
        memset(&attack_targets[i], 0, sizeof(attack_targets[i]));
      }
      continue;
    }
    count++;
    if(visit != NULL) {
      visit(&attack_targets[i], ctx);
    }
  }

  return count;
}

#endif
