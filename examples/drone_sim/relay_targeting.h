#ifndef RELAY_TARGETING_H
#define RELAY_TARGETING_H

#include "contiki.h"
#include "net/rime/broadcast.h"
#include "relay_discovery.h"
#include <string.h>

#define MAX_RELAY_TARGETS 8

typedef struct {
  uint8_t used;
  uint8_t relay_id;
  uint8_t channel;
  uint32_t last_seen;
} relay_target_t;

static relay_target_t relay_targets[MAX_RELAY_TARGETS];
static struct broadcast_conn relay_target_discovery_conn;
static uint8_t relay_targeting_opened;

static relay_target_t *
relay_target_find_or_create(uint8_t relay_id)
{
  int i;
  int free_index = -1;

  for(i = 0; i < MAX_RELAY_TARGETS; i++) {
    if(relay_targets[i].used && relay_targets[i].relay_id == relay_id) {
      return &relay_targets[i];
    }
    if(!relay_targets[i].used && free_index < 0) {
      free_index = i;
    }
  }

  if(free_index < 0) {
    return NULL;
  }
  memset(&relay_targets[free_index], 0, sizeof(relay_targets[free_index]));
  relay_targets[free_index].used = 1;
  relay_targets[free_index].relay_id = relay_id;
  return &relay_targets[free_index];
}

static uint8_t
relay_target_visible(const relay_target_t *relay, uint32_t now)
{
  return (uint8_t)(relay != NULL && relay->used &&
                   now >= relay->last_seen &&
                   (now - relay->last_seen) <= RELAY_DISCOVERY_TIMEOUT_SEC);
}

static relay_target_t *
relay_target_pick(uint32_t now)
{
  relay_target_t *best = NULL;
  int i;

  for(i = 0; i < MAX_RELAY_TARGETS; i++) {
    if(!relay_target_visible(&relay_targets[i], now)) {
      continue;
    }
    if(best == NULL ||
       relay_targets[i].last_seen > best->last_seen ||
       (relay_targets[i].last_seen == best->last_seen &&
        relay_targets[i].relay_id > best->relay_id)) {
      best = &relay_targets[i];
    }
  }
  return best;
}

static void
relay_target_recv_discovery(struct broadcast_conn *c, const linkaddr_t *from)
{
  relay_discovery_msg_t msg;
  relay_target_t *relay;

  (void)c;
  (void)from;

  if(packetbuf_datalen() != sizeof(msg)) {
    return;
  }

  memcpy(&msg, packetbuf_dataptr(), sizeof(msg));
  if(msg.ver != 1 || (msg.flags & RELAY_FLAG_FORWARDER) == 0 ||
     msg.relay_id == 0 || msg.relay_id == linkaddr_node_addr.u8[0]) {
    return;
  }

  relay = relay_target_find_or_create(msg.relay_id);
  if(relay == NULL) {
    return;
  }
  relay->channel = msg.channel;
  relay->last_seen = clock_seconds();
}

static const struct broadcast_callbacks relay_target_discovery_cb = {
  relay_target_recv_discovery
};

static void
relay_targeting_init(void)
{
  memset(relay_targets, 0, sizeof(relay_targets));
  broadcast_open(&relay_target_discovery_conn,
                 RELAY_DISCOVERY_CHANNEL,
                 &relay_target_discovery_cb);
  relay_targeting_opened = 1;
}

static void
relay_targeting_close(void)
{
  if(relay_targeting_opened) {
    broadcast_close(&relay_target_discovery_conn);
    relay_targeting_opened = 0;
  }
}

#endif
