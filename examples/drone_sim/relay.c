#include "contiki.h"
#include "net/rime/broadcast.h"
#include "net/rime/mesh.h"
#include "relay_discovery.h"
#include "security_control.h"
#include <stdio.h>
#include <string.h>

#define RADIO_CHANNEL_START 129
#define RADIO_CHANNEL_COUNT 4

#define MSG_VER 1

#define MAC_KEY 0x6a09e667u

#define RELAY_ATTACK_NONE 0
#define RELAY_ATTACK_BLACKHOLE 1
#define RELAY_ATTACK_SELECTIVE 2
#define SELECTIVE_TARGET_MASK 0x01

PROCESS(relay_proc, "Relay");
AUTOSTART_PROCESSES(&relay_proc);

static uint8_t current_channel = RADIO_CHANNEL_START;
static uint8_t channel_index = 0;
static const uint8_t channel_list[RADIO_CHANNEL_COUNT] = {129, 130, 131, 132};
static const linkaddr_t sink_addr = {{1, 0}};
static uint8_t relay_attack_mode = RELAY_ATTACK_NONE;
static uint32_t relay_attack_until;
static uint8_t selective_drop_toggle;

static void recv_mesh(struct mesh_conn *c, const linkaddr_t *from, uint8_t hops);
static const struct mesh_callbacks mesh_cb = { recv_mesh, NULL, NULL };
static struct mesh_conn mesh;
static void recv_discovery(struct broadcast_conn *c, const linkaddr_t *from);
static const struct broadcast_callbacks discovery_cb = { recv_discovery };
static struct broadcast_conn discovery;

static void
update_relay_attack(uint32_t now)
{
  if(relay_attack_until != 0 && now >= relay_attack_until) {
    relay_attack_until = 0;
    relay_attack_mode = RELAY_ATTACK_NONE;
    selective_drop_toggle = 0;
  }
}

static uint32_t
mac_fnv1a(const void *data, size_t len)
{
  const uint8_t *p = (const uint8_t *)data;
  uint32_t h = 2166136261u;
  uint32_t key = MAC_KEY;
  int i;
  for(i = 0; i < 4; i++) {
    h ^= (uint8_t)(key & 0xff);
    h *= 16777619u;
    key >>= 8;
  }
  for(size_t j = 0; j < len; j++) {
    h ^= p[j];
    h *= 16777619u;
  }
  return h;
}

static void
set_channel(uint8_t ch)
{
  if(ch == current_channel) {
    return;
  }
  mesh_close(&mesh);
  current_channel = ch;
  mesh_open(&mesh, current_channel, &mesh_cb);
}

static void
recv_mesh(struct mesh_conn *c, const linkaddr_t *from, uint8_t hops)
{
  control_msg_t ctrl;
  uint32_t now;
  (void)c;
  (void)from;
  (void)hops;

  now = clock_seconds();
  update_relay_attack(now);

  if(packetbuf_datalen() != sizeof(ctrl)) {
    if(relay_attack_mode == RELAY_ATTACK_BLACKHOLE) {
      return;
    }
    if(relay_attack_mode == RELAY_ATTACK_SELECTIVE) {
      uint8_t selective_target = (uint8_t)(from != NULL &&
                                           (from->u8[0] & SELECTIVE_TARGET_MASK) != 0);
      if(selective_target) {
        selective_drop_toggle = (uint8_t)!selective_drop_toggle;
        if(selective_drop_toggle) {
          return;
        }
      }
    }
    mesh_send(&mesh, &sink_addr);
    return;
  }

  memcpy(&ctrl, packetbuf_dataptr(), sizeof(ctrl));
  if(ctrl.ver != MSG_VER) {
    return;
  }

  uint32_t mac = ctrl.mac;
  ctrl.mac = 0;
  if(mac != mac_fnv1a(&ctrl, sizeof(ctrl))) {
    return;
  }

  if(ctrl.cmd == CTRL_CMD_HOP) {
    set_channel(ctrl.value);
  } else if(ctrl.cmd == CTRL_CMD_RELAY_BLACKHOLE) {
    relay_attack_mode = RELAY_ATTACK_BLACKHOLE;
    relay_attack_until = ctrl.duration == 0 ? 0 : now + ctrl.duration;
    selective_drop_toggle = 0;
  } else if(ctrl.cmd == CTRL_CMD_RELAY_SELECTIVE) {
    relay_attack_mode = RELAY_ATTACK_SELECTIVE;
    relay_attack_until = ctrl.duration == 0 ? 0 : now + ctrl.duration;
    selective_drop_toggle = 0;
  } else if(ctrl.cmd == CTRL_CMD_RELAY_NORMAL) {
    relay_attack_mode = RELAY_ATTACK_NONE;
    relay_attack_until = 0;
    selective_drop_toggle = 0;
  }
}

static void
recv_discovery(struct broadcast_conn *c, const linkaddr_t *from)
{
  (void)c;
  (void)from;
}

PROCESS_THREAD(relay_proc, ev, data)
{
  static struct etimer beacon_timer;
  static relay_discovery_msg_t beacon;
  (void)ev;
  (void)data;

  PROCESS_EXITHANDLER(mesh_close(&mesh); broadcast_close(&discovery);)
  PROCESS_BEGIN();

  current_channel = channel_list[channel_index % RADIO_CHANNEL_COUNT];
  relay_attack_mode = RELAY_ATTACK_NONE;
  relay_attack_until = 0;
  selective_drop_toggle = 0;
  mesh_open(&mesh, current_channel, &mesh_cb);
  broadcast_open(&discovery, RELAY_DISCOVERY_CHANNEL, &discovery_cb);
  etimer_set(&beacon_timer, CLOCK_SECOND * RELAY_DISCOVERY_BEACON_SEC);
  printf("Starting relay on channel %u\n", current_channel);

  while(1) {
    PROCESS_WAIT_EVENT();
    if(ev == PROCESS_EVENT_TIMER && data == &beacon_timer) {
      beacon.ver = MSG_VER;
      beacon.relay_id = linkaddr_node_addr.u8[0];
      beacon.channel = current_channel;
      beacon.flags = RELAY_FLAG_FORWARDER;
      packetbuf_copyfrom(&beacon, sizeof(beacon));
      broadcast_send(&discovery);
      etimer_reset(&beacon_timer);
    }
  }

  PROCESS_END();
}
