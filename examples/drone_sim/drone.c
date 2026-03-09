#include "contiki.h"
#include "net/rime/broadcast.h"
#include "net/rime/mesh.h"
#include "attack_discovery.h"
#include "lib/random.h"
#include <stdio.h>
#include <string.h>

#define DRONE_LOG 0

#define RADIO_CHANNEL_START 129
#define RADIO_CHANNEL_COUNT 4

#define MSG_VER 1
#define CTRL_CMD_HOP 1

#define MAC_KEY 0x6a09e667u

PROCESS(drone_proc, "Drone sensors");
AUTOSTART_PROCESSES(&drone_proc);

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
static void recv_discovery(struct broadcast_conn *c, const linkaddr_t *from);
static const struct broadcast_callbacks discovery_cb = { recv_discovery };
static struct broadcast_conn discovery;

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

static void
recv_discovery(struct broadcast_conn *c, const linkaddr_t *from)
{
  (void)c;
  (void)from;
}

PROCESS_THREAD(drone_proc, ev, data)
{
  static struct etimer timer;
  static sensor_msg_t msg;
  static attack_discovery_msg_t discovery_msg;
  static uint16_t seq;
  static uint16_t batt_mv;

  PROCESS_EXITHANDLER(mesh_close(&mesh); broadcast_close(&discovery);)
  PROCESS_BEGIN();

  seq = 0;
  batt_mv = 4200;
  current_channel = channel_list[channel_index % RADIO_CHANNEL_COUNT];
  mesh_open(&mesh, current_channel, &mesh_cb);
  broadcast_open(&discovery, ATTACK_DISCOVERY_CHANNEL, &discovery_cb);
  etimer_set(&timer, CLOCK_SECOND);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

    msg.ver = MSG_VER;
    msg.drone_id = linkaddr_node_addr.u8[0];
    msg.seq = ++seq;
    msg.t = clock_seconds();
    msg.temp = 20 + (random_rand() % 20);  /* 20..39 C */
    msg.vib  = random_rand() % 200;        /* условная вибрация */
    msg.gas  = random_rand() % 500;        /* условный газ/дым */
    if((seq % 20) == 0) {
      /* Инъекция тревожного события для проверки правил sink */
      msg.temp = 50 + (random_rand() % 10);
      msg.gas = 420 + (random_rand() % 70);
    }
    if((seq % 35) == 0) {
      msg.vib = 220 + (random_rand() % 50);
    }
    if(batt_mv > 3300) {
      batt_mv -= (random_rand() % 2);
    }
    msg.batt_mv = batt_mv;
    msg.mac = 0;
    msg.mac = mac_fnv1a(&msg, sizeof(msg));

    packetbuf_copyfrom(&msg, sizeof(msg));
    mesh_send(&mesh, &sink_addr);

    discovery_msg.ver = MSG_VER;
    discovery_msg.channel = current_channel;
    discovery_msg.reserved0 = 0;
    discovery_msg.reserved1 = 0;
    memcpy(&discovery_msg.sensor, &msg, sizeof(msg));
    packetbuf_copyfrom(&discovery_msg, sizeof(discovery_msg));
    broadcast_send(&discovery);

#if DRONE_LOG
    printf("DRONE id=%u seq=%u t=%lu temp=%u vib=%u gas=%u batt=%u\n",
           msg.drone_id, msg.seq, (unsigned long)msg.t,
           msg.temp, msg.vib, msg.gas, msg.batt_mv);
#endif

    etimer_reset(&timer);
  }

  PROCESS_END();
}
