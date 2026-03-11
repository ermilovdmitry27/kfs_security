#include "contiki.h"
#include "net/rime/broadcast.h"
#include "net/rime/mesh.h"
#include "attack_discovery.h"
#include "relay_discovery.h"
#include "security_control.h"
#include "lib/random.h"
#include <stdio.h>
#include <string.h>

#define DRONE_LOG 0

#define RADIO_CHANNEL_START 129
#define RADIO_CHANNEL_COUNT 4

#define MSG_VER 1

#define MAC_KEY 0x6a09e667u
#define DEFAULT_TX_PERIOD_SEC 1
#define POLICY_RECHECK_SEC 1
#define MAX_RELAYS 8

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

static uint8_t current_channel = RADIO_CHANNEL_START;
static uint8_t channel_index = 0;
static const uint8_t channel_list[RADIO_CHANNEL_COUNT] = {129, 130, 131, 132};
static const linkaddr_t sink_addr = {{1, 0}};
static struct etimer send_timer;
static uint8_t telemetry_period_sec = DEFAULT_TX_PERIOD_SEC;
static uint32_t rate_limit_until;
static uint32_t quarantine_until;
static uint8_t preferred_relay_id;
static uint8_t isolated_relay_id;
static uint32_t isolated_relay_until;

typedef struct {
  uint8_t used;
  uint8_t relay_id;
  uint8_t channel;
  uint32_t last_seen;
} relay_info_t;

static relay_info_t relays[MAX_RELAYS];

static void recv_mesh(struct mesh_conn *c, const linkaddr_t *from, uint8_t hops);
static const struct mesh_callbacks mesh_cb = { recv_mesh, NULL, NULL };
static struct mesh_conn mesh;
static void recv_discovery(struct broadcast_conn *c, const linkaddr_t *from);
static const struct broadcast_callbacks discovery_cb = { recv_discovery };
static struct broadcast_conn discovery;
static void recv_relay_discovery(struct broadcast_conn *c, const linkaddr_t *from);
static const struct broadcast_callbacks relay_discovery_cb = { recv_relay_discovery };
static struct broadcast_conn relay_discovery;

static relay_info_t *
find_or_create_relay(uint8_t relay_id)
{
  int i;
  int free_index = -1;

  for(i = 0; i < MAX_RELAYS; i++) {
    if(relays[i].used && relays[i].relay_id == relay_id) {
      return &relays[i];
    }
    if(!relays[i].used && free_index < 0) {
      free_index = i;
    }
  }

  if(free_index < 0) {
    return NULL;
  }

  memset(&relays[free_index], 0, sizeof(relays[free_index]));
  relays[free_index].used = 1;
  relays[free_index].relay_id = relay_id;
  return &relays[free_index];
}

static uint8_t
relay_visible(const relay_info_t *relay, uint32_t now)
{
  return (uint8_t)(relay != NULL && relay->used &&
                   now >= relay->last_seen &&
                   (now - relay->last_seen) <= RELAY_DISCOVERY_TIMEOUT_SEC);
}

static uint8_t
relay_isolated(uint8_t relay_id, uint32_t now)
{
  return (uint8_t)(relay_id != 0 && isolated_relay_id == relay_id &&
                   isolated_relay_until != 0 && now < isolated_relay_until);
}

static uint8_t
select_relay_candidate(uint8_t avoid_relay_id, uint32_t now)
{
  uint8_t best_id = 0;
  uint32_t best_seen = 0;
  int i;

  for(i = 0; i < MAX_RELAYS; i++) {
    if(!relay_visible(&relays[i], now) ||
       relay_isolated(relays[i].relay_id, now) ||
       relays[i].relay_id == avoid_relay_id) {
      continue;
    }
    if(best_id == 0 || relays[i].last_seen >= best_seen) {
      best_id = relays[i].relay_id;
      best_seen = relays[i].last_seen;
    }
  }

  return best_id;
}

static void
refresh_preferred_relay(uint8_t force_rotate, uint32_t now)
{
  relay_info_t *preferred = NULL;
  uint8_t next_relay = 0;

  if(isolated_relay_until != 0 && now >= isolated_relay_until) {
    isolated_relay_id = 0;
    isolated_relay_until = 0;
  }

  if(preferred_relay_id != 0) {
    preferred = find_or_create_relay(preferred_relay_id);
  }
  if(!force_rotate && relay_visible(preferred, now) &&
     !relay_isolated(preferred_relay_id, now)) {
    return;
  }

  next_relay = select_relay_candidate(preferred_relay_id, now);
  if(next_relay == 0 && (force_rotate || preferred == NULL ||
                         !relay_visible(preferred, now) ||
                         relay_isolated(preferred_relay_id, now))) {
    next_relay = select_relay_candidate(0, now);
  }
  preferred_relay_id = next_relay;
}

static void
schedule_next_send(uint8_t interval_sec)
{
  if(interval_sec == 0) {
    interval_sec = DEFAULT_TX_PERIOD_SEC;
  }
  etimer_set(&send_timer, CLOCK_SECOND * interval_sec);
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

  if(packetbuf_datalen() != sizeof(ctrl)) {
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

  now = clock_seconds();

  switch(ctrl.cmd) {
  case CTRL_CMD_HOP:
    set_channel(ctrl.value);
    break;
  case CTRL_CMD_REROUTE:
    refresh_preferred_relay(1, now);
    schedule_next_send(POLICY_RECHECK_SEC);
    break;
  case CTRL_CMD_ISOLATE_RELAY:
    if(preferred_relay_id != 0) {
      isolated_relay_id = preferred_relay_id;
      isolated_relay_until = now + (ctrl.duration == 0 ?
                             RELAY_DISCOVERY_TIMEOUT_SEC : ctrl.duration);
    }
    refresh_preferred_relay(1, now);
    schedule_next_send(POLICY_RECHECK_SEC);
    break;
  case CTRL_CMD_RATE_LIMIT:
    telemetry_period_sec = ctrl.value == 0 ? DEFAULT_TX_PERIOD_SEC : ctrl.value;
    rate_limit_until = now + (ctrl.duration == 0 ? 1 : ctrl.duration);
    schedule_next_send(telemetry_period_sec);
    break;
  case CTRL_CMD_QUARANTINE:
    quarantine_until = now + (ctrl.duration == 0 ? 1 : ctrl.duration);
    schedule_next_send(POLICY_RECHECK_SEC);
    break;
  default:
    break;
  }
}

static void
recv_discovery(struct broadcast_conn *c, const linkaddr_t *from)
{
  (void)c;
  (void)from;
}

static void
recv_relay_discovery(struct broadcast_conn *c, const linkaddr_t *from)
{
  relay_discovery_msg_t msg;
  relay_info_t *relay;
  uint32_t now;

  (void)c;
  (void)from;

  if(packetbuf_datalen() != sizeof(msg)) {
    return;
  }

  memcpy(&msg, packetbuf_dataptr(), sizeof(msg));
  if(msg.ver != MSG_VER || (msg.flags & RELAY_FLAG_FORWARDER) == 0 ||
     msg.relay_id == 0 || msg.relay_id == linkaddr_node_addr.u8[0]) {
    return;
  }

  relay = find_or_create_relay(msg.relay_id);
  if(relay == NULL) {
    return;
  }

  now = clock_seconds();
  relay->channel = msg.channel;
  relay->last_seen = now;
  refresh_preferred_relay(0, now);
}

PROCESS_THREAD(drone_proc, ev, data)
{
  static sensor_msg_t msg;
  static attack_discovery_msg_t discovery_msg;
  static linkaddr_t uplink_addr;
  static uint16_t seq;
  static uint16_t batt_mv;
  static uint32_t now;

  PROCESS_EXITHANDLER(mesh_close(&mesh); broadcast_close(&discovery); broadcast_close(&relay_discovery);)
  PROCESS_BEGIN();

  memset(relays, 0, sizeof(relays));
  seq = 0;
  batt_mv = 4200;
  telemetry_period_sec = DEFAULT_TX_PERIOD_SEC;
  rate_limit_until = 0;
  quarantine_until = 0;
  preferred_relay_id = 0;
  isolated_relay_id = 0;
  isolated_relay_until = 0;
  current_channel = channel_list[channel_index % RADIO_CHANNEL_COUNT];
  mesh_open(&mesh, current_channel, &mesh_cb);
  broadcast_open(&discovery, ATTACK_DISCOVERY_CHANNEL, &discovery_cb);
  broadcast_open(&relay_discovery, RELAY_DISCOVERY_CHANNEL, &relay_discovery_cb);
  schedule_next_send(DEFAULT_TX_PERIOD_SEC);

  while(1) {
    PROCESS_WAIT_EVENT();
    if(ev != PROCESS_EVENT_TIMER || data != &send_timer) {
      continue;
    }

    now = clock_seconds();
    if(rate_limit_until != 0 && now >= rate_limit_until) {
      rate_limit_until = 0;
      telemetry_period_sec = DEFAULT_TX_PERIOD_SEC;
    }
    if(quarantine_until != 0 && now >= quarantine_until) {
      quarantine_until = 0;
    }
    refresh_preferred_relay(0, now);
    if(quarantine_until != 0 && now < quarantine_until) {
      schedule_next_send(POLICY_RECHECK_SEC);
      continue;
    }

    msg.ver = MSG_VER;
    msg.drone_id = linkaddr_node_addr.u8[0];
    msg.seq = ++seq;
    msg.t = now;
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
    if(preferred_relay_id != 0) {
      uplink_addr.u8[0] = preferred_relay_id;
      uplink_addr.u8[1] = 0;
      mesh_send(&mesh, &uplink_addr);
    } else {
      mesh_send(&mesh, &sink_addr);
    }

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

    schedule_next_send(telemetry_period_sec);
  }

  PROCESS_END();
}
