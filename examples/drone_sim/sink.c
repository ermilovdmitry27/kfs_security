#include "contiki.h"
#include "net/rime/mesh.h"
#include <stdio.h>
#include <string.h>

#define SINK_LOG 1
#define MAX_DRONES 16
#define OFFLINE_TIMEOUT_SEC 5
#define ATTACKER_ID_BASE 200

#define RADIO_CHANNEL_START 129
#define RADIO_CHANNEL_COUNT 4

#define MSG_VER 1
#define CTRL_CMD_HOP 1

#define MAC_KEY 0x6a09e667u

#define ALERT_GAS       0x01
#define ALERT_IMPACT    0x02
#define ALERT_FIRE      0x04
#define ALERT_BAT_LOW   0x08
#define ALERT_REPLAY    0x0010
#define ALERT_PKT_GAP   0x0020
#define ALERT_INVALID   0x0040
#define ALERT_FLOOD     0x0080
#define ALERT_SELECTIVE 0x0100
#define ALERT_BLACKHOLE 0x0200
#define ALERT_IMPERSONATION 0x0400

#define FLOOD_WINDOW_SEC 1
#define FLOOD_MAX_PER_WINDOW 5

#define HOP_COOLDOWN_SEC 5

#define SELECTIVE_MIN_SAMPLES 10
#define SELECTIVE_GLOBAL_MIN 30
#define SELECTIVE_MIN_PCT 30
#define SELECTIVE_MARGIN_PCT 20

PROCESS(sink_proc, "Sink");
AUTOSTART_PROCESSES(&sink_proc);


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

typedef struct {
  uint8_t used;
  uint8_t drone_id;
  uint16_t last_seq;
  uint32_t last_t;
  uint32_t missed_packets;
  uint8_t offline_reported;
  uint32_t data_count;
  uint32_t alert_count;
  uint32_t warn_count;
  uint32_t crit_count;
  uint32_t window_start;
  uint16_t window_count;
} drone_state_t;

static drone_state_t states[MAX_DRONES];
static uint32_t global_received;
static uint32_t global_missed;

static uint8_t current_channel = RADIO_CHANNEL_START;
static uint8_t channel_index = 0;
static const uint8_t channel_list[RADIO_CHANNEL_COUNT] = {129, 130, 131, 132};
static uint8_t hop_pending;
static uint8_t hop_target;
static uint32_t last_hop_time;

static void recv_mesh(struct mesh_conn *c, const linkaddr_t *from, uint8_t hops);
static const struct mesh_callbacks mesh_cb = { recv_mesh, NULL, NULL };
static struct mesh_conn mesh;

static const char *
alert_severity(uint16_t alerts)
{
  if(alerts & (ALERT_FIRE | ALERT_REPLAY | ALERT_INVALID | ALERT_IMPERSONATION)) {
    return "CRIT";
  }
  if(alerts != 0) {
    return "WARN";
  }
  return "INFO";
}

static const char *
detect_attack(uint16_t alerts)
{
  if(alerts & ALERT_INVALID) {
    return "spoofing";
  }
  if(alerts & ALERT_REPLAY) {
    return "replay";
  }
  if(alerts & ALERT_FLOOD) {
    return "flood";
  }
  if(alerts & ALERT_SELECTIVE) {
    return "selective_forwarding";
  }
  if(alerts & ALERT_BLACKHOLE) {
    return "blackhole";
  }
  if(alerts & ALERT_IMPERSONATION) {
    return "impersonation";
  }
  if(alerts & ALERT_PKT_GAP) {
    return "jamming";
  }
  return "none";
}

static const char *
detect_hazard(uint16_t alerts)
{
  uint8_t hazard_mask = alerts & (ALERT_GAS | ALERT_IMPACT | ALERT_FIRE | ALERT_BAT_LOW);
  if(hazard_mask == 0) {
    return "none";
  }
  if(alerts & ALERT_FIRE) {
    return "fire";
  }
  if(hazard_mask & (hazard_mask - 1)) {
    return "multi";
  }
  if(alerts & ALERT_GAS) {
    return "gas";
  }
  if(alerts & ALERT_IMPACT) {
    return "impact";
  }
  if(alerts & ALERT_BAT_LOW) {
    return "battery_low";
  }
  return "none";
}

static void
account_alert(drone_state_t *st, uint16_t alerts)
{
  if(alerts == 0) {
    return;
  }
  st->alert_count++;
  if(alerts & (ALERT_FIRE | ALERT_REPLAY | ALERT_INVALID | ALERT_IMPERSONATION)) {
    st->crit_count++;
  } else {
    st->warn_count++;
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
send_hop_command(const linkaddr_t *dest, uint8_t ch)
{
  control_msg_t ctrl;
  ctrl.ver = MSG_VER;
  ctrl.cmd = CTRL_CMD_HOP;
  ctrl.channel = ch;
  ctrl.reserved = 0;
  ctrl.t = clock_seconds();
  ctrl.mac = 0;
  ctrl.mac = mac_fnv1a(&ctrl, sizeof(ctrl));
  packetbuf_copyfrom(&ctrl, sizeof(ctrl));
  mesh_send(&mesh, dest);
}

static uint8_t
next_channel(void)
{
  channel_index = (uint8_t)((channel_index + 1) % RADIO_CHANNEL_COUNT);
  return channel_list[channel_index];
}

static void
send_hop_command_all(uint8_t ch)
{
  linkaddr_t dest;
  uint8_t self = linkaddr_node_addr.u8[0];
  uint8_t id;

  for(id = 1; id <= MAX_DRONES; id++) {
    if(id == self) {
      continue;
    }
    dest.u8[0] = id;
    dest.u8[1] = 0;
    send_hop_command(&dest, ch);
  }
}

static drone_state_t *
find_or_create_state(uint8_t drone_id)
{
  int i;
  int free_index = -1;
  for(i = 0; i < MAX_DRONES; i++) {
    if(states[i].used && states[i].drone_id == drone_id) {
      return &states[i];
    }
    if(!states[i].used && free_index < 0) {
      free_index = i;
    }
  }

  if(free_index < 0) {
    return NULL;
  }
  memset(&states[free_index], 0, sizeof(states[free_index]));
  states[free_index].used = 1;
  states[free_index].drone_id = drone_id;
  return &states[free_index];
}

static void recv_mesh(struct mesh_conn *c, const linkaddr_t *from, uint8_t hops)
{
  sensor_msg_t msg;
  drone_state_t *st;
  uint16_t alerts = 0;
  uint8_t invalid_id = 0;
  uint8_t invalid = 0;
  uint8_t invalid_mac = 0;
  uint8_t invalid_fields = 0;
  uint8_t rate_limited = 0;
  uint8_t replay_detected = 0;
  uint8_t is_attacker = 0;
  uint8_t sender_id = 0;
  uint16_t prev_seq = 0;
  uint32_t prev_t = 0;
  uint16_t gap = 0;
  uint32_t now = 0;
  uint32_t expected_mac = 0;

  (void)c;
  (void)hops;

  if(packetbuf_datalen() == sizeof(msg)) {
    memcpy(&msg, packetbuf_dataptr(), sizeof(msg));
    st = find_or_create_state(msg.drone_id);
    if(st == NULL) {
      return;
    }

    sender_id = from->u8[0];
    if(msg.drone_id != sender_id) {
      invalid_id = 1;
    }
    if(sender_id >= ATTACKER_ID_BASE) {
      is_attacker = 1;
    }

    expected_mac = msg.mac;
    msg.mac = 0;
    if(expected_mac != mac_fnv1a(&msg, sizeof(msg))) {
      invalid_mac = 1;
    }
    if(msg.ver != MSG_VER) {
      invalid_fields = 1;
    }

    if(msg.temp > 120 || msg.vib > 1500 || msg.gas > 2000 ||
       msg.batt_mv < 2600 || msg.batt_mv > 5000) {
      invalid_fields = 1;
    }

    if(invalid_mac || invalid_fields) {
      alerts |= ALERT_INVALID;
    }
    invalid = (uint8_t)(invalid_mac || invalid_fields);

    if(msg.gas >= 380) {
      alerts |= ALERT_GAS;
    }
    if(msg.vib >= 180) {
      alerts |= ALERT_IMPACT;
    }
    if(msg.temp >= 45 && msg.gas >= 300) {
      alerts |= ALERT_FIRE;
    }
    if(msg.batt_mv <= 3400) {
      alerts |= ALERT_BAT_LOW;
    }

    if(st->last_seq != 0) {
      prev_seq = st->last_seq;
      prev_t = st->last_t;
      if(msg.seq <= st->last_seq) {
        alerts |= ALERT_REPLAY;
        replay_detected = 1;
      } else if(msg.seq > (uint16_t)(st->last_seq + 1)) {
        gap = (uint16_t)(msg.seq - st->last_seq - 1);
        st->missed_packets += gap;
        if(!is_attacker) {
          global_missed += gap;
        }
        alerts |= ALERT_PKT_GAP;
      }
      if(prev_t != 0 && (msg.t > prev_t + OFFLINE_TIMEOUT_SEC)) {
        alerts |= ALERT_PKT_GAP;
      }
    }

    if(invalid_id && !invalid_mac && !invalid_fields && !replay_detected) {
      alerts |= ALERT_IMPERSONATION;
    }

    now = clock_seconds();
    if(st->window_start == 0 || now - st->window_start >= FLOOD_WINDOW_SEC) {
      st->window_start = now;
      st->window_count = 0;
    }
    st->window_count++;
    if(st->window_count > FLOOD_MAX_PER_WINDOW) {
      alerts |= ALERT_FLOOD;
      rate_limited = 1;
    }

    if(!rate_limited) {
      if(!invalid && !replay_detected) {
        st->last_seq = msg.seq;
        st->last_t = msg.t;
        if(!is_attacker) {
          st->data_count++;
          global_received++;
        }
      }
    } else {
      if(!invalid && !replay_detected && msg.seq > st->last_seq) {
        st->last_seq = msg.seq;
        st->last_t = msg.t;
      }
    }

    if(!is_attacker && !rate_limited && (alerts & ALERT_PKT_GAP)) {
      uint32_t node_total = st->data_count + st->missed_packets;
      uint32_t global_total = global_received + global_missed;
      if(node_total >= SELECTIVE_MIN_SAMPLES && global_total >= SELECTIVE_GLOBAL_MIN) {
        uint32_t node_loss_pct = (st->missed_packets * 100u) / node_total;
        uint32_t global_loss_pct = (global_missed * 100u) / global_total;
        if(node_loss_pct >= SELECTIVE_MIN_PCT &&
           node_loss_pct >= (global_loss_pct + SELECTIVE_MARGIN_PCT)) {
          alerts |= ALERT_SELECTIVE;
        }
      }
    }

    account_alert(st, alerts);
    st->offline_reported = 0;

#if SINK_LOG
    if(!is_attacker) {
      printf("DATA,id=%u,from=%u.%u,seq=%u,t=%lu,temp=%u,vib=%u,gas=%u,batt=%u,alerts=0x%04x\n",
             msg.drone_id, from->u8[0], from->u8[1], msg.seq, (unsigned long)msg.t,
             msg.temp, msg.vib, msg.gas, msg.batt_mv, alerts);
      printf("CSV_DATA,%lu,%s,%u,%u,%u,%u,%u,%u,%u,%u,%lu,%lu,%lu,%lu,%s,%s\n",
             (unsigned long)clock_seconds(), alert_severity(alerts), msg.drone_id, msg.seq,
             msg.temp, msg.vib, msg.gas, msg.batt_mv, alerts, st->missed_packets,
             (unsigned long)st->data_count, (unsigned long)st->alert_count,
             (unsigned long)st->warn_count, (unsigned long)st->crit_count,
             detect_attack(alerts),
             detect_hazard(alerts));
    }
    if(alerts != 0) {
      printf("ALERT,sev=%s,attack=%s,hazard=%s,id=%u,seq=%u,flags=0x%04x,prev_seq=%u,gap=%u,missed_total=%lu,alerts_total=%lu\n",
             alert_severity(alerts), detect_attack(alerts),
             detect_hazard(alerts),
             msg.drone_id, msg.seq, alerts, prev_seq, gap,
             (unsigned long)st->missed_packets, (unsigned long)st->alert_count);
      printf("CSV_ALERT,%lu,%s,%u,%u,%u,%u,%u,%u,%u,%u,%lu,%lu,%lu,%lu,%s,%s\n",
             (unsigned long)clock_seconds(), alert_severity(alerts), msg.drone_id,
             msg.seq, msg.temp, msg.vib, msg.gas, msg.batt_mv, alerts,
             (unsigned long)st->missed_packets, (unsigned long)st->data_count,
             (unsigned long)st->alert_count, (unsigned long)st->warn_count,
             (unsigned long)st->crit_count, detect_attack(alerts),
             detect_hazard(alerts));
    }
#endif

    if(!is_attacker && (alerts & ALERT_PKT_GAP) &&
       (now - last_hop_time) >= HOP_COOLDOWN_SEC) {
      hop_target = next_channel();
      hop_pending = 1;
      last_hop_time = now;
      process_poll(&sink_proc);
    }
  }
}

PROCESS_THREAD(sink_proc, ev, data)
{
  static struct etimer monitor_timer;
  int i;
  uint32_t now;

  PROCESS_BEGIN();

  memset(states, 0, sizeof(states));
  current_channel = channel_list[channel_index % RADIO_CHANNEL_COUNT];
  mesh_open(&mesh, current_channel, &mesh_cb);
  etimer_set(&monitor_timer, CLOCK_SECOND);
#if SINK_LOG
  printf("CSV_HEADER,sim_t,severity,drone_id,seq,temp,vib,gas,batt_mv,alerts,missed_total,data_count,alert_count,warn_count,crit_count,attack,hazard\n");
#endif

  while(1) {
    PROCESS_WAIT_EVENT();

    if(ev == PROCESS_EVENT_POLL && hop_pending) {
      hop_pending = 0;
      send_hop_command_all(hop_target);
      set_channel(hop_target);
    } else if(ev == PROCESS_EVENT_TIMER && data == &monitor_timer) {
      now = clock_seconds();
      for(i = 0; i < MAX_DRONES; i++) {
        if(states[i].used &&
           states[i].drone_id < ATTACKER_ID_BASE &&
           states[i].last_t > 0 &&
           !states[i].offline_reported &&
          now > (states[i].last_t + OFFLINE_TIMEOUT_SEC)) {
#if SINK_LOG
          uint16_t offline_alerts = ALERT_PKT_GAP | ALERT_BLACKHOLE;
          account_alert(&states[i], offline_alerts);
          printf("ALERT,sev=%s,attack=%s,hazard=%s,id=%u,seq=%u,flags=0x%04x,reason=offline,last_t=%lu,now=%lu,alerts_total=%lu\n",
                 alert_severity(offline_alerts), detect_attack(offline_alerts),
                 detect_hazard(offline_alerts),
                 states[i].drone_id, states[i].last_seq, offline_alerts,
                 (unsigned long)states[i].last_t, (unsigned long)now,
                 (unsigned long)states[i].alert_count);
          printf("CSV_ALERT,%lu,%s,%u,%u,%u,%u,%u,%u,%u,%u,%lu,%lu,%lu,%lu,%s,%s\n",
                 (unsigned long)now, alert_severity(offline_alerts),
                 states[i].drone_id, states[i].last_seq, 0, 0, 0, 0, offline_alerts,
                 (unsigned long)states[i].missed_packets, (unsigned long)states[i].data_count,
                 (unsigned long)states[i].alert_count, (unsigned long)states[i].warn_count,
                 (unsigned long)states[i].crit_count, detect_attack(offline_alerts),
                 detect_hazard(offline_alerts));
#endif
          states[i].offline_reported = 1;
        }
      }
      etimer_reset(&monitor_timer);
    }
  }

  PROCESS_END();
}
