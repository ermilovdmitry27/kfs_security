#include "contiki.h"
#include "net/rime/broadcast.h"
#include "net/rime/mesh.h"
#include "relay_discovery.h"
#include "security_control.h"
#include <stdio.h>
#include <string.h>

#define SINK_LOG 1
#define MAX_DRONES 16
#define MAX_SOURCES 32
#define MAX_RELAYS 16
#define OFFLINE_TIMEOUT_SEC 5
#define ATTACKER_ID_BASE 200

#define RADIO_CHANNEL_START 129
#define RADIO_CHANNEL_COUNT 4

#define MSG_VER 1

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
#define SECURITY_ALERT_MASK \
  (ALERT_REPLAY | ALERT_PKT_GAP | ALERT_INVALID | ALERT_FLOOD | \
   ALERT_SELECTIVE | ALERT_BLACKHOLE | ALERT_IMPERSONATION)

#define FLOOD_WINDOW_SEC 1
#define FLOOD_MAX_PER_WINDOW 5
#define SOURCE_CLASSIFY_WINDOW_SEC 2

#define HOP_COOLDOWN_SEC 5
#define REROUTE_COOLDOWN_SEC 5
#define RATE_LIMIT_PERIOD_SEC 3
#define RATE_LIMIT_DURATION_SEC 12
#define QUARANTINE_DURATION_SEC 8
#define RELAY_ISOLATION_DURATION_SEC 10
#define FLOOD_OFFLINE_SUPPRESS_SEC 60
#define JAMMING_OFFLINE_SUPPRESS_SEC 20

#define SELECTIVE_MIN_SAMPLES 4
#define SELECTIVE_GLOBAL_MIN 10
#define SELECTIVE_MIN_PCT 20
#define SELECTIVE_MARGIN_PCT 5

#define RISK_MAX 100
#define RISK_DECAY_IDLE 5

#define SEC_STATE_NORMAL 0
#define SEC_STATE_SUSPICIOUS 1
#define SEC_STATE_UNDER_ATTACK 2
#define SEC_STATE_ISOLATED 3
#define SEC_STATE_RECOVERING 4
#define SEC_STATE_RECOVERED 5

#define SEC_RESPONSE_NONE 0
#define SEC_RESPONSE_OBSERVE 1
#define SEC_RESPONSE_CHANNEL_HOP 2
#define SEC_RESPONSE_RATE_LIMIT 3
#define SEC_RESPONSE_QUARANTINE 4
#define SEC_RESPONSE_REROUTE 5
#define SEC_RESPONSE_ISOLATE_RELAY 6

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
  uint8_t used;
  uint8_t drone_id;
  uint8_t risk_score;
  uint8_t security_state;
  uint8_t last_response;
  uint8_t source_managed_rate_limit;
  uint8_t last_policy_reason_code;
  uint32_t quarantine_until;
  uint32_t rate_limit_until;
  uint32_t offline_grace_until;
  uint32_t last_policy_reason_time;
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

typedef struct {
  uint8_t used;
  uint8_t sender_id;
  uint8_t report_drone_id;
  uint8_t rate_limit_period;
  uint8_t classification_granted;
  uint32_t quarantine_until;
  uint32_t rate_limit_until;
  uint32_t next_allowed_time;
  uint32_t classify_until;
  uint32_t window_start;
  uint16_t window_count;
} source_state_t;

typedef struct {
  uint8_t used;
  uint8_t relay_id;
  uint32_t last_seen;
} relay_state_t;

static drone_state_t states[MAX_DRONES];
static source_state_t sources[MAX_SOURCES];
static relay_state_t relays[MAX_RELAYS];
static uint32_t global_received;
static uint32_t global_missed;

static uint8_t current_channel = RADIO_CHANNEL_START;
static uint8_t channel_index = 0;
static const uint8_t channel_list[RADIO_CHANNEL_COUNT] = {129, 130, 131, 132};
static uint8_t hop_pending;
static uint8_t hop_target;
static uint32_t last_hop_time;
static uint32_t last_reroute_time;
static uint32_t last_global_flood_time;
static uint32_t last_global_jamming_time;

static void recv_mesh(struct mesh_conn *c, const linkaddr_t *from, uint8_t hops);
static const struct mesh_callbacks mesh_cb = { recv_mesh, NULL, NULL };
static struct mesh_conn mesh;
static void recv_relay_discovery(struct broadcast_conn *c, const linkaddr_t *from);
static const struct broadcast_callbacks relay_discovery_cb = { recv_relay_discovery };
static struct broadcast_conn relay_discovery;

static const char *security_state_name(uint8_t state);
static uint8_t risk_delta_for_alerts(uint16_t alerts);
static void update_security_posture(drone_state_t *st, uint16_t alerts);
static uint8_t security_response_code(uint16_t alerts, uint8_t security_state);
static const char *security_response_name(uint8_t response);
static const char *security_response(uint16_t alerts, uint8_t security_state);
static uint8_t quarantine_active(const drone_state_t *st, uint32_t now);
static uint8_t rate_limit_active(const drone_state_t *st, uint32_t now);
static uint8_t flood_recovery_active(const drone_state_t *st, uint32_t now);
static uint8_t source_quarantine_active(const source_state_t *src, uint32_t now);
static uint8_t source_rate_limit_active(const source_state_t *src, uint32_t now);
static void release_security_policy(drone_state_t *st, const char *reason,
                                    uint32_t now, uint8_t reset_liveness);
static void release_source_policy(source_state_t *src, const char *reason,
                                  uint32_t now);
static void emit_security_decision(drone_state_t *st, uint16_t alerts,
                                   const char *reason, uint8_t prev_state,
                                   uint8_t prev_response);
static void apply_security_policy(drone_state_t *st, uint8_t sender_id,
                                  uint16_t alerts, uint32_t now);

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

static const char *
security_state_name(uint8_t state)
{
  switch(state) {
  case SEC_STATE_SUSPICIOUS:
    return "SUSPICIOUS";
  case SEC_STATE_UNDER_ATTACK:
    return "UNDER_ATTACK";
  case SEC_STATE_ISOLATED:
    return "ISOLATED";
  case SEC_STATE_RECOVERING:
    return "RECOVERING";
  case SEC_STATE_RECOVERED:
    return "RECOVERED";
  default:
    return "NORMAL";
  }
}

static uint8_t
risk_delta_for_alerts(uint16_t alerts)
{
  uint16_t security_alerts = alerts & SECURITY_ALERT_MASK;
  uint16_t delta = 0;

  if(security_alerts & ALERT_INVALID) {
    delta += 35;
  }
  if(security_alerts & ALERT_IMPERSONATION) {
    delta += 30;
  }
  if(security_alerts & ALERT_REPLAY) {
    delta += 25;
  }
  if(security_alerts & ALERT_FLOOD) {
    delta += 20;
  }
  if(security_alerts & ALERT_SELECTIVE) {
    delta += 25;
  }
  if(security_alerts & ALERT_BLACKHOLE) {
    delta += 40;
  }
  if((security_alerts & ALERT_PKT_GAP) && !(security_alerts & ALERT_BLACKHOLE)) {
    delta += 15;
  }

  if(delta > RISK_MAX) {
    return RISK_MAX;
  }
  return (uint8_t)delta;
}

static void
update_security_posture(drone_state_t *st, uint16_t alerts)
{
  uint16_t security_alerts = alerts & SECURITY_ALERT_MASK;
  uint16_t risk = st->risk_score;
  uint8_t prev_state = st->security_state;

  if(security_alerts == 0) {
    if(risk > RISK_DECAY_IDLE) {
      risk -= RISK_DECAY_IDLE;
    } else {
      risk = 0;
    }
    st->risk_score = (uint8_t)risk;
    if(risk == 0) {
      if(prev_state != SEC_STATE_NORMAL && prev_state != SEC_STATE_RECOVERED) {
        st->security_state = SEC_STATE_RECOVERED;
      } else {
        st->security_state = SEC_STATE_NORMAL;
      }
    } else {
      st->security_state = SEC_STATE_RECOVERING;
    }
    return;
  }

  risk += risk_delta_for_alerts(security_alerts);
  if(risk > RISK_MAX) {
    risk = RISK_MAX;
  }
  st->risk_score = (uint8_t)risk;

  if(security_alerts & ALERT_BLACKHOLE) {
    st->security_state = SEC_STATE_ISOLATED;
  } else if(risk >= 60 ||
            (security_alerts & (ALERT_INVALID | ALERT_IMPERSONATION |
                                ALERT_REPLAY | ALERT_FLOOD | ALERT_SELECTIVE))) {
    st->security_state = SEC_STATE_UNDER_ATTACK;
  } else {
    st->security_state = SEC_STATE_SUSPICIOUS;
  }
}

static const char *
security_response_name(uint8_t response)
{
  switch(response) {
  case SEC_RESPONSE_OBSERVE:
    return "observe";
  case SEC_RESPONSE_CHANNEL_HOP:
    return "channel_hop";
  case SEC_RESPONSE_RATE_LIMIT:
    return "rate_limit";
  case SEC_RESPONSE_QUARANTINE:
    return "quarantine";
  case SEC_RESPONSE_REROUTE:
    return "reroute";
  case SEC_RESPONSE_ISOLATE_RELAY:
    return "isolate_relay";
  default:
    return "none";
  }
}

static uint8_t
security_response_code(uint16_t alerts, uint8_t security_state)
{
  uint16_t security_alerts = alerts & SECURITY_ALERT_MASK;

  if(security_alerts & ALERT_BLACKHOLE) {
    return SEC_RESPONSE_ISOLATE_RELAY;
  }
  if(security_alerts & ALERT_SELECTIVE) {
    return SEC_RESPONSE_REROUTE;
  }
  if(security_alerts & ALERT_PKT_GAP) {
    return SEC_RESPONSE_CHANNEL_HOP;
  }
  if(security_alerts & ALERT_FLOOD) {
    return SEC_RESPONSE_RATE_LIMIT;
  }
  if(security_alerts & (ALERT_INVALID | ALERT_IMPERSONATION | ALERT_REPLAY)) {
    return SEC_RESPONSE_QUARANTINE;
  }
  if(security_state == SEC_STATE_RECOVERING || security_state == SEC_STATE_RECOVERED) {
    return SEC_RESPONSE_OBSERVE;
  }
  return SEC_RESPONSE_NONE;
}

static const char *
security_response(uint16_t alerts, uint8_t security_state)
{
  return security_response_name(security_response_code(alerts, security_state));
}

static uint8_t
quarantine_active(const drone_state_t *st, uint32_t now)
{
  return (uint8_t)(st->quarantine_until != 0 && now < st->quarantine_until);
}

static uint8_t
rate_limit_active(const drone_state_t *st, uint32_t now)
{
  return (uint8_t)(st->rate_limit_until != 0 && now < st->rate_limit_until);
}

static uint8_t
flood_recovery_active(const drone_state_t *st, uint32_t now)
{
  if(st == NULL) {
    return 0;
  }
  return (uint8_t)(rate_limit_active(st, now) ||
                   st->source_managed_rate_limit ||
                   st->last_response == SEC_RESPONSE_RATE_LIMIT ||
                   (st->offline_grace_until != 0 &&
                    now < st->offline_grace_until));
}

static uint8_t
policy_reason_code(const char *reason)
{
  if(reason == NULL) {
    return 0;
  }
  if(strcmp(reason, "apply_rate_limit") == 0) {
    return 1;
  }
  if(strcmp(reason, "apply_quarantine") == 0) {
    return 2;
  }
  if(strcmp(reason, "rate_limit_released") == 0) {
    return 3;
  }
  if(strcmp(reason, "quarantine_released") == 0) {
    return 4;
  }
  return 0;
}

static void
release_security_policy(drone_state_t *st, const char *reason, uint32_t now,
                        uint8_t reset_liveness)
{
  uint8_t prev_state = st->security_state;
  uint8_t prev_response = st->last_response;

  if(reason != NULL && strcmp(reason, "rate_limit_released") == 0) {
    uint32_t suppress_until = now + FLOOD_OFFLINE_SUPPRESS_SEC;
    last_global_flood_time = now;
    if(suppress_until > st->offline_grace_until) {
      st->offline_grace_until = suppress_until;
    }
  }
  st->security_state = (st->risk_score == 0) ? SEC_STATE_RECOVERED : SEC_STATE_RECOVERING;
  st->last_response = security_response_code(0, st->security_state);
  if(reset_liveness) {
    st->last_t = now;
    st->offline_reported = 0;
  }
  emit_security_decision(st, 0, reason, prev_state, prev_response);
}

static void
emit_security_decision(drone_state_t *st, uint16_t alerts, const char *reason,
                       uint8_t prev_state, uint8_t prev_response)
{
  uint8_t reason_code = policy_reason_code(reason);
  uint32_t sim_t = clock_seconds();
  const char *attack = detect_attack(alerts);
  const char *state = security_state_name(st->security_state);
  const char *response = security_response_name(st->last_response);
  const char *prev_state_name = security_state_name(prev_state);
  const char *prev_response_name = security_response_name(prev_response);

  if(reason_code != 0 &&
     st->last_policy_reason_code == reason_code &&
     st->last_policy_reason_time == sim_t) {
    return;
  }

  printf("DECISION,id=%u,prev_state=%s,state=%s,prev_response=%s,response=%s,risk=%u,reason=%s,attack=%s,alerts=0x%04x\n",
         st->drone_id, prev_state_name, state, prev_response_name, response,
         (unsigned)st->risk_score, reason, attack, alerts);
  printf("CSV_DECISION,%lu,%u,%s,%s,%s,%s,%u,%s,%u,%s\n",
         (unsigned long)sim_t, st->drone_id, prev_state_name, state,
         prev_response_name, response, (unsigned)st->risk_score, reason,
         (unsigned)alerts, attack);

  if(reason_code != 0) {
    st->last_policy_reason_code = reason_code;
    st->last_policy_reason_time = sim_t;
  }
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
send_control_command(const linkaddr_t *dest, uint8_t cmd, uint8_t value,
                     uint8_t duration)
{
  control_msg_t ctrl;
  ctrl.ver = MSG_VER;
  ctrl.cmd = cmd;
  ctrl.value = value;
  ctrl.duration = duration;
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
send_control_command_all(uint8_t cmd, uint8_t value, uint8_t duration)
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
    send_control_command(&dest, cmd, value, duration);
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

static source_state_t *
find_or_create_source_state(uint8_t sender_id)
{
  int i;
  int free_index = -1;

  for(i = 0; i < MAX_SOURCES; i++) {
    if(sources[i].used && sources[i].sender_id == sender_id) {
      return &sources[i];
    }
    if(!sources[i].used && free_index < 0) {
      free_index = i;
    }
  }

  if(free_index < 0) {
    return NULL;
  }
  memset(&sources[free_index], 0, sizeof(sources[free_index]));
  sources[free_index].used = 1;
  sources[free_index].sender_id = sender_id;
  return &sources[free_index];
}

static relay_state_t *
find_or_create_relay_state(uint8_t relay_id)
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
relay_forwarder_active(uint8_t relay_id, uint32_t now)
{
  relay_state_t *relay = find_or_create_relay_state(relay_id);

  if(relay == NULL || !relay->used || relay->last_seen == 0 || now < relay->last_seen) {
    return 0;
  }
  return (uint8_t)((now - relay->last_seen) <= RELAY_DISCOVERY_TIMEOUT_SEC);
}

static void
recv_relay_discovery(struct broadcast_conn *c, const linkaddr_t *from)
{
  relay_discovery_msg_t msg;
  relay_state_t *relay;

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

  relay = find_or_create_relay_state(msg.relay_id);
  if(relay == NULL) {
    return;
  }
  relay->last_seen = clock_seconds();
}

static void
clear_source_rate_limit(source_state_t *src)
{
  if(src == NULL) {
    return;
  }
  src->rate_limit_until = 0;
  src->rate_limit_period = 0;
  src->next_allowed_time = 0;
  src->window_start = 0;
  src->window_count = 0;
  src->classify_until = 0;
  src->classification_granted = 0;
}

static void
clear_source_quarantine(source_state_t *src)
{
  if(src == NULL) {
    return;
  }
  src->quarantine_until = 0;
  src->window_start = 0;
  src->window_count = 0;
  src->classify_until = 0;
  src->classification_granted = 0;
}

static uint8_t
source_quarantine_active(const source_state_t *src, uint32_t now)
{
  return (uint8_t)(src != NULL && src->quarantine_until != 0 &&
                   now < src->quarantine_until);
}

static uint8_t
source_rate_limit_active(const source_state_t *src, uint32_t now)
{
  return (uint8_t)(src != NULL && src->rate_limit_until != 0 &&
                   now < src->rate_limit_until);
}

static void
release_source_policy(source_state_t *src, const char *reason, uint32_t now)
{
  drone_state_t *st;

  if(src == NULL) {
    return;
  }
  if(src->report_drone_id != 0) {
    st = find_or_create_state(src->report_drone_id);
    if(st != NULL) {
      if(strcmp(reason, "rate_limit_released") == 0) {
        st->rate_limit_until = 0;
        st->source_managed_rate_limit = 0;
      }
      release_security_policy(st, reason, now, 1);
    }
    src->report_drone_id = 0;
  }
}

static void
apply_security_policy(drone_state_t *st, uint8_t sender_id,
                      uint16_t alerts, uint32_t now)
{
  linkaddr_t dest;
  source_state_t *src;
  const char *reason = NULL;
  uint8_t prev_state = st->security_state;
  uint8_t prev_response = st->last_response;
  uint8_t local_sender;

  if(st->drone_id >= ATTACKER_ID_BASE) {
    return;
  }
  src = find_or_create_source_state(sender_id);
  local_sender = (uint8_t)(sender_id == st->drone_id &&
                           sender_id < ATTACKER_ID_BASE);

  switch(st->last_response) {
  case SEC_RESPONSE_RATE_LIMIT:
    if(st->source_managed_rate_limit && local_sender &&
       (alerts & ALERT_FLOOD) == 0) {
      st->last_t = now;
      st->offline_reported = 0;
      if((now + FLOOD_OFFLINE_SUPPRESS_SEC) > st->offline_grace_until) {
        st->offline_grace_until = now + FLOOD_OFFLINE_SUPPRESS_SEC;
      }
      break;
    }
    if(src != NULL && !source_quarantine_active(src, now)) {
      if(source_rate_limit_active(src, now)) {
        if(!local_sender) {
          if(src->rate_limit_until > st->rate_limit_until) {
            st->rate_limit_until = src->rate_limit_until;
          }
          st->source_managed_rate_limit = 1;
          if((now + FLOOD_OFFLINE_SUPPRESS_SEC) > st->offline_grace_until) {
            st->offline_grace_until = now + FLOOD_OFFLINE_SUPPRESS_SEC;
          }
          st->last_t = now;
          st->offline_reported = 0;
        }
      } else {
        clear_source_quarantine(src);
        src->rate_limit_until = now + RATE_LIMIT_DURATION_SEC;
        src->rate_limit_period = RATE_LIMIT_PERIOD_SEC;
        src->next_allowed_time = now + RATE_LIMIT_PERIOD_SEC;
        src->report_drone_id = local_sender ? 0 : st->drone_id;
        st->rate_limit_until = src->rate_limit_until;
        st->source_managed_rate_limit = (uint8_t)!local_sender;
        st->offline_grace_until = now + FLOOD_OFFLINE_SUPPRESS_SEC;
        st->last_t = now;
        st->offline_reported = 0;
        if(local_sender) {
          dest.u8[0] = sender_id;
          dest.u8[1] = 0;
          send_control_command(&dest, CTRL_CMD_RATE_LIMIT,
                               RATE_LIMIT_PERIOD_SEC, RATE_LIMIT_DURATION_SEC);
        }
        reason = "apply_rate_limit";
      }
    }
    break;
  case SEC_RESPONSE_QUARANTINE:
    if(src != NULL && !source_quarantine_active(src, now)) {
      clear_source_rate_limit(src);
      src->quarantine_until = now + QUARANTINE_DURATION_SEC;
      src->report_drone_id = local_sender ? 0 : st->drone_id;
      if(local_sender) {
        dest.u8[0] = sender_id;
        dest.u8[1] = 0;
        send_control_command(&dest, CTRL_CMD_QUARANTINE, 0, QUARANTINE_DURATION_SEC);
        st->quarantine_until = src->quarantine_until;
        st->last_t = now;
        st->offline_reported = 0;
      }
      reason = "apply_quarantine";
    }
    break;
  case SEC_RESPONSE_REROUTE:
    if((now - last_reroute_time) >= REROUTE_COOLDOWN_SEC) {
      send_control_command_all(CTRL_CMD_REROUTE, 0, 0);
      last_reroute_time = now;
      reason = "apply_reroute";
    }
    break;
  case SEC_RESPONSE_ISOLATE_RELAY:
    if((now - last_reroute_time) >= REROUTE_COOLDOWN_SEC) {
      send_control_command_all(CTRL_CMD_ISOLATE_RELAY, 0,
                               RELAY_ISOLATION_DURATION_SEC);
      last_reroute_time = now;
      reason = "apply_isolate_relay";
    }
    break;
  default:
    break;
  }

  if(reason != NULL) {
    emit_security_decision(st, alerts, reason, prev_state, prev_response);
  }
}

static void recv_mesh(struct mesh_conn *c, const linkaddr_t *from, uint8_t hops)
{
  sensor_msg_t msg;
  drone_state_t *st;
  source_state_t *src;
  uint16_t alerts = 0;
  uint8_t invalid_id = 0;
  uint8_t invalid = 0;
  uint8_t invalid_mac = 0;
  uint8_t invalid_fields = 0;
  uint8_t rate_limited = 0;
  uint8_t replay_detected = 0;
  uint8_t is_attacker = 0;
  uint8_t remote_attacker_source = 0;
  uint8_t source_flood_active = 0;
  uint8_t source_flood_detected = 0;
  uint8_t source_classification_pending = 0;
  uint8_t sender_id = 0;
  uint8_t physical_sender_id = 0;
  uint8_t relay_forwarder = 0;
  uint8_t prev_state = SEC_STATE_NORMAL;
  uint8_t prev_response = SEC_RESPONSE_NONE;
  uint8_t response = SEC_RESPONSE_NONE;
  uint16_t prev_seq = 0;
  uint32_t prev_t = 0;
  uint16_t gap = 0;
  uint32_t now = 0;
  uint32_t expected_mac = 0;

  (void)c;
  (void)hops;

  if(packetbuf_datalen() == sizeof(msg)) {
    memcpy(&msg, packetbuf_dataptr(), sizeof(msg));
    physical_sender_id = from->u8[0];
    now = clock_seconds();
    relay_forwarder = (uint8_t)(physical_sender_id != msg.drone_id &&
                                relay_forwarder_active(physical_sender_id, now));
    sender_id = relay_forwarder ? msg.drone_id : physical_sender_id;
    src = find_or_create_source_state(sender_id);
    if(source_quarantine_active(src, now)) {
      return;
    }
    if(source_rate_limit_active(src, now)) {
      if(src->next_allowed_time != 0 && now < src->next_allowed_time) {
        return;
      }
      src->next_allowed_time = now + src->rate_limit_period;
    }
    st = find_or_create_state(msg.drone_id);
    if(st == NULL) {
      return;
    }
    if(quarantine_active(st, now)) {
      return;
    }
    prev_state = st->security_state;
    prev_response = st->last_response;
    if(msg.drone_id != sender_id) {
      invalid_id = 1;
    }
    if(!relay_forwarder &&
       (sender_id >= ATTACKER_ID_BASE || msg.drone_id != physical_sender_id)) {
      is_attacker = 1;
    }
    remote_attacker_source = is_attacker;

    if(src != NULL) {
      source_flood_active = (uint8_t)(remote_attacker_source &&
                                      source_rate_limit_active(src, now));
      if(src->window_start == 0 || now < src->window_start ||
         (now - src->window_start) >= FLOOD_WINDOW_SEC) {
        src->window_start = now;
        src->window_count = 0;
      }
      src->window_count++;
      if(src->window_count > FLOOD_MAX_PER_WINDOW) {
        source_flood_detected = 1;
      }
      if(remote_attacker_source && !src->classification_granted) {
        src->classification_granted = 1;
        src->classify_until = now + SOURCE_CLASSIFY_WINDOW_SEC;
      }
      if(remote_attacker_source && src->classify_until != 0 && now < src->classify_until) {
        source_classification_pending = 1;
      }
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
      } else if(!is_attacker &&
                !flood_recovery_active(st, now) &&
                msg.seq > (uint16_t)(st->last_seq + 1)) {
        gap = (uint16_t)(msg.seq - st->last_seq - 1);
        st->missed_packets += gap;
        if(!is_attacker) {
          global_missed += gap;
        }
        alerts |= ALERT_PKT_GAP;
      }
      if(!is_attacker &&
         !flood_recovery_active(st, now) &&
         prev_t != 0 &&
         (msg.t > prev_t + OFFLINE_TIMEOUT_SEC)) {
        alerts |= ALERT_PKT_GAP;
      }
    }

    if(invalid_id && !invalid_mac && !invalid_fields && !replay_detected) {
      alerts |= ALERT_IMPERSONATION;
    }
    if(remote_attacker_source && source_classification_pending &&
       !source_flood_detected && !source_flood_active) {
      alerts &= (uint16_t)~ALERT_IMPERSONATION;
    }

    if(st->window_start == 0 || now - st->window_start >= FLOOD_WINDOW_SEC) {
      st->window_start = now;
      st->window_count = 0;
    }
    st->window_count++;
    if(st->window_count > FLOOD_MAX_PER_WINDOW) {
      alerts |= ALERT_FLOOD;
      rate_limited = 1;
    }
    if(remote_attacker_source && (source_flood_detected || source_flood_active)) {
      alerts |= ALERT_FLOOD;
      alerts &= (uint16_t)~(ALERT_IMPERSONATION | ALERT_REPLAY | ALERT_PKT_GAP);
      replay_detected = 0;
      rate_limited = 1;
      if(src != NULL) {
        src->classify_until = 0;
      }
      source_classification_pending = 0;
    }
    if(alerts & ALERT_FLOOD) {
      uint32_t suppress_until = now + FLOOD_OFFLINE_SUPPRESS_SEC;
      last_global_flood_time = now;
      if(suppress_until > st->offline_grace_until) {
        st->offline_grace_until = suppress_until;
      }
    }

    if(!rate_limited) {
      if(!is_attacker && !invalid && !replay_detected &&
         (alerts & ALERT_FLOOD) == 0) {
        st->last_seq = msg.seq;
        st->last_t = msg.t;
        st->data_count++;
        global_received++;
      }
    } else {
      if(!is_attacker && !invalid && !replay_detected &&
         (alerts & ALERT_FLOOD) == 0 &&
         msg.seq > st->last_seq) {
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
          alerts &= (uint16_t)~ALERT_PKT_GAP;
        }
      }
    }

    account_alert(st, alerts);
    update_security_posture(st, alerts);
    if((alerts & SECURITY_ALERT_MASK) == 0) {
      if(rate_limit_active(st, now)) {
        st->security_state = SEC_STATE_UNDER_ATTACK;
      } else if(quarantine_active(st, now)) {
        st->security_state = SEC_STATE_UNDER_ATTACK;
      }
    }
    response = security_response_code(alerts, st->security_state);
    if((alerts & SECURITY_ALERT_MASK) == 0) {
      if(rate_limit_active(st, now)) {
        response = SEC_RESPONSE_RATE_LIMIT;
      } else if(quarantine_active(st, now)) {
        response = SEC_RESPONSE_QUARANTINE;
      }
    }
    if(remote_attacker_source && source_classification_pending &&
       (alerts & ALERT_FLOOD) == 0 &&
       (alerts & ALERT_INVALID) == 0 &&
       (alerts & ALERT_IMPERSONATION) != 0 &&
       (alerts & ALERT_REPLAY) == 0) {
      response = SEC_RESPONSE_OBSERVE;
    }
    st->last_response = response;
    st->offline_reported = 0;
    if((alerts & SECURITY_ALERT_MASK) != 0 ||
       st->security_state != prev_state ||
       st->last_response != prev_response) {
      const char *decision_reason = "risk_decay";
      if((alerts & SECURITY_ALERT_MASK) != 0) {
        decision_reason = detect_attack(alerts);
      } else if(st->security_state == SEC_STATE_RECOVERED) {
        decision_reason = "recovered";
      }
      emit_security_decision(st, alerts, decision_reason, prev_state, prev_response);
    }
    apply_security_policy(st, sender_id, alerts, now);

#if SINK_LOG
    if(!is_attacker) {
      printf("DATA,id=%u,from=%u.%u,seq=%u,t=%lu,temp=%u,vib=%u,gas=%u,batt=%u,alerts=0x%04x\n",
             msg.drone_id, from->u8[0], from->u8[1], msg.seq, (unsigned long)msg.t,
             msg.temp, msg.vib, msg.gas, msg.batt_mv, alerts);
      printf("CSV_DATA,%lu,%s,%u,%u,%u,%u,%u,%u,%u,%u,%lu,%lu,%lu,%lu,%s,%s,%u,%s,%s\n",
             (unsigned long)clock_seconds(), alert_severity(alerts), msg.drone_id, msg.seq,
             msg.temp, msg.vib, msg.gas, msg.batt_mv, alerts, st->missed_packets,
             (unsigned long)st->data_count, (unsigned long)st->alert_count,
             (unsigned long)st->warn_count, (unsigned long)st->crit_count,
             detect_attack(alerts), detect_hazard(alerts),
             (unsigned)st->risk_score, security_state_name(st->security_state),
             security_response(alerts, st->security_state));
    }
    if(alerts != 0) {
      printf("ALERT,sev=%s,attack=%s,hazard=%s,id=%u,seq=%u,flags=0x%04x,prev_seq=%u,gap=%u,missed_total=%lu,alerts_total=%lu,risk=%u,state=%s,response=%s\n",
             alert_severity(alerts), detect_attack(alerts),
             detect_hazard(alerts),
             msg.drone_id, msg.seq, alerts, prev_seq, gap,
             (unsigned long)st->missed_packets, (unsigned long)st->alert_count,
             (unsigned)st->risk_score, security_state_name(st->security_state),
             security_response(alerts, st->security_state));
      printf("CSV_ALERT,%lu,%s,%u,%u,%u,%u,%u,%u,%u,%u,%lu,%lu,%lu,%lu,%s,%s,%u,%s,%s\n",
             (unsigned long)clock_seconds(), alert_severity(alerts), msg.drone_id,
             msg.seq, msg.temp, msg.vib, msg.gas, msg.batt_mv, alerts,
             (unsigned long)st->missed_packets, (unsigned long)st->data_count,
             (unsigned long)st->alert_count, (unsigned long)st->warn_count,
             (unsigned long)st->crit_count, detect_attack(alerts),
             detect_hazard(alerts), (unsigned)st->risk_score,
             security_state_name(st->security_state),
             security_response(alerts, st->security_state));
    }
#endif

    if(!is_attacker && (alerts & ALERT_PKT_GAP) &&
       (now - last_hop_time) >= HOP_COOLDOWN_SEC) {
      int j;
      uint32_t suppress_until = now + JAMMING_OFFLINE_SUPPRESS_SEC;
      last_global_jamming_time = now;
      for(j = 0; j < MAX_DRONES; j++) {
        if(states[j].used && states[j].drone_id < ATTACKER_ID_BASE &&
           suppress_until > states[j].offline_grace_until) {
          states[j].offline_grace_until = suppress_until;
          states[j].offline_reported = 0;
        }
      }
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

  PROCESS_EXITHANDLER(mesh_close(&mesh); broadcast_close(&relay_discovery);)
  PROCESS_BEGIN();

  memset(states, 0, sizeof(states));
  memset(sources, 0, sizeof(sources));
  memset(relays, 0, sizeof(relays));
  current_channel = channel_list[channel_index % RADIO_CHANNEL_COUNT];
  broadcast_open(&relay_discovery, RELAY_DISCOVERY_CHANNEL, &relay_discovery_cb);
  mesh_open(&mesh, current_channel, &mesh_cb);
  etimer_set(&monitor_timer, CLOCK_SECOND);
#if SINK_LOG
  printf("CSV_HEADER,sim_t,severity,drone_id,seq,temp,vib,gas,batt_mv,alerts,missed_total,data_count,alert_count,warn_count,crit_count,attack,hazard,risk,state,response\n");
  printf("CSV_DECISION_HEADER,sim_t,drone_id,prev_state,state,prev_response,response,risk,reason,alerts,attack\n");
#endif

  while(1) {
    PROCESS_WAIT_EVENT();

    if(ev == PROCESS_EVENT_POLL && hop_pending) {
      hop_pending = 0;
      send_control_command_all(CTRL_CMD_HOP, hop_target, 0);
      set_channel(hop_target);
    } else if(ev == PROCESS_EVENT_TIMER && data == &monitor_timer) {
      now = clock_seconds();
      for(i = 0; i < MAX_DRONES; i++) {
        if(states[i].used && states[i].rate_limit_until != 0 &&
           now >= states[i].rate_limit_until) {
          states[i].rate_limit_until = 0;
          if(states[i].source_managed_rate_limit) {
            states[i].source_managed_rate_limit = 0;
            states[i].last_t = now;
            states[i].offline_reported = 0;
          } else {
            release_security_policy(&states[i], "rate_limit_released", now, 1);
          }
        }
        if(states[i].used && states[i].quarantine_until != 0 &&
           now >= states[i].quarantine_until) {
          states[i].quarantine_until = 0;
          release_security_policy(&states[i], "quarantine_released", now, 1);
        }
        if(states[i].used &&
           states[i].drone_id < ATTACKER_ID_BASE &&
           states[i].last_t > 0 &&
           states[i].risk_score == 0 &&
           states[i].security_state == SEC_STATE_NORMAL &&
           states[i].last_response == SEC_RESPONSE_NONE &&
           (last_global_flood_time == 0 ||
            now >= (last_global_flood_time + FLOOD_OFFLINE_SUPPRESS_SEC)) &&
           (last_global_jamming_time == 0 ||
            now >= (last_global_jamming_time + JAMMING_OFFLINE_SUPPRESS_SEC)) &&
           (states[i].offline_grace_until == 0 ||
            now >= states[i].offline_grace_until) &&
           !rate_limit_active(&states[i], now) &&
           !quarantine_active(&states[i], now) &&
           !states[i].offline_reported &&
          now > (states[i].last_t + OFFLINE_TIMEOUT_SEC)) {
#if SINK_LOG
          uint8_t prev_state = states[i].security_state;
          uint8_t prev_response = states[i].last_response;
          uint16_t offline_alerts = ALERT_PKT_GAP | ALERT_BLACKHOLE;
          account_alert(&states[i], offline_alerts);
          update_security_posture(&states[i], offline_alerts);
          states[i].last_response = security_response_code(offline_alerts,
                                                           states[i].security_state);
          emit_security_decision(&states[i], offline_alerts, "offline_timeout",
                                 prev_state, prev_response);
          apply_security_policy(&states[i], states[i].drone_id, offline_alerts, now);
          printf("ALERT,sev=%s,attack=%s,hazard=%s,id=%u,seq=%u,flags=0x%04x,reason=offline,last_t=%lu,now=%lu,alerts_total=%lu,risk=%u,state=%s,response=%s\n",
                 alert_severity(offline_alerts), detect_attack(offline_alerts),
                 detect_hazard(offline_alerts),
                 states[i].drone_id, states[i].last_seq, offline_alerts,
                 (unsigned long)states[i].last_t, (unsigned long)now,
                 (unsigned long)states[i].alert_count, (unsigned)states[i].risk_score,
                 security_state_name(states[i].security_state),
                 security_response(offline_alerts, states[i].security_state));
          printf("CSV_ALERT,%lu,%s,%u,%u,%u,%u,%u,%u,%u,%u,%lu,%lu,%lu,%lu,%s,%s,%u,%s,%s\n",
                 (unsigned long)now, alert_severity(offline_alerts),
                 states[i].drone_id, states[i].last_seq, 0, 0, 0, 0, offline_alerts,
                 (unsigned long)states[i].missed_packets, (unsigned long)states[i].data_count,
                 (unsigned long)states[i].alert_count, (unsigned long)states[i].warn_count,
                 (unsigned long)states[i].crit_count, detect_attack(offline_alerts),
                 detect_hazard(offline_alerts), (unsigned)states[i].risk_score,
                 security_state_name(states[i].security_state),
                 security_response(offline_alerts, states[i].security_state));
#endif
          states[i].offline_reported = 1;
        }
      }
      for(i = 0; i < MAX_SOURCES; i++) {
        if(sources[i].used && sources[i].rate_limit_until != 0 &&
           now >= sources[i].rate_limit_until) {
          clear_source_rate_limit(&sources[i]);
          release_source_policy(&sources[i], "rate_limit_released", now);
        }
        if(sources[i].used && sources[i].quarantine_until != 0 &&
           now >= sources[i].quarantine_until) {
          clear_source_quarantine(&sources[i]);
          release_source_policy(&sources[i], "quarantine_released", now);
        }
      }
      etimer_reset(&monitor_timer);
    }
  }

  PROCESS_END();
}
