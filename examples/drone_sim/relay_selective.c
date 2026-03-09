#include "contiki.h"
#include "net/rime/mesh.h"
#include "net/netstack.h"
#include "attack_report.h"
#include <stdio.h>
#include <string.h>

#define RADIO_CHANNEL_START 129
#define RADIO_CHANNEL_COUNT 4

#define MSG_VER 1
#define CTRL_CMD_HOP 1

#define MAC_KEY 0x6a09e667u

#define SELECTIVE_ON_MS 800
#define SELECTIVE_OFF_MS 800

PROCESS(relay_selective_proc, "Relay selective");
AUTOSTART_PROCESSES(&relay_selective_proc);

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

PROCESS_THREAD(relay_selective_proc, ev, data)
{
  static struct etimer timer;
  static uint8_t radio_on;

  PROCESS_BEGIN();

  radio_on = 1;
  current_channel = channel_list[channel_index % RADIO_CHANNEL_COUNT];
  mesh_open(&mesh, current_channel, &mesh_cb);
  printf("Starting selective relay on channel %u\n", current_channel);

  etimer_set(&timer, (CLOCK_SECOND * SELECTIVE_ON_MS) / 1000);

  while(1) {
    PROCESS_WAIT_EVENT();
    if(ev == PROCESS_EVENT_TIMER && data == &timer) {
      if(radio_on) {
        NETSTACK_RADIO.off();
        radio_on = 0;
        etimer_set(&timer, (CLOCK_SECOND * SELECTIVE_OFF_MS) / 1000);
        attack_report_emit(REPORT_ALERT_SELECTIVE, "selective_forwarding");
        printf("Selective relay OFF\n");
      } else {
        NETSTACK_RADIO.on();
        radio_on = 1;
        etimer_set(&timer, (CLOCK_SECOND * SELECTIVE_ON_MS) / 1000);
        printf("Selective relay ON\n");
      }
    }
  }

  PROCESS_END();
}
