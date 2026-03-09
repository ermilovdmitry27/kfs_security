#include "contiki.h"
#include "net/rime/rime.h"
#include "attack_report.h"
#include "lib/random.h"
#include <stdio.h>
#include <string.h>

#define JAMMER_LOG 0

#define RADIO_CHANNEL_START 129
#define RADIO_CHANNEL_COUNT 4
#define JAMMER_INTERVAL_MS 10
#define JAMMER_PAYLOAD_SIZE 110

PROCESS(jammer_proc, "Jammer");
AUTOSTART_PROCESSES(&jammer_proc);

static const struct broadcast_callbacks bc_cb = { NULL, NULL };
static struct broadcast_conn bc;
static uint8_t current_channel = RADIO_CHANNEL_START;
static uint8_t channel_index = 0;
static const uint8_t channel_list[RADIO_CHANNEL_COUNT] = {129, 130, 131, 132};

static void
set_channel(uint8_t ch)
{
  if(ch == current_channel) {
    return;
  }
  broadcast_close(&bc);
  current_channel = ch;
  broadcast_open(&bc, current_channel, &bc_cb);
}

PROCESS_THREAD(jammer_proc, ev, data)
{
  static struct etimer timer;
  static uint8_t payload[JAMMER_PAYLOAD_SIZE];
  int i;

  PROCESS_BEGIN();

  current_channel = channel_list[channel_index % RADIO_CHANNEL_COUNT];
  broadcast_open(&bc, current_channel, &bc_cb);
  attack_report_emit(REPORT_ALERT_PKT_GAP, "jamming");
  etimer_set(&timer, (CLOCK_SECOND * JAMMER_INTERVAL_MS) / 1000);

  for(i = 0; i < (int)sizeof(payload); i++) {
    payload[i] = (uint8_t)(random_rand() & 0xff);
  }

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

    payload[0] = (uint8_t)(random_rand() & 0xff);
    packetbuf_copyfrom(payload, sizeof(payload));
    broadcast_send(&bc);

    channel_index = (uint8_t)((channel_index + 1) % RADIO_CHANNEL_COUNT);
    set_channel(channel_list[channel_index]);

#if JAMMER_LOG
    printf("JAMMER tx len=%u\n", (unsigned)sizeof(payload));
#endif

    etimer_reset(&timer);
  }

  PROCESS_END();
}
