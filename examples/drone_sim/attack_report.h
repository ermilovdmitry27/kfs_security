#ifndef ATTACK_REPORT_H
#define ATTACK_REPORT_H

#include "contiki.h"
#include "net/linkaddr.h"
#include <stdint.h>
#include <stdio.h>

#define REPORT_ALERT_PKT_GAP   0x0020
#define REPORT_ALERT_SELECTIVE 0x0100
#define REPORT_ALERT_BLACKHOLE 0x0200

static unsigned
attack_report_risk(uint16_t alerts)
{
  if(alerts & REPORT_ALERT_BLACKHOLE) {
    return 90;
  }
  if(alerts & REPORT_ALERT_SELECTIVE) {
    return 60;
  }
  if(alerts & REPORT_ALERT_PKT_GAP) {
    return 40;
  }
  return 20;
}

static const char *
attack_report_state(uint16_t alerts)
{
  if(alerts & REPORT_ALERT_BLACKHOLE) {
    return "ISOLATED";
  }
  if(alerts & REPORT_ALERT_SELECTIVE) {
    return "UNDER_ATTACK";
  }
  if(alerts & REPORT_ALERT_PKT_GAP) {
    return "SUSPICIOUS";
  }
  return "SUSPICIOUS";
}

static const char *
attack_report_response(uint16_t alerts)
{
  if(alerts & REPORT_ALERT_BLACKHOLE) {
    return "isolate_relay";
  }
  if(alerts & REPORT_ALERT_SELECTIVE) {
    return "reroute";
  }
  if(alerts & REPORT_ALERT_PKT_GAP) {
    return "channel_hop";
  }
  return "observe";
}

static void
attack_report_emit(uint16_t alerts, const char *attack)
{
  uint8_t mote_id = linkaddr_node_addr.u8[0];

  printf("ALERT,sev=WARN,attack=%s,hazard=none,id=%u,seq=0,flags=0x%04x,source=module\n",
         attack, mote_id, alerts);
  printf("CSV_ALERT,%lu,WARN,%u,0,0,0,0,0,%u,0,0,1,1,0,%s,none,%u,%s,%s\n",
         (unsigned long)clock_seconds(), mote_id, (unsigned)alerts, attack,
         attack_report_risk(alerts), attack_report_state(alerts),
         attack_report_response(alerts));
}

#endif
