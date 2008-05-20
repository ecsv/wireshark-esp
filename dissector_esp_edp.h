#ifndef _DISSECTOR_ESP_EDP_H_
#define _DISSECTOR_ESP_EDP_H_

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gmodule.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>

#ifndef ETHERTYPE_ETH_EDP
#define ETHERTYPE_ETH_EDP            0x8889
#endif

#ifndef ETHERTYPE_ETH_ESP
#define ETHERTYPE_ETH_ESP            0x8887
#endif

#define EH_SYN  0x01
#define EH_ACK  0x02
#define EH_FIN  0x04
#define EH_RST  0x08
#define EH_RRQ  0x10
#define EH_TXS  0x20
#define EH_TXF  0x40
#define EH_XXX  0x80

/* forward reference */
void proto_register_eth_edp();
void proto_reg_handoff_eth_edp();
void proto_register_eth_esp();
void proto_reg_handoff_eth_esp();

extern int proto_eth_edp;
extern int proto_eth_esp;

#endif /* _DISSECTOR_ESP_EDP_H_ */
