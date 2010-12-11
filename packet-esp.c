/* packet-bat-gw.c
 * Routines for Ethernet Stream Protocol dissection
 * Copyright 2008-2009  Sven Eckelmann <sven@narfation.org>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>

#ifndef ETHERTYPE_ETH_ESP
#define ETHERTYPE_ETH_ESP            0x8887
#endif

/* ESP structs and definitions */
typedef struct _e_eth_esphdr {
	guint16 eh_dport;   /**< esp destination port */
	guint16 eh_sport;   /**< esp source port */
	guint16 eh_pkt_seq; /**< esp packet sequence number */
	guint16 eh_ack_seq; /**< acknowledgement sequence number */
	guint16 eh_len;     /**< data length */
	guint8 eh_flags;    /**< esp flags */
} e_eth_esphdr;
#define ETH_ESP_PACKET_SIZE 11

#define EH_SYN  0x01
#define EH_ACK  0x02
#define EH_FIN  0x04
#define EH_RST  0x08
#define EH_RRQ  0x10
#define EH_TXS  0x20
#define EH_TXF  0x40
#define EH_XXX  0x80

/* trees */
static gint ett_eth_esp = -1;
static gint ett_eth_esp_flags = -1;

/* hfs */
static int hf_eth_esp_dstport = -1;
static int hf_eth_esp_srcport = -1;
static int hf_eth_esp_pkt_seq = -1;
static int hf_eth_esp_ack_seq = -1;
static int hf_eth_esp_len = -1;
static int hf_eth_esp_flags = -1;

/* forward reference */
void proto_register_eth_esp(void);
void proto_reg_handoff_eth_esp(void);
static dissector_handle_t eth_esp_handle;

/* flags */
static int hf_eth_esp_flags_syn = -1;
static int hf_eth_esp_flags_ack = -1;
static int hf_eth_esp_flags_fin = -1;
static int hf_eth_esp_flags_rst = -1;
static int hf_eth_esp_flags_rrq = -1;
static int hf_eth_esp_flags_txs = -1;
static int hf_eth_esp_flags_txf = -1;
static int hf_eth_esp_flags_xxx = -1;

/* supported packet dissectors */
static void dissect_eth_esp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* other dissectors */
static int proto_eth_esp_plugin = -1;

static dissector_handle_t data_handle;

/* tap */
static int eth_esp_tap = -1;
static int eth_esp_follow_tap = -1;

static heur_dissector_list_t heur_subdissector_list;
static gboolean try_heuristic_first = FALSE;

static unsigned int eth_esp_ethertype = ETHERTYPE_ETH_ESP;

static void dissect_eth_esp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	e_eth_esphdr *eth_esph;
	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;
	guint len;
	gchar      *flags = "<None>";
	const gchar *fstr[] = {"SYN", "ACK", "FIN", "RST", "RRQ", "TXS", "TXF", "XXX" };
	gint i;
	guint      bpos;
	size_t     fpos = 0, returned_length;

	eth_esph = ep_alloc(sizeof(e_eth_esphdr));
	eth_esph->eh_dport = tvb_get_ntohs(tvb, 0);
	eth_esph->eh_sport = tvb_get_ntohs(tvb, 2);
	eth_esph->eh_pkt_seq = tvb_get_ntohs(tvb, 4);
	eth_esph->eh_ack_seq = tvb_get_ntohs(tvb, 6);
	eth_esph->eh_len = tvb_get_ntohs(tvb, 8);
	eth_esph->eh_flags = tvb_get_guint8(tvb, 10);

	/* set protocol name */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETH_ESP");
	}

	/* Set info column */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		col_append_fstr(pinfo->cinfo, COL_INFO, "%u > %u", eth_esph->eh_sport, eth_esph->eh_dport);
	}

	/* Set tree info */
	if (tree) {
		proto_item *ti = NULL, *tf;
		proto_tree *eth_esp_tree = NULL, *field_tree = NULL;

		ti = proto_tree_add_item(tree, proto_eth_esp_plugin, tvb, 0, ETH_ESP_PACKET_SIZE, FALSE);
		eth_esp_tree = proto_item_add_subtree(ti, ett_eth_esp);

		/* items */
		proto_tree_add_item(eth_esp_tree, hf_eth_esp_dstport, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(eth_esp_tree, hf_eth_esp_srcport, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(eth_esp_tree, hf_eth_esp_pkt_seq, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(eth_esp_tree, hf_eth_esp_ack_seq, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(eth_esp_tree, hf_eth_esp_len, tvb, offset, 2, FALSE);
		offset += 2;

		tf = proto_tree_add_item(eth_esp_tree, hf_eth_esp_flags, tvb, offset, 1, FALSE);

		field_tree = proto_item_add_subtree(tf, ett_eth_esp_flags);
		proto_tree_add_boolean(field_tree, hf_eth_esp_flags_syn, tvb, offset, 1, eth_esph->eh_flags);
		proto_tree_add_boolean(field_tree, hf_eth_esp_flags_ack, tvb, offset, 1, eth_esph->eh_flags);
		proto_tree_add_boolean(field_tree, hf_eth_esp_flags_fin, tvb, offset, 1, eth_esph->eh_flags);
		proto_tree_add_boolean(field_tree, hf_eth_esp_flags_rst, tvb, offset, 1, eth_esph->eh_flags);
		proto_tree_add_boolean(field_tree, hf_eth_esp_flags_rrq, tvb, offset, 1, eth_esph->eh_flags);
		proto_tree_add_boolean(field_tree, hf_eth_esp_flags_txs, tvb, offset, 1, eth_esph->eh_flags);
		proto_tree_add_boolean(field_tree, hf_eth_esp_flags_txf, tvb, offset, 1, eth_esph->eh_flags);
		proto_tree_add_boolean(field_tree, hf_eth_esp_flags_xxx, tvb, offset, 1, eth_esph->eh_flags);
		offset += 1;
	}

	if (check_col(pinfo->cinfo, COL_INFO) || tree) {
#define MAX_FLAGS_LEN 64
		flags = ep_alloc(MAX_FLAGS_LEN);
		flags[0] = 0;
		for (i = 0; i < 8; i++) {
			bpos = 1 << i;
			if (eth_esph->eh_flags & bpos) {
				returned_length = g_snprintf(&flags[fpos], MAX_FLAGS_LEN - fpos, "%s%s",
				                             fpos ? ", " : "",
				                             fstr[i]);
				fpos += MIN(returned_length, MAX_FLAGS_LEN - fpos);
			}
		}
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u Ack=%u", flags, eth_esph->eh_pkt_seq, eth_esph->eh_ack_seq);
	}

	pinfo->srcport = eth_esph->eh_sport;
	pinfo->destport = eth_esph->eh_dport;

	tap_queue_packet(eth_esp_tap, pinfo, eth_esph);

	length_remaining = tvb_length_remaining(tvb, offset);
	len = length_remaining;

	if (length_remaining != eth_esph->eh_len) {
		len = length_remaining;
	} else {
		len = eth_esph->eh_len;
	}

	if (len != 0) {
		next_tvb = tvb_new_subset(tvb, offset, len, -1);

		if (have_tap_listener(eth_esp_follow_tap)) {
			tap_queue_packet(eth_esp_follow_tap, pinfo, next_tvb);
		}

		if (try_heuristic_first) {
			/* do lookup with the heuristic subdissector table */
			if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree))
				return;
		}

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

void proto_register_eth_esp(void)
{
	static hf_register_info hf_eth_esp[] = {
		{ &hf_eth_esp_dstport,
		  { "Destination Port", "eth_esp.dstport",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "", HFILL }},
		{ &hf_eth_esp_srcport,
		  { "Source Port", "eth_esp.srcport",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_eth_esp_pkt_seq,
		  { "Sequence number", "eth_esp.seq",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_eth_esp_ack_seq,
		  { "Acknowledgement number", "eth_esp.ack",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_eth_esp_len,
		  { "Data Len", "eth_esp.len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "", HFILL}
		},
		{ &hf_eth_esp_flags,
		  { "Flags", "eth_esp.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_eth_esp_flags_syn,
		  { "Syn", "eth_esp.flags.syn",
		    FT_BOOLEAN, 8, TFS(&flags_set_truth), EH_SYN,
		    "", HFILL }
		},
		{ &hf_eth_esp_flags_ack,
		  { "Ack", "eth_esp.flags.ack",
		    FT_BOOLEAN, 8, TFS(&flags_set_truth), EH_ACK,
		    "", HFILL }
		},
		{ &hf_eth_esp_flags_fin,
		  { "Fin", "eth_esp.flags.fin",
		    FT_BOOLEAN, 8, TFS(&flags_set_truth), EH_FIN,
		    "", HFILL }
		},
		{ &hf_eth_esp_flags_rst,
		  { "Rst", "eth_esp.flags.rst",
		    FT_BOOLEAN, 8, TFS(&flags_set_truth), EH_RST,
		    "", HFILL }
		},
		{ &hf_eth_esp_flags_rrq,
		  { "RRQ", "eth_esp.flags.rrq",
		    FT_BOOLEAN, 8, TFS(&flags_set_truth), EH_RRQ,
		    "", HFILL }
		},
		{ &hf_eth_esp_flags_txs,
		  { "TXS", "eth_esp.flags.txs",
		    FT_BOOLEAN, 8, TFS(&flags_set_truth), EH_TXS,
		    "", HFILL }
		},
		{ &hf_eth_esp_flags_txf,
		  { "TXF", "eth_esp.flags.txf",
		    FT_BOOLEAN, 8, TFS(&flags_set_truth), EH_TXF,
		    "", HFILL }
		},
		{ &hf_eth_esp_flags_xxx,
		  { "XXX", "eth_esp.flags.xxx",
		    FT_BOOLEAN, 8, TFS(&flags_set_truth), EH_XXX,
		    "", HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_eth_esp,
		&ett_eth_esp_flags
	};

	module_t *eth_esp_module;
	proto_eth_esp_plugin = proto_register_protocol(
	                        "Ethernet Stream Protocol",
	                        "ETH_ESP",          /* short name */
	                        "eth_esp"           /* abbrev */
	                );
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_eth_esp_plugin, hf_eth_esp, array_length(hf_eth_esp));

	/* Register configuration preferences */
	eth_esp_module = prefs_register_protocol(proto_eth_esp_plugin, NULL);
	prefs_register_bool_preference(eth_esp_module, "try_heuristic_first",
	                               "Try heuristic sub-dissectors first",
	                               "Try to decode a packet using an heuristic sub-dissector before using a data-dissector",
	                               &try_heuristic_first);

	prefs_register_uint_preference(eth_esp_module, "ethertype",
	                               "Ethertype",
	                               "Ethertype used to indicate Ethernet Stream Protocol packet.",
	                               16, &eth_esp_ethertype);
}

void proto_reg_handoff_eth_esp(void)
{
	static gboolean inited = FALSE;
	static unsigned int old_eth_esp_ethertype;

	if (!inited) {
		eth_esp_handle = create_dissector_handle(dissect_eth_esp, proto_eth_esp_plugin);

		data_handle = find_dissector("data");

		eth_esp_tap = register_tap("eth_esp");
		eth_esp_follow_tap = register_tap("eth_esp_follow");

		register_heur_dissector_list("eth_esp", &heur_subdissector_list);

		inited = TRUE;
	} else {
		dissector_delete("ethertype", old_eth_esp_ethertype, eth_esp_handle);
	}

	old_eth_esp_ethertype = eth_esp_ethertype;
	dissector_add("ethertype", eth_esp_ethertype, eth_esp_handle);
}
