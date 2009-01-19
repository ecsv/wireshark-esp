/* packet-bat-gw.c
 * Routines for Ethernet Datagram Protocol dissection
 * Copyright 2008, Sven Eckelmann <sven.eckelmann@gmx.de>
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

#ifndef ETHERTYPE_ETH_EDP
#define ETHERTYPE_ETH_EDP            0x8889
#endif

/* EDP structs and definitions */
typedef struct _e_eth_edphdr {
	guint16 eh_dport;
	guint16 eh_sport;
	guint16 eh_len;
} e_eth_edphdr;

/* trees */
static gint ett_eth_edp = -1;

/* hfs */
static int hf_eth_edp_srcport = -1;
static int hf_eth_edp_dstport = -1;
static int hf_eth_edp_len = -1;
static int hf_eth_edp_ctype = -1;

/* forward reference */
void proto_register_eth_edp(void);
void proto_reg_handoff_eth_edp(void);
static dissector_handle_t eth_edp_handle;

/* flags */
static const value_string packettypenames[] = {
	{ 0, "EDP_CMSG_START" },
	{ 1, "EDP_ECHO_REQUEST" },
	{ 2, "EDP_ECHO_REPLY" },
	{ 3, "EDP_CMSG_END" },
	{ 0, NULL }
};

/* supported packet dissectors */
static void dissect_eth_edp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* other dissectors */
static dissector_handle_t data_handle;

static int proto_eth_edp_plugin = -1;

/* tap */
static int eth_edp_tap = -1;
static int eth_edp_follow_tap = -1;

static heur_dissector_list_t heur_subdissector_list;
static gboolean try_heuristic_first = FALSE;

static void dissect_eth_edp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	e_eth_edphdr *eth_edph;
	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;
	guint len;

	eth_edph = ep_alloc(sizeof(e_eth_edphdr));
	eth_edph->eh_dport = tvb_get_ntohs(tvb, 0);
	eth_edph->eh_sport = tvb_get_ntohs(tvb, 2);
	eth_edph->eh_len = tvb_get_ntohs(tvb, 4);

	/* set protocol name */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETH_EDP");
	}

	/* Set info column */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);

		if (eth_edph->eh_sport == 0) {
			uint8_t ctype = tvb_get_guint8(tvb, 6);
			col_append_fstr(pinfo->cinfo, COL_INFO, "KERNEL > %u [%s]", eth_edph->eh_dport,
			                val_to_str(ctype, packettypenames, "Unknown (0x%02x)"));
		} else if (eth_edph->eh_dport == 0) {
			uint8_t ctype = tvb_get_guint8(tvb, 6);
			col_append_fstr(pinfo->cinfo, COL_INFO, "%u > KERNEL [%s]", eth_edph->eh_sport,
			                val_to_str(ctype, packettypenames, "Unknown (0x%02x)"));
		} else {
			col_append_fstr(pinfo->cinfo, COL_INFO, "%u > %u", eth_edph->eh_sport, eth_edph->eh_dport);
		}
	}

	/* Set tree info */
	if (tree) {
		proto_item *ti = NULL;
		proto_tree *eth_edp_tree = NULL;

		ti = proto_tree_add_item(tree, proto_eth_edp_plugin, tvb, 0, -1, FALSE);
		eth_edp_tree = proto_item_add_subtree(ti, ett_eth_edp);

		/* items */
		proto_tree_add_item(eth_edp_tree, hf_eth_edp_dstport, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(eth_edp_tree, hf_eth_edp_srcport, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(eth_edp_tree, hf_eth_edp_len, tvb, offset, 2, FALSE);
		offset += 2;

		if (eth_edph->eh_dport == 0 || eth_edph->eh_sport == 0) {
			uint8_t ctype = tvb_get_guint8(tvb, 6);
			proto_tree_add_uint_format(eth_edp_tree, hf_eth_edp_ctype, tvb, offset, 1, ctype,
			                           "CType: %s (%u)",
			                           val_to_str(ctype, packettypenames, "Unknown (0x%02x)"), ctype);
			offset += 1;
		}
	}

	pinfo->srcport = eth_edph->eh_sport;
	pinfo->destport = eth_edph->eh_dport;

	tap_queue_packet(eth_edp_tap, pinfo, eth_edph);

	length_remaining = tvb_length_remaining(tvb, offset);
	len = length_remaining;

	if (length_remaining != eth_edph->eh_len) {
		len = length_remaining;
	} else {
		len = eth_edph->eh_len;
	}

	if (len != 0) {
		next_tvb = tvb_new_subset(tvb, offset, len, -1);

		if (have_tap_listener(eth_edp_follow_tap)) {
			tap_queue_packet(eth_edp_follow_tap, pinfo, next_tvb);
		}

		if (try_heuristic_first) {
			/* do lookup with the heuristic subdissector table */
			if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree))
				return;
		}

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

void proto_register_eth_edp(void)
{
	static hf_register_info hf_eth_edp[] = {
		{ &hf_eth_edp_dstport,
		  { "Destination Port", "eth_edp.dstport",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_eth_edp_srcport,
		  { "Source Port", "eth_edp.srcport",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "", HFILL }
		},
		{ &hf_eth_edp_len,
		  { "Data Len", "eth_edp.len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "", HFILL}
		},
		{ &hf_eth_edp_ctype,
		  { "CType", "eth_edp.ctype",
		    FT_UINT8, BASE_DEC, VALS(packettypenames), 0x0,
		    "", HFILL}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_eth_edp
	};

	module_t *eth_edp_module;
	proto_eth_edp_plugin = proto_register_protocol(
	                        "Ethernet Datagram Protocol",
	                        "ETH_EDP",          /* short name */
	                        "eth_edp"           /* abbrev */
	                );
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_eth_edp_plugin, hf_eth_edp, array_length(hf_eth_edp));

	/* Register configuration preferences */
	eth_edp_module = prefs_register_protocol(proto_eth_edp_plugin, NULL);
	prefs_register_bool_preference(eth_edp_module, "try_heuristic_first",
	                               "Try heuristic sub-dissectors first",
	                               "Try to decode a packet using an heuristic sub-dissector before using a data-dissector",
	                               &try_heuristic_first);
}

void proto_reg_handoff_eth_edp(void)
{
	static gboolean inited = FALSE;

	if (!inited) {
		eth_edp_handle = create_dissector_handle(dissect_eth_edp, proto_eth_edp_plugin);

		data_handle = find_dissector("data");

		eth_edp_tap = register_tap("eth_edp");
		eth_edp_follow_tap = register_tap("eth_edp_follow");

		register_heur_dissector_list("eth_edp", &heur_subdissector_list);

		dissector_add("ethertype", ETHERTYPE_ETH_EDP, eth_edp_handle);

		inited = TRUE;
	}
}
