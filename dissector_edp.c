#include "dissector_esp_edp.h"

/* UDP structs and definitions */
typedef struct _e_eth_edphdr {
	guint16 eh_dport;
	guint16 eh_sport;
	guint16 eh_len;
} e_eth_edphdr;

void dissect_eth_edp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

int proto_eth_edp = -1;
static dissector_handle_t eth_edp_handle;

static int eth_edp_tap = -1;
static int eth_edp_follow_tap = -1;

static heur_dissector_list_t heur_subdissector_list;

static gint ett_eth_edp = -1;

static int hf_eth_edp_srcport = -1;
static int hf_eth_edp_dstport = -1;
static int hf_eth_edp_len = -1;
static int hf_eth_edp_ctype = -1;
static dissector_handle_t data_handle;

static gboolean try_heuristic_first = FALSE;

static const value_string packettypenames[] = {
	{ 0, "EDP_CMSG_START" },
	{ 1, "EDP_ECHO_REQUEST" },
	{ 2, "EDP_ECHO_REPLY" },
	{ 3, "EDP_CMSG_END" },
	{ 4, NULL }
};

static hf_register_info hf_eth_edp[] = {
	{ &hf_eth_edp_dstport,
		{ "Destination Port",
			"eth_edp.dstport",
			FT_UINT16,
			BASE_DEC,
			NULL,
			0x0,
			"",
			HFILL }},
	{ &hf_eth_edp_srcport,
	  { "Source Port",
	    "eth_edp.srcport",
	    FT_UINT16,
	    BASE_DEC,
	    NULL,
	    0x0,
	    "",
	    HFILL }},
	{ &hf_eth_edp_len,
	  { "Data Len",
	    "eth_edp.len",
	    FT_UINT16,
	    BASE_DEC,
	    NULL,
	    0x0,
	    "",
	    HFILL}},
	{ &hf_eth_edp_ctype,
	  { "CType",
	    "eth_edp.ctype",
	    FT_UINT8,
	    BASE_DEC,
	    VALS(packettypenames),
	    0x0,
	    "",
	    HFILL}}
};

/* Setup protocol subtree array */
static gint *ett[] = {
	&ett_eth_edp
};

void
proto_register_eth_edp(void)
{
	if (proto_eth_edp == -1) {
		module_t *eth_edp_module;
		proto_eth_edp = proto_register_protocol(
		                        "Ethernet Datagram Protocol",
		                        "ETH_EDP",          /* short name */
		                        "eth_edp"           /* abbrev */
		                );
		proto_register_subtree_array(ett, array_length(ett));

		/* Register configuration preferences */
		eth_edp_module = prefs_register_protocol(proto_eth_edp, NULL);
		prefs_register_bool_preference(eth_edp_module, "try_heuristic_first",
		                               "Try heuristic sub-dissectors first",
		                               "Try to decode a packet using an heuristic sub-dissector before using a data-dissector",
		                               &try_heuristic_first);
	}

	register_heur_dissector_list("eth_edp", &heur_subdissector_list);
}

void proto_reg_handoff_eth_edp(void)
{
	eth_edp_handle = create_dissector_handle(dissect_eth_edp, proto_eth_edp);
	dissector_add("ethertype", ETHERTYPE_ETH_EDP, eth_edp_handle);
	proto_register_field_array(proto_eth_edp, hf_eth_edp, array_length(hf_eth_edp));
	data_handle = find_dissector("data");
	eth_edp_tap = register_tap("eth_edp");
	eth_edp_follow_tap = register_tap("eth_edp_follow");
}

void dissect_eth_edp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
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
			uint8_t ctype = tvb_get_guint8(tvb, 5);
			col_append_fstr(pinfo->cinfo, COL_INFO, "KERNEL > %u [%s]", eth_edph->eh_dport,
			                val_to_str(ctype, packettypenames, "Unknown (0x%02x)"));
		} else if (eth_edph->eh_dport == 0) {
			uint8_t ctype = tvb_get_guint8(tvb, 5);
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

		ti = proto_tree_add_item(tree, proto_eth_edp, tvb, 0, -1, FALSE);
		eth_edp_tree = proto_item_add_subtree(ti, ett_eth_edp);
		proto_tree_add_uint_format(eth_edp_tree, hf_eth_edp_dstport, tvb, offset, 2, eth_edph->eh_dport,
		                           "Destination port: %u", eth_edph->eh_dport);
		proto_tree_add_uint_hidden(eth_edp_tree, hf_eth_edp_dstport, tvb, offset, 2, eth_edph->eh_dport);
		offset += 2;

		proto_tree_add_uint_format(eth_edp_tree, hf_eth_edp_srcport, tvb, offset, 2, eth_edph->eh_sport,
		                           "Source port: %u", eth_edph->eh_sport);
		proto_tree_add_uint_hidden(eth_edp_tree, hf_eth_edp_srcport, tvb, offset, 2, eth_edph->eh_sport);
		offset += 2;

		proto_tree_add_uint_format(eth_edp_tree, hf_eth_edp_len, tvb, offset, 2, eth_edph->eh_len,
		                           "Length: %u", eth_edph->eh_len);
		proto_tree_add_uint_hidden(eth_edp_tree, hf_eth_edp_len, tvb, offset, 2, eth_edph->eh_len);
		offset += 2;

		if (eth_edph->eh_dport == 0 || eth_edph->eh_sport == 0) {
			uint8_t ctype = tvb_get_guint8(tvb, 5);
			proto_tree_add_uint_format(eth_edp_tree, hf_eth_edp_ctype, tvb, offset, 1, ctype,
			                           "CType: %s (%u)",
			                           val_to_str(ctype, packettypenames, "Unknown (0x%02x)"), ctype);
			proto_tree_add_uint_hidden(eth_edp_tree, hf_eth_edp_ctype, tvb, offset, 1, ctype);
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
		next_tvb = tvb_new_subset(tvb, offset, len, len);

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
