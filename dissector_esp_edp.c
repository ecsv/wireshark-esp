#include "dissector_esp_edp.h"

#ifndef ENABLE_STATIC
/* forward declaration */
G_MODULE_EXPORT extern const gchar version[];
G_MODULE_EXPORT void plugin_register(void);
G_MODULE_EXPORT void plugin_reg_handoff(void);

G_MODULE_EXPORT const gchar version[] = "0.0";

G_MODULE_EXPORT void plugin_register(void)
{
	if (proto_eth_edp == -1) {
		proto_register_eth_edp();
	}

	if (proto_eth_esp == -1) {
		proto_register_eth_esp();
	}
}

G_MODULE_EXPORT void plugin_reg_handoff(void)
{
	proto_reg_handoff_eth_edp();
	proto_reg_handoff_eth_esp();
}
#endif
