#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gmodule.h>

#include "moduleinfo.h"

#ifndef ENABLE_STATIC
G_MODULE_EXPORT void plugin_register(void);
G_MODULE_EXPORT void plugin_reg_handoff(void);

G_MODULE_EXPORT const gchar version[] = VERSION;

/* Start the functions we need for the plugin stuff */

G_MODULE_EXPORT void
plugin_register(void)
{
	{
		extern void proto_register_eth_edp(void);
		extern void proto_register_eth_esp(void);
		proto_register_eth_edp();
		proto_register_eth_esp();
	}
}

G_MODULE_EXPORT void
plugin_reg_handoff(void)
{
	{
		extern void proto_reg_handoff_eth_edp(void);
		extern void proto_reg_handoff_eth_esp(void);
		proto_reg_handoff_eth_edp();
		proto_reg_handoff_eth_esp();
	}
}
#endif
