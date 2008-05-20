SRCS = dissector_edp.c  dissector_esp.c  dissector_esp_edp.c

OBJS = $(foreach src, $(SRCS), $(src:.c=.o))

PLUGIN = packet-esp_edp.so
PLUGIN_DIR = $(HOME)/.wireshark/plugins
PLUGIN_INSTALL = $(PLUGIN_DIR)/$(PLUGIN)

WIRESHARK_FLAGS = -DHAVE_CONFIG_H -I/usr/include/wireshark
CFLAGS = -Wall $(WIRESHARK_FLAGS) `pkg-config --cflags glib-2.0`-fPIC -DPIC

WIRESHARK_LDFLAGS = -L/usr/lib/wireshark -lwireshark
LDFLAGS = $(WIRESHARK_LDFLAGS) `pkg-config --libs glib-2.0` -Wl,--export-dynamic

all: $(PLUGIN)

$(PLUGIN): $(OBJS)
	$(CC) -shared $(OBJS) $(LDFLAGS) -Wl,-soname -Wl,$(PLUGIN).so -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

install: $(PLUGIN)
	install -d $(PLUGIN_DIR)
	install $(PLUGIN) $(PLUGIN_INSTALL)

clean:
	rm -f $(OBJS) $(PLUGIN)
