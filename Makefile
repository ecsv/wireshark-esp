WIRESHARK_INCLUDE_PATH = /usr/include/wireshark/
WIRESHARK_LIBRARY_PATH = /usr/lib/wireshark/

include Makefile.common

SRCS = $(DISSECTOR_SRC) plugin.c

OBJS = $(foreach src, $(SRCS), $(src:.c=.o))

PLUGIN = $(PLUGIN_NAME).so
PLUGIN_DIR = $(HOME)/.wireshark/plugins
PLUGIN_INSTALL = $(PLUGIN_DIR)/$(PLUGIN)

WIRESHARK_FLAGS = -DHAVE_CONFIG_H -I$(WIRESHARK_INCLUDE_PATH)
CFLAGS = -Wall $(WIRESHARK_FLAGS) `pkg-config --cflags glib-2.0`-fPIC -DPIC

WIRESHARK_LDFLAGS = -L$(WIRESHARK_LIBRARY_PATH) -lwireshark
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
