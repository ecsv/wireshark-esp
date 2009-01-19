WIRESHARK_INCLUDE_PATH = /usr/include/wireshark/
WIRESHARK_LIBRARY_PATH = /usr/lib/wireshark/

include Makefile.common

SRCS = $(DISSECTOR_SRC) plugin.c

OBJS = $(foreach src, $(SRCS), $(src:.c=.o))

PLUGIN = $(PLUGIN_NAME).so
PLUGIN_DIR = $(HOME)/.wireshark/plugins
PLUGIN_INSTALL = $(PLUGIN_DIR)/$(PLUGIN)

WIRESHARK_FLAGS = -DHAVE_CONFIG_H -I$(WIRESHARK_INCLUDE_PATH)
EXTRA_FLAGS = -D_U_= $(WIRESHARK_FLAGS) `pkg-config --cflags glib-2.0` -fPIC -DPIC
CFLAGS = -Wall

WIRESHARK_LDFLAGS = -L$(WIRESHARK_LIBRARY_PATH) -lwireshark
EXTRA_LDFLAGS = $(WIRESHARK_LDFLAGS) `pkg-config --libs glib-2.0`
LDFLAGS += -Wl,--export-dynamic

all: $(PLUGIN)

$(PLUGIN): $(OBJS)
	$(CC) -shared $(OBJS) $(LDFLAGS) $(EXTRA_LDFLAGS) -Wl,-soname -Wl,$(PLUGIN).so -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $(EXTRA_FLAGS) $< -o $@

install: $(PLUGIN)
	install -d $(PLUGIN_DIR)
	install $(PLUGIN) $(PLUGIN_INSTALL)

clean:
	rm -f $(OBJS) $(PLUGIN)
