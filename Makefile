#! /usr/bin/make -f
# -*- makefile -*-
#
# Copyright 2008-2009  Sven Eckelmann <sven.eckelmann@gmx.de>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	Q_CC = @echo '   ' CC $@;
	Q_LD = @echo '   ' LD $@;
	export Q_CC
	export Q_LD
endif
endif

WIRESHARK_INCLUDE_PATH = /usr/include/wireshark/
WIRESHARK_LIBRARY_PATH = /usr/lib/wireshark/

include Makefile.common

SRCS = $(DISSECTOR_SRC) plugin.c

OBJS = $(foreach src, $(SRCS), $(src:.c=.o))

PLUGIN = $(PLUGIN_NAME).so
PLUGIN_DIR = $(HOME)/.wireshark/plugins
PLUGIN_INSTALL = $(PLUGIN_DIR)/$(PLUGIN)

WIRESHARK_FLAGS = -DHAVE_CONFIG_H -I$(WIRESHARK_INCLUDE_PATH)
CFLAGS = -Wall -D_U_= $(WIRESHARK_FLAGS) `pkg-config --cflags glib-2.0` -fPIC -DPIC

WIRESHARK_LDFLAGS = -L$(WIRESHARK_LIBRARY_PATH) -lwireshark
LDFLAGS += -Wl,--export-dynamic $(WIRESHARK_LDFLAGS) `pkg-config --libs glib-2.0`

all: $(PLUGIN)

$(PLUGIN): $(OBJS)
	$(Q_LD)$(CC) -shared $(OBJS) $(LDFLAGS) -Wl,-soname -Wl,$(PLUGIN).so -o $@

%.o : %.c
	$(Q_CC)$(CC) -c $(CFLAGS) $< -o $@

install: $(PLUGIN)
	install -d $(PLUGIN_DIR)
	install $(PLUGIN) $(PLUGIN_INSTALL)

clean:
	rm -f $(OBJS) $(PLUGIN)
