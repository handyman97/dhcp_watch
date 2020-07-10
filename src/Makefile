#
all::
clean::;	rm -f *~ *.o

PREFIX		?= /usr/local
TOP_DIR		= $(shell readlink -f ..)
BUILD_DIR	= $(TOP_DIR)/_build

OBJS		= logger.o
BINS		= dhcp_watch

OBJS		:= $(OBJS:%=$(BUILD_DIR)/%)
BINS		:= $(BINS:%=$(BUILD_DIR)/%)

CC		= gcc
CFLAGS		= -g

include ./Makefile.common

#

all::	$(BINS)

# sniffer
$(BUILD_DIR)/dhcp_watch:	$(BUILD_DIR)/main.o
	$(CC) $(COPTS) $< -o $@ -lpcap -lmosquitto
#dhcp_watch.o:	dhcp_watch.c
#	$(CC) $(COPTS) -c $<

#
veryclean::	clean

install::	$(BINS)
	@mkdir -p $(PREFIX)/bin
	cp -fp $(BINS) $(PREFIX)/bin
