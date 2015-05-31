#
# Simple DNS Sniffer
# Copyright (C) 2015 Tim Hentenaar.
#
# This code is licensed under the Simplified BSD License.
# See the LICENSE file for details.
#

CC=gcc
CFLAGS=-O2 -Wall -fPIC
OBJS=sniffer.o dissect.o output.o
LIBS=-lpcap

sniffer: $(OBJS)
	@echo "  LD $@"
	@$(CC) -o $@ $(OBJS) $(LIBS)

all: sniffer

clean:
	@rm -f sniffer *.o

.c.o:
	@echo "  CC $@"
	@$(CC) $(CFLAGS) -c -o $@ $<

.SUFFIXES: .c .o
.PHONY: clean all
