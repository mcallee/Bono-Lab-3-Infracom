CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -std=c11

# Ajusta /opt/homebrew a /usr/local si tu Homebrew es Intel
QUIC_INC  := -I/opt/homebrew/include -I/opt/homebrew/opt/openssl@3/include
QUIC_LIBS := -L/opt/homebrew/lib -L/opt/homebrew/opt/openssl@3/lib -lmsquic -lssl -lcrypto

QUIC_BROKER := build/broker_quic
QUIC_PUB    := build/publisher_quic
QUIC_SUB    := build/subscriber_quic

all: quic
quic: $(QUIC_BROKER) $(QUIC_PUB) $(QUIC_SUB)

$(QUIC_BROKER): quic/broker_quic.c
$(CC) $(CFLAGS) $(QUIC_INC) $< -o $@ $(QUIC_LIBS)

$(QUIC_PUB): quic/publisher_quic.c
$(CC) $(CFLAGS) $(QUIC_INC) $< -o $@ $(QUIC_LIBS)

$(QUIC_SUB): quic/subscriber_quic.c
$(CC) $(CFLAGS) $(QUIC_INC) $< -o $@ $(QUIC_LIBS)

clean:
rm -rf build/*

.PHONY: all quic clean
