CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11

BUILD_DIR := build
SRC_DIR := quic

all: $(BUILD_DIR)/broker_quic $(BUILD_DIR)/subscriber_quic $(BUILD_DIR)/publisher_quic

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/broker_quic: $(SRC_DIR)/broker_quic.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD_DIR)/subscriber_quic: $(SRC_DIR)/subscriber_quic.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD_DIR)/publisher_quic: $(SRC_DIR)/publisher_quic.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BUILD_DIR) *.o

.PHONY: all clean
