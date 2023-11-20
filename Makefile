CC := gcc
CXX = gcc

TARGET_EXEC := tcp_monitor

BUILD_DIR := ./build
SRC_DIRS := ./src

SRCS := $(shell find $(SRC_DIRS) -name '*.c' -or -name '*.s')
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

INC_DIRS := $(SRC_DIRS) /usr/include/glib-2.0 /usr/lib/x86_64-linux-gnu/glib-2.0/include
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

CFLAGS := $(INC_FLAGS)
CXXFLAGS :=
LDFLAGS := -lpcap -lpthread -lglib-2.0

all: $(BUILD_DIR)/$(TARGET_EXEC)

debug: CFLAGS := -DDEBUG -g $(CFLAGS)
debug: CXXFLAGS := -DDEBUG -g
debug: $(BUILD_DIR)/$(TARGET_EXEC)

$(BUILD_DIR)/$(TARGET_EXEC): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.c.o: %.c
	mkdir -p $(dir $@)
	$(CXX) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -r $(BUILD_DIR)
