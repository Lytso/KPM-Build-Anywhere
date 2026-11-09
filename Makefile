# Makefile for Kernel Patch Module (KPM) build system
# Enhanced by @ItsLytso for local Termux & CI builds

ifeq ($(OS), Windows_NT)
    PLATFORM := windows-x86_64
else
    PLATFORM := linux-x86_64
endif

# Check if NDK_PATH is provided; otherwise fallback to host clang if aarch64
ifdef NDK_PATH
    TARGET_COMPILE := $(NDK_PATH)/toolchains/llvm/prebuilt/$(PLATFORM)/bin/
    CC := $(TARGET_COMPILE)aarch64-linux-android31-clang
    LD := $(TARGET_COMPILE)ld.lld
    STRIP := $(TARGET_COMPILE)llvm-strip
else
    # Host compiler (e.g. Termux ARM64)
    CC ?= clang
    LD ?= ld.lld
    STRIP ?= llvm-strip
endif

ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS = $(INCLUDE_FLAGS) -Wall -Ofast -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables -fno-semantic-interposition -U_FORTIFY_SOURCE -fno-common -fvisibility=hidden
LDFLAGS += -s

MODULES := lytso_spoof.kpm hello.kpm

all: $(MODULES)

%.kpm: %.o
	$(CC) $(LDFLAGS) -r -o $@ $^
	$(STRIP) -g --strip-unneeded --strip-debug --remove-section=.comment --remove-section=.note.GNU-stack $@

%.o: %.c
	$(CC) $(CFLAGS) -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -rf *.o *.kpm