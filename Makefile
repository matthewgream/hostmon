
##

CC=gcc
CFLAGS_COMMON=\
    -Wfloat-conversion -Werror=float-conversion \
    -Wall -Wextra -Werror -Wpedantic \
    -Wstrict-prototypes -Wold-style-definition \
    -Wno-cast-align -Wcast-qual -Wconversion \
    -Wfloat-equal -Wformat=2 -Wformat-security \
    -Winit-self -Wjump-misses-init \
    -Wlogical-op -Wmissing-include-dirs \
    -Wnested-externs -Wpointer-arith \
    -Wredundant-decls -Wshadow \
    -Wstrict-overflow=2 -Wswitch-default \
    -Wunreachable-code -Wunused \
    -Wwrite-strings \
    -Wdouble-promotion \
    -Wnull-dereference \
    -Wduplicated-cond \
    -Wduplicated-branches \
    -Wrestrict \
    -Wstringop-overflow \
    -Wundef \
    -Wvla \
    -Wno-duplicated-branches
CFLAGS_OPT=-O3
CFLAGS=$(CFLAGS_COMMON) $(CFLAGS_OPT)
LDFLAGS=
LIBS=-ljson-c -lmosquitto -lm -lpthread

##

TARGET=hostmon
# native = bare; cross = $(TARGET).<arch> via SUFFIX (the iotdata toolchain Makefile passes it).
SUFFIX ?=
BIN=$(TARGET)$(SUFFIX)
MAIN=hostmon.c
SOURCES=\
    config_linux.h mqtt_linux.h
HOSTNAME:=$(shell hostname)
CFG_SRC:=$(if $(wildcard $(TARGET).$(HOSTNAME).cfg),$(TARGET).$(HOSTNAME).cfg,$(TARGET).cfg)
# mosquitto bridge dropin: machine-specific only, NO default fallback (empty if absent).
MOSQ_CFG:=$(wildcard mosquitto.$(HOSTNAME).cfg)

##

all: $(BIN)

$(BIN): $(MAIN) $(SOURCES)
	$(CC) $(CFLAGS) -o $(BIN) $(MAIN) $(LDFLAGS) $(LIBS)

clean:
	rm -f $(TARGET) $(BIN) $(TARGET).armhf
format:
	clang-format-19 -i $(MAIN) $(SOURCES)
test: $(TARGET)
	./$(TARGET) --config $(CFG_SRC)

DEV_PACKAGES=libmosquitto-dev libjson-c-dev
DEV_PACKAGES_ARMHF=$(addsuffix :armhf,$(DEV_PACKAGES))
install-dev:
	apt install -y $(DEV_PACKAGES)
remove-dev:
	apt purge -y $(DEV_PACKAGES)
install-dev-armhf:
	dpkg --add-architecture armhf
	apt update
	apt install -y gcc-arm-linux-gnueabihf $(DEV_PACKAGES_ARMHF)
remove-dev-armhf:
	apt purge -y gcc-arm-linux-gnueabihf $(DEV_PACKAGES_ARMHF)
	dpkg --remove-architecture armhf
	apt update

CROSS_CC_ARMHF=arm-linux-gnueabihf-gcc
$(TARGET).armhf: $(MAIN) $(SOURCES)
	$(CROSS_CC_ARMHF) $(CFLAGS) -o $(TARGET).armhf $(MAIN) $(LDFLAGS) $(LIBS)
armhf: $(TARGET).armhf

.PHONY: all clean format install-dev remove-dev install-dev-armhf remove-dev-armhf armhf

##

INSTALL=hostmon
DIR_INSTALL=/usr/local/bin
DIR_DEFAULT=/etc/default
DIR_SYSTEMD=/etc/systemd/system
DIR_MOSQUITTO=/etc/mosquitto/conf.d
define install_service_systemd
	-systemctl stop $(2) 2>/dev/null || true
	-systemctl disable $(2) 2>/dev/null || true
	install -m 644 $(1).service $(DIR_SYSTEMD)/$(2).service
	systemctl daemon-reload
	systemctl enable $(2)
	systemctl start $(2) || echo "Warning: Failed to start $(2)"
endef
install_target: $(TARGET)
	install -m 755 $(TARGET) $(DIR_INSTALL)/$(INSTALL)
install_default: $(CFG_SRC)
	@echo "installing config from $(CFG_SRC)"
	install -m 644 $(CFG_SRC) $(DIR_DEFAULT)/$(INSTALL)
install_service: $(TARGET).service
	$(call install_service_systemd,$(TARGET),$(INSTALL))
install_mosquitto:
ifeq ($(MOSQ_CFG),)
	@echo "no mosquitto bridge config (mosquitto.$(HOSTNAME).cfg); skipping"
else
	@echo "installing mosquitto bridge from $(MOSQ_CFG)"
	install -m 644 $(MOSQ_CFG) $(DIR_MOSQUITTO)/$(INSTALL)-bridge.conf
	systemctl restart mosquitto || echo "Warning: Failed to restart mosquitto"
endif
install: install_target install_default install_service install_mosquitto
restart:
	systemctl restart $(INSTALL)
.PHONY: install install_target install_default install_service install_mosquitto
.PHONY: restart

##
