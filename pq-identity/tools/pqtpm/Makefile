# Builds the pqtpm bridge against the task-local wolfTPM (socket/swtpm transport, v1.85)
# and wolfSSL (ML-DSA) builds. Both are GPLv3; so is this tool (see LICENSE).
TOOLCHAIN ?= ../../.toolchain
CC ?= cc
CFLAGS ?= -O2 -Wall -Wno-unused-function -DHAVE_CONFIG_H -DWOLFTPM_SWTPM -DWOLFTPM_V185 -DWOLFTPM_AUTODETECT -DWOLFTPM_CHECK_WAIT_STATE -DWOLFTPM_EXAMPLE_HAL -DWOLFTPM_PROVISIONING -DWOLFTPM_FWTPM_BUILD -DTPM2_SWTPM_PORT=2321
INC = -I$(TOOLCHAIN)/wolftpm/include -I$(TOOLCHAIN)/wolfssl/include
LIBS = $(TOOLCHAIN)/wolftpm/libwolftpm.a $(TOOLCHAIN)/wolfssl/lib/libwolfssl.a -lm -lpthread

pqtpm: pqtpm.c
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIBS)

clean:
	rm -f pqtpm
