CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -Os -s -Wall -Wextra
LDFLAGS = -lwinhttp -ladvapi32

LHOST ?= 127.0.0.1
LPORT ?= 443
KEY   ?= $(shell python3 -c "import secrets; print(secrets.token_hex(32))")

DEFINES = -DCALLBACK_HOST=\"$(LHOST)\" \
          -DCALLBACK_PORT=$(LPORT)     \
          -DPSK=\"$(KEY)\"

all: dew.exe

dew.exe: dew.c monocypher.c monocypher.h
	$(CC) $(CFLAGS) $(DEFINES) dew.c monocypher.c -o $@ $(LDFLAGS)

clean:
	rm -f dew.exe

.PHONY: all clean
