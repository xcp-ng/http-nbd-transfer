CC = gcc

CFLAGS = \
	--std=gnu99 \
	-Wall \
	-Wcast-align \
	-Wconversion \
	-Wextra \
	-Wfloat-equal \
	-Winit-self \
	-Wpointer-arith \
	-Wreturn-type \
	-Wsign-conversion \
	-Wuninitialized \
	-Wlogical-op

LDFLAGS = -lcurl

ifeq ($(PREFIX),)
	PREFIX := /usr/local
endif

.PHONY: all
all: nbdkit-multi-http-plugin.so

nbdkit-multi-http-plugin.so:
	$(CC) $(CFLAGS) -fPIC -shared nbdkit-multi-http-plugin.c -o $@ $(LDFLAGS)

install: nbdkit-multi-http-plugin.so
	mkdir -p $(DESTDIR)$(PREFIX)/lib64/nbdkit/plugins/
	cp nbdkit-multi-http-plugin.so $(DESTDIR)$(PREFIX)/lib64/nbdkit/plugins/
	mkdir -p $(DESTDIR)$(PREFIX)/bin/
	cp nbd-http-server $(DESTDIR)$(PREFIX)/bin/
	cp http-disk-server $(DESTDIR)$(PREFIX)/bin/

clean:
	$(RM) *.so
