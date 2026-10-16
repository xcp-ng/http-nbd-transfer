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

# Tests are installed with a pytest.ini giving the path of the installed binaries.
TESTS_DIR = $(PREFIX)/share/http-nbd-transfer

install-tests:
	mkdir -p $(DESTDIR)$(TESTS_DIR)/tests/
	cp tests/*.py $(DESTDIR)$(TESTS_DIR)/tests/
	printf '%s\n' \
		'[pytest]' \
		'bin_dir = $(PREFIX)/bin' \
		> $(DESTDIR)$(TESTS_DIR)/pytest.ini

clean:
	$(RM) *.so
