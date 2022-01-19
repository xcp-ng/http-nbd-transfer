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

.PHONY: all
all: multi-http-plugin.so

multi-http-plugin.so:
	$(CC) $(CFLAGS) -fPIC -shared multi-http-plugin.c -o $@ $(LDFLAGS)

clean:
	$(RM) *.so
