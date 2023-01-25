# http-nbd-transfer

Set of tools to transfer NBD requests to an HTTP server:

  - `http-disk-server` is used to handle HTTP requests and to read/write in a device.
  - `nbd-server` is used to create a new NBD on the system, and to communicate with one or many HTTP servers.
    If a request fails, another attempt is launched on another server.

## Dependencies

- `gcc` & `make` to build sources
- `curl` devel C lib
- `nbdkit` devel C lib
- `nbd` to use `nbd-client` binary
-
## Build

Run `make` command directly in the root project directory.


## Example

Execute on the first host:
```
# Start the HTTP server and attach a DRBD volume to it.
# All range requests are forwarded to this volume.
> http-disk-server --disk /dev/drbd/by-res/xcp-volume-eccacf4a-a5b7-4a4a-b397-8011dcf5f5f9/0
```

And on the secondary:
```
# Start a NBD server
> nbd-server --socket-path ./socket --nbd-name heartbeat --urls "http://totor-a:8000,http://totor-b:8000"
nbdkit: debug: TLS disabled: could not load TLS certificates
nbdkit: debug: registering plugin /root/http-nbd-transfer/multi-http-plugin.so
nbdkit: debug: registered plugin /root/http-nbd-transfer/multi-http-plugin.so (name multihttp)
nbdkit: debug: multihttp: load
nbdkit: debug: multihttp: config key=urls, value=http://totor-a:8000,http://totor-b:8000
nbdkit: debug: multihttp: config_complete
nbdkit: debug: bound to unix socket /root/http-nbd-transfer/./socket
nbdkit: debug: accepted connection
nbdkit: multihttp[1]: debug: newstyle negotiation: flags: global 0x3
nbdkit: multihttp[1]: debug: newstyle negotiation: client flags: 0x3
nbdkit: multihttp[1]: debug: newstyle negotiation: NBD_OPT_EXPORT_NAME: client requested export '' (ignored)
nbdkit: multihttp[1]: debug: multihttp: open readonly=0
nbdkit: multihttp[1]: debug: Trying to use server: `http://totor-a:8000`...
nbdkit: multihttp[1]: debug: Selected server: `http://totor-a:8000`.
nbdkit: multihttp[1]: debug: Device size: 4311818240.
nbdkit: multihttp[1]: debug: get_size
nbdkit: multihttp[1]: debug: can_write
nbdkit: multihttp[1]: debug: can_zero
nbdkit: multihttp[1]: debug: can_write
nbdkit: multihttp[1]: debug: can_trim
nbdkit: multihttp[1]: debug: can_fua
nbdkit: multihttp[1]: debug: can_flush
nbdkit: multihttp[1]: debug: is_rotational
nbdkit: multihttp[1]: debug: newstyle negotiation: flags: export 0x41
nbdkit: multihttp[1]: debug: handshake complete, processing requests serially
NBD `/dev/nbd15` is now attached.
nbdkit: multihttp[1]: debug: pread count=4096 offset=0
```

After the start of the NBD server, you can see the device to use in the previous trace.
Here: `/dev/nbd15`.

You should have a similar trace on the first host:

```
172.16.211.126 - - [20/Jan/2022 11:21:58] "HEAD / HTTP/1.1" 200 -
172.16.211.126 - - [20/Jan/2022 11:21:58] "GET / HTTP/1.1" 206 -
```

Now you can use a script like this in the secondary to write a request in the NBD, this last one will be transfered to the remote:

```
> python
Python 2.7.5 (default, Jul 13 2018, 13:06:57)
[GCC 4.8.5 20150623 (Red Hat 4.8.5-28)] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> dev = os.open('/dev/nbd15', os.O_RDWR | os.O_SYNC)
>>> os.lseek(dev, 4096 * 20, os.SEEK_SET)
81920
>>> os.write(dev, "toto")
4
```
