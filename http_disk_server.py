#!/usr/bin/env python

#
# Copyright (C) 2022  Vates SAS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

from __future__ import print_function

import sys

if sys.version_info > (3,):
    from http.server import BaseHTTPRequestHandler, HTTPServer

    def get_header(handler, header):
        return handler.headers.get(header)
else:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

    def get_header(handler, header):
        return handler.headers.getheader(header)

from io import BytesIO
import argparse
import errno
import fcntl
import json
import os
import signal
import socket
import stat
import struct
import subprocess
import threading
import time
import traceback

BLKGETSIZE64 = 0x80081272
BLKFLSBUF = (0x12 << 8) + 97  # Flush buffer cache.

REQ_LIMIT_SIZE = 1024 * 1024 * 128  # In bytes.

DRBD_MAJOR = 147
DRBD_BY_RES_PATH = '/dev/drbd/by-res/'

DRBD_OPEN_SLEEP = 1.0  # In seconds.

# ==============================================================================

OUTPUT_PREFIX = ''

SIGTERM_RECEIVED = False
STARTING_SERVER = True

VERBOSE = False

def handle_sigterm(*args):
    global SIGTERM_RECEIVED
    SIGTERM_RECEIVED = True

# -----------------------------------------------------------------------------

def check_bindable(port):
    p = subprocess.Popen(
        ['lsof', '-i:' + str(port), '-Fp'],
        stdout=subprocess.PIPE,
        close_fds=True,
        universal_newlines=True
    )

    stdout, stderr = p.communicate()
    if p.returncode:
        return True

    pid = stdout[1:].rstrip() # remove 'p' before pid
    eprint('Cannot use port {}, already used by: {}.'.format(port, pid))
    return False

def eprint(str):
    print(OUTPUT_PREFIX + str, file=sys.stderr)

def dprint(str):
    if VERBOSE:
        eprint(str)

def is_drbd_device(path):
    try:
        st = os.stat(path)
    except Exception as e:
        eprint('Failed to execute `stat` call on `{}`: {}.'.format(path, e))
        return False
    return stat.S_ISBLK(st.st_mode) and os.major(st.st_rdev) == DRBD_MAJOR

def open_device(dev_path, retry=True):
    def cannot_open(e):
        raise Exception('Cannot open device `{}`: `{}`.'.format(dev_path, e))

    is_drbd = None
    while not SIGTERM_RECEIVED:
        try:
            disk_fd = os.open(dev_path, os.O_RDWR)
            eprint('Disk open!')
            return disk_fd
        except OSError as e:
            if e.errno == errno.EAGAIN or e.errno == errno.EINTR:
                continue
            if e.errno != errno.EROFS or not retry:
                cannot_open(e)

            if is_drbd is None:
                is_drbd = is_drbd_device(dev_path)
            if not is_drbd:
                cannot_open(e)

            if not SIGTERM_RECEIVED:
                time.sleep(DRBD_OPEN_SLEEP)

def close_device(fd):
    if not fd:
        return

    while True:
        try:
            os.close(fd)
            return
        except OSError as e:
            if e.errno == errno.EBADF:
                return
            if e.errno == errno.EINTR:
                continue
            raise
        except Exception as e:
            eprint('Cannot close fd {}: `{}`.'.format(fd, e))
            return

def is_openable(dev_path):
    if not is_drbd_device(dev_path):
        return True # Assume non-DRBD paths are always openable.

    if dev_path.startswith(DRBD_BY_RES_PATH):
        prefix_len = len(DRBD_BY_RES_PATH)
        res_name_end = dev_path.find('/', prefix_len)
        assert res_name_end != -1
        resource_name = dev_path[prefix_len:res_name_end]
    else:
        assert False # TODO: Implement me.

    try:
        p = subprocess.Popen(
            ['drbdsetup', 'status', resource_name, '--json'],
            stdout=subprocess.PIPE,
            close_fds=True,
            universal_newlines=True
        )
    except OSError:
        return False # Binary not installed.

    stdout, stderr = p.communicate()
    if p.returncode:
        return False

    try:
        conf = json.loads(stdout)
        if not conf:
            return False

        for connection in conf[0]['connections']:
            if connection['peer-role'] == 'Primary':
                return False
    except Exception as e:
        eprint('Failed to read DRBD res status: `{}`.'.format(e))
        return False

    return True

def get_device_size(fd):
    disk_capacity = -1
    while True:
        try:
            fd_stat = os.fstat(fd)
            if stat.S_ISBLK(fd_stat.st_mode):
                buf = fcntl.ioctl(fd, BLKGETSIZE64, b' ' * 8)
                disk_capacity = struct.unpack('L', buf)[0]
            else:
                disk_capacity = fd_stat.st_size
            break
        except OSError as e:
            if e.errno != errno.EINTR:
                eprint('Can\'t get device size: `{}`.'.format(e))
                raise
        except Exception as e:
            eprint('Can\'t get device size (generic): `{}`.'.format(e))
            raise
    return disk_capacity

# -----------------------------------------------------------------------------

def MakeRequestHandler(disk_fd, is_block_device):
    class RequestHandler(BaseHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            # Note: We cannot use this call in python 2:
            # super(RequestHandler, self).__init__(*args, **kwargs)
            # > TypeError: must be type, not classobj
            #
            # The base class of `BaseHTTPRequestHandler` uses an old def:
            # "class BaseRequestHandler:"
            self.disk_fd = disk_fd
            self.is_block_device = is_block_device
            BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

        def get_content_size(self):
            return get_device_size(self.disk_fd)

        # Ignore broken pipe for python2 version.
        # See: https://stackoverflow.com/questions/6063416/python-basehttpserver-how-do-i-catch-trap-broken-pipe-errors#answer-14355079
        def finish(self):
            try:
                if not self.wfile.closed:
                    self.wfile.flush()
                    self.wfile.close()
            except socket.error:
                pass
            self.rfile.close()

        def parse_range(self):
            req_range = self.headers.get('range')
            if req_range is None:
                self.send_response(400)
                self.end_headers()
                return

            if req_range.startswith('bytes'):
                req_range = req_range[5:].strip()
                if req_range.startswith('='):
                    try:
                        values = req_range[1:].lstrip().split('-')
                        begin = int(values[0])
                        end = int(values[1])
                        if begin <= end and end - begin < self.get_content_size():
                            return [begin, end - begin + 1]
                    except Exception:
                        pass

            # Return error: "Range Not Satisfiable".
            self.send_response(416)
            self.end_headers()

        def parse_content_range(self):
            req_range = self.headers.get('Content-Range')
            if req_range is None:
                self.send_response(400)
                self.end_headers()
                return

            if req_range.startswith('bytes'):
                req_range = req_range[5:].strip()
                try:
                    values = req_range.split('-')
                    begin = int(values[0])
                    end = int(values[1].split('/')[0].strip())
                    if begin <= end and end - begin < self.get_content_size():
                        return [begin, end - begin + 1]
                except Exception:
                    pass

            # Return error: "Range Not Satisfiable".
            self.send_response(416)
            self.end_headers()

        def _log_message(self, func, format, *args):
            func('%s - - [%s] %s\n' % (
                self.address_string() if sys.version_info > (3,) else self.client_address[0],
                self.log_date_time_string(),
                format % args
            ))

        def log_message(self, format, *args):
            self._log_message(dprint, format, *args)

        def log_error(self, format, *args):
            self._log_message(eprint, format, *args)

        def do_HEAD(self):
            self.send_response(200)
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('Content-Length', str(self.get_content_size()))
            self.end_headers()

        def do_GET(self):
            req_range = self.parse_range()
            if not req_range:
                return

            offset = req_range[0]
            size = min(req_range[1], REQ_LIMIT_SIZE)

            try:
                dprint('GET [{}]: Read {}B at {}.'.format(self.client_address[0], size, offset))
                os.lseek(self.disk_fd, offset, os.SEEK_SET)
                chunk = os.read(self.disk_fd, size)
            except Exception as e:
                eprint('Can\'t do GET: `{}`.'.format(e))
                self.send_response(500)
                self.end_headers()
                return

            self.send_response(206)
            self.send_header('Content-Range', 'bytes {}-{}/{}'.format(offset, size - 1, self.get_content_size()))
            self.send_header('Content-Length', str(int(size)))
            self.end_headers()

            self.wfile.write(chunk)

        def do_PUT(self):
            req_range = self.parse_content_range()
            if not req_range:
                return

            offset = req_range[0]
            size = req_range[1]

            try:
                encoding = get_header(self, 'Transfer-Encoding')
                if encoding is not None:
                    if encoding != 'chunked':
                        raise Exception('Unsupported encoding: `{}`.'.format(encoding))

                    chunk = bytearray()
                    while True:
                        chunk_size = int(self.rfile.readline().strip(), 16)
                        if not chunk_size:
                            break
                        chunk.extend(self.rfile.read(chunk_size))
                        self.rfile.readline()

                    if len(chunk) != size:
                        raise Exception('Inconsistent values between chunked data and content range size!')
                else:
                    chunk = self.rfile.read(size)
                    if len(chunk) < size:
                        raise Exception('Truncated chunk!')

                dprint('PUT [{}]: Write {}B at {}.'.format(self.client_address[0], len(chunk), offset))
                os.lseek(self.disk_fd, offset, os.SEEK_SET)
                os.write(self.disk_fd, chunk)
                if self.is_block_device:
                    fcntl.ioctl(self.disk_fd, BLKFLSBUF)
                else:
                    os.fsync(self.disk_fd)
            except Exception as e:
                eprint('Can\'t do PUT: `{}`.'.format(e))
                self.send_response(500)
                self.end_headers()
                return

            self.send_response(200)
            self.end_headers()
            response = BytesIO()
            response.write(b'Ok.')

            # Write response for all python versions.
            # Handle broken pipe error for python3 version.
            try:
                self.wfile.write(response.getvalue())
            except Exception:
                if sys.version_info > (3,):
                    from builtins import BrokenPipeError
                    try:
                        raise
                    except BrokenPipeError:
                        # The client closed the connection too early,
                        # so we should ignore the error.
                        pass
                else:
                    raise

    return RequestHandler

class HttpDiskServer(HTTPServer):
    def __init__(self, *args, **kwargs):
        # Reuse old port to avoid: "Address already in use".
        self.allow_reuse_address = True
        HTTPServer.__init__(self, *args, **kwargs)
        self.ready_event = threading.Event()

    def serve_forever(self, poll_interval=0.5):
        self.ready_event.set()
        HTTPServer.serve_forever(self, poll_interval)

    def wait_startup(self):
        self.ready_event.wait()

# -----------------------------------------------------------------------------

def run_server(disk, ip, port):
    # Check if we can use this port.
    if not check_bindable(port):
        return

    # Note: We try to open the device and start the HTTP server to handle requests before
    # sending the message below to the calling process. If we can't open the device, or if
    # there is an issue during the first open call, we emit the message, because there
    # is probably a running server on another machine.
    #
    # The goal of this function is to notify the caller and to be sure to always have
    # a running server before sending requests. We try to prevent HTTP errors like
    # "Destination Host Unreachable".
    def emit_server_ready():
        global STARTING_SERVER
        if STARTING_SERVER:
            eprint('Server ready!')
            STARTING_SERVER = False

    httpd = None
    httpd_thread = None
    disk_fd = None
    while True:
        if SIGTERM_RECEIVED:
            eprint('SIGTERM received. Exiting server...')
            break

        try:
            if STARTING_SERVER:
                # It's useful in the case of a DRBD to check if the path
                # is openable, mainly when this param is set:
                # "DrbdOptions/Resource/auto-promote-timeout".
                # In the worst case, we may be stuck in an open call for 1 min.
                if not is_openable(disk):
                    # Emit server ready and wait for openable disk.
                    continue
                # Try to open device without retry first and then emit ready message.
                # In case of concurrent calls with DRBD, we may stuck for many seconds.
                disk_fd = open_device(disk, retry=False)
            else:
                disk_fd = open_device(disk)

            if SIGTERM_RECEIVED:
                break

            is_block_device = stat.S_ISBLK(os.fstat(disk_fd).st_mode)

            HandlerClass = MakeRequestHandler(disk_fd, is_block_device)
            httpd = HttpDiskServer((ip or '', port), HandlerClass)
            httpd_thread = threading.Thread(target=httpd.serve_forever)
            httpd_thread.start()

            if STARTING_SERVER:
                httpd.wait_startup()
                # We emit only after effective startup.
                emit_server_ready()

            while not SIGTERM_RECEIVED:
                signal.pause()
        except KeyboardInterrupt:
            eprint('Exiting server...')
            break
        except Exception as e:
            eprint('Unhandled exception: `{}`.'.format(e))
            eprint(traceback.format_exc())
            eprint('Restarting server...')
            if not STARTING_SERVER:
                time.sleep(1)
        finally:
            try:
                if httpd_thread:
                    httpd.shutdown()
                    httpd_thread.join()
                    httpd_thread = None
                if httpd:
                    httpd.server_close()
                    httpd = None
            except Exception as e:
                eprint('Failed to close server: {}.'.format(e))
            finally:
                close_device(disk_fd)

                # Make sure we notify for server startup if the device cannot be opened.
                # Or in case of exception during the first open call. It can be triggered
                # if we failed to open the volume due to concurrent DRBD calls.
                emit_server_ready()

# ==============================================================================

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--disk', action='store', dest='disk', default=None, required=True,
        help='Device to share'
    )
    parser.add_argument(
        '--ip', action='store', dest='ip', type=str, default='', required=False,
        help='IP to use'
    )
    parser.add_argument(
        '--port', action='store', dest='port', type=int, default=8000, required=False,
        help='Port to use'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true', dest='verbose', default=False, required=False,
        help='Enable verbose logging'
    )

    args = parser.parse_args()
    global OUTPUT_PREFIX
    OUTPUT_PREFIX = '[' + os.path.basename(os.path.realpath(args.disk)) + '] '
    global VERBOSE
    VERBOSE = args.verbose
    signal.signal(signal.SIGTERM, handle_sigterm)
    run_server(args.disk, args.ip, args.port)

if __name__ == '__main__':
    main()
