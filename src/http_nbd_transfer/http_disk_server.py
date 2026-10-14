#!/usr/bin/env python3

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

import argparse
import contextlib
import errno
import fcntl
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import signal
import socket
from socketserver import BaseServer, ThreadingMixIn
import stat
import struct
import sys
import threading
import time
import traceback

from http_nbd_transfer.platform import EXEC_PATH_DRBDSETUP, EXEC_PATH_LSOF
from http_nbd_transfer.process import CommandError, run_internal_command

from http_nbd_transfer.typing import Callable, cast, List, NoReturn, Optional, override, Set, Tuple, Type, Union

# ==============================================================================

BLKGETSIZE64 = 0x80081272
BLKFLSBUF = (0x12 << 8) + 97  # Flush buffer cache.

REQ_LIMIT_SIZE = 1024 * 1024 * 128  # In bytes.

# Timeout for closing a client connection when no data is received for N seconds.
DEFAULT_CLIENT_TIMEOUT = 60.0

DRBD_MAJOR = 147
DRBD_BY_RES_PATH = "/dev/drbd/by-res/"

DRBD_OPEN_SLEEP = 1.0  # In seconds.

# ------------------------------------------------------------------------------

SIGTERM_EVENT = threading.Event()

def handle_sigterm(*_args: object) -> None:
    SIGTERM_EVENT.set()

# ------------------------------------------------------------------------------

class LogConfig:
    prefix = ""
    verbose = False

LOG_CONFIG = LogConfig()

# ------------------------------------------------------------------------------

def check_bindable(port: int) -> bool:
    stdout, _stderr, ret_code = run_internal_command([EXEC_PATH_LSOF, "-i:" + str(port), "-Fp"], simple=False)
    if ret_code:
        return True

    pid = stdout[1:].rstrip() # remove 'p' before pid
    eprint(f"Cannot use port {port}, already used by: {pid}.")
    return False

def eprint(message: str) -> None:
    print(LOG_CONFIG.prefix + message, file=sys.stderr)  # noqa: T201

def dprint(message: str) -> None:
    if LOG_CONFIG.verbose:
        eprint(message)

def is_drbd_device(path: str) -> bool:
    try:
        st = Path(path).stat()
    except Exception as e:
        eprint(f"Failed to execute `stat` call on `{path}`: `{e}`.")
        return False
    return stat.S_ISBLK(st.st_mode) and os.major(st.st_rdev) == DRBD_MAJOR

def open_device(dev_path: str, *, retry: bool = True) -> Optional[int]:
    def cannot_open(e: OSError) -> NoReturn:
        raise Exception(f"Cannot open device `{dev_path}`: `{e}`.")

    is_drbd = None
    while not SIGTERM_EVENT.is_set():
        try:
            disk_fd = os.open(dev_path, os.O_RDWR)
            eprint("Disk open!")
            return disk_fd
        except OSError as e:  # noqa: PERF203
            if e.errno == errno.EAGAIN or e.errno == errno.EINTR:
                continue
            if e.errno != errno.EROFS or not retry:
                cannot_open(e)

            if is_drbd is None:
                is_drbd = is_drbd_device(dev_path)
            if not is_drbd:
                cannot_open(e)

            if not SIGTERM_EVENT.is_set():
                time.sleep(DRBD_OPEN_SLEEP)
    return None

def close_device(fd: Optional[int]) -> None:
    if not fd:
        return

    while True:
        try:
            os.close(fd)
            return
        except OSError as e:  # noqa: PERF203
            if e.errno == errno.EBADF:
                return
            if e.errno == errno.EINTR:
                continue
            raise
        except Exception as e:
            eprint(f"Cannot close fd {fd}: `{e}`.")
            return

def is_openable(dev_path: str) -> bool:
    if not is_drbd_device(dev_path):
        return True # Assume non-DRBD paths are always openable.

    if dev_path.startswith(DRBD_BY_RES_PATH):
        prefix_len = len(DRBD_BY_RES_PATH)
        res_name_end = dev_path.find("/", prefix_len)
        assert res_name_end != -1
        resource_name = dev_path[prefix_len:res_name_end]
    else:
        raise NotImplementedError(f"Only DRBD paths in `{DRBD_BY_RES_PATH}` are supported, got: `{dev_path}`.")

    try:
        stdout, _stderr, ret_code = run_internal_command(
            [EXEC_PATH_DRBDSETUP, "status", resource_name, "--json"],
            simple=False
        )
    except CommandError:
        return False # Binary not installed.

    if ret_code:
        return False

    try:
        conf = json.loads(stdout)
        if not conf:
            return False

        for connection in conf[0]["connections"]:
            if connection["peer-role"] == "Primary":
                return False
    except Exception as e:
        eprint(f"Failed to read DRBD res status: `{e}`.")
        return False

    return True

def pread(fd: int, size: int, offset: int) -> bytes:
    chunks: List[bytes] = []
    while size > 0:
        chunk = os.pread(fd, size, offset)
        if not chunk:
            break
        chunks.append(chunk)
        size -= len(chunk)
        offset += len(chunk)
    return b"".join(chunks)

def pwrite(fd: int, data: Union[bytes, bytearray], offset: int) -> None:
    chunk = memoryview(data)
    while chunk:
        written = os.pwrite(fd, chunk, offset)
        chunk = chunk[written:]
        offset += written

def get_device_size(fd: int) -> int:
    disk_capacity = -1
    while True:
        try:
            fd_stat = os.fstat(fd)
            if stat.S_ISBLK(fd_stat.st_mode):
                buf = fcntl.ioctl(fd, BLKGETSIZE64, b" " * 8)
                disk_capacity = struct.unpack("L", buf)[0]
            else:
                disk_capacity = fd_stat.st_size
            break
        except OSError as e:
            if e.errno != errno.EINTR:
                eprint(f"Can't get device size: `{e}`.")
                raise
        except Exception as e:
            eprint(f"Can't get device size (generic): `{e}`.")
            raise
    return disk_capacity

# ------------------------------------------------------------------------------

RequestType = Union[socket.socket, Tuple[bytes, socket.socket]]

def make_request_handler(  # noqa: C901
    disk_fd: int,
    *,
    is_block_device: bool,
    client_timeout: float
) -> Type[BaseHTTPRequestHandler]:
    class RequestHandler(BaseHTTPRequestHandler):
        # Use HTTP 1.1: TCP connections are reused and not directly closed.
        protocol_version = "HTTP/1.1"

        # Max time in seconds without data from a client. Without it,
        # a dead host would keep a thread and its connection forever.
        timeout = client_timeout

        # Headers and body are sent with separate `send` calls: without this, Nagle's
        # algorithm and delayed ACKs can add ~40ms to each small response.
        disable_nagle_algorithm = True

        def __init__(self, request: RequestType, client_address: Tuple[str, int], server: BaseServer) -> None:
            self.disk_fd = disk_fd
            self.is_block_device = is_block_device
            super().__init__(request, client_address, server)

        def get_content_size(self) -> int:
            return get_device_size(self.disk_fd)

        def send_response_and_close(self, code: int) -> None:
            # This method must be called in case of errors:
            # - In case of malformed request.
            # - Invalid buffer => close the connection, we can't reuse it.
            # - Body not consumed.
            # - ...
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True

        def parse_range(self) -> Optional[List[int]]:
            req_range = self.headers.get("range")
            if req_range is None:
                self.send_response_and_close(400)
                return None

            if req_range.startswith("bytes"):
                req_range = req_range[5:].strip()
                if req_range.startswith("="):
                    with contextlib.suppress(Exception):
                        values = req_range[1:].lstrip().split("-")
                        begin = int(values[0])
                        end = int(values[1])
                        if begin <= end < self.get_content_size():
                            return [begin, end - begin + 1]

            # Return error: "Range Not Satisfiable".
            self.send_response_and_close(416)
            return None

        def parse_content_range(self) -> Optional[List[int]]:
            req_range = self.headers.get("Content-Range")
            if req_range is None:
                self.send_response_and_close(400)
                return None

            if req_range.startswith("bytes"):
                req_range = req_range[5:].strip()
                with contextlib.suppress(Exception):
                    values = req_range.split("-")
                    begin = int(values[0])
                    end = int(values[1].split("/")[0].strip())
                    if begin <= end < self.get_content_size():
                        return [begin, end - begin + 1]

            # Return error: "Range Not Satisfiable".
            self.send_response_and_close(416)
            return None

        def _log_message(self, func: Callable[[str], None], message_format: str, *args: object) -> None:
            func(f"{self.address_string()} - - [{self.log_date_time_string()}] {message_format % args}\n")

        @override
        def log_message(self, format: str, *args: object) -> None:
            self._log_message(dprint, format, *args)

        @override
        def log_error(self, format: str, *args: object) -> None:
            # Hide closed connections on timeout, we still have other messages to understand
            # when there is really and issue. For example in `do_PUT`.
            func = dprint if format.startswith("Request timed out") else eprint
            self._log_message(func, format, *args)

        def do_HEAD(self) -> None:
            self.send_response(200)
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", str(self.get_content_size()))
            self.end_headers()

        def do_GET(self) -> None:
            req_range = self.parse_range()
            if not req_range:
                return

            offset = req_range[0]
            size = min(req_range[1], REQ_LIMIT_SIZE)

            try:
                dprint(f"GET [{self.client_address[0]}]: Read {size}B at {offset}.")
                chunk = pread(self.disk_fd, size, offset)
                if len(chunk) != size:
                    # Raise and close connection in case of short read, we must strictly avoid reusing it.
                    raise Exception(f"Short read ({len(chunk)}/{size} bytes)!")
            except Exception as e:
                eprint(f"Can't do GET: `{e}`.")
                self.send_response_and_close(500)
                return

            self.send_response(206)
            self.send_header("Content-Range", f"bytes {offset}-{offset + size - 1}/{self.get_content_size()}")
            self.send_header("Content-Length", str(int(size)))
            self.end_headers()

            self.wfile.write(chunk)

        def do_PUT(self) -> None:  # noqa: C901
            req_range = self.parse_content_range()
            if not req_range:
                return

            offset = req_range[0]
            size = req_range[1]

            chunk: Union[bytes, bytearray]
            try:
                encoding = self.headers.get("Transfer-Encoding")
                if encoding is not None:
                    if encoding != "chunked":
                        raise Exception(f"Unsupported encoding: `{encoding}`.")

                    chunk = bytearray()
                    while True:
                        chunk_size = int(self.rfile.readline().strip(), 16)
                        if not chunk_size:
                            # Consume empty line after chunk size, otherwise the next request
                            # of a persistent connection would start with garbage.
                            while self.rfile.readline().strip():
                                pass
                            break
                        chunk.extend(self.rfile.read(chunk_size))
                        self.rfile.readline()

                    if len(chunk) != size:
                        raise Exception("Inconsistent values between chunked data and content range size!")
                else:
                    chunk = self.rfile.read(size)
                    if len(chunk) < size:
                        raise Exception("Truncated chunk!")

                dprint(f"PUT [{self.client_address[0]}]: Write {len(chunk)}B at {offset}.")
                pwrite(self.disk_fd, chunk, offset)
                if self.is_block_device:
                    fcntl.ioctl(self.disk_fd, BLKFLSBUF)
                else:
                    os.fsync(self.disk_fd)
            except Exception as e:
                eprint(f"Can't do PUT: `{e}`.")
                self.send_response_and_close(500)
                return

            body = b"Ok."
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()

            # The client closed the connection too early, so we should ignore the error.
            with contextlib.suppress(BrokenPipeError):
                self.wfile.write(body)

    return RequestHandler

class HttpDiskServer(ThreadingMixIn, HTTPServer):
    def __init__(
        self, server_address: Tuple[str, int], request_handler_class: Type[BaseHTTPRequestHandler]
    ) -> None:
        # Reuse old port to avoid: "Address already in use".
        self.allow_reuse_address = True
        self.active_requests: Set[RequestType] = set()
        self.active_requests_lock = threading.Lock()
        HTTPServer.__init__(self, server_address, request_handler_class)
        self.ready_event = threading.Event()

    @override
    def process_request(self, request: RequestType, client_address: Tuple[str, int]) -> None:
        with self.active_requests_lock:
            self.active_requests.add(request)
        ThreadingMixIn.process_request(self, request, client_address)

    @override
    def shutdown_request(self, request: RequestType) -> None:
        with self.active_requests_lock:
            self.active_requests.discard(request)
        HTTPServer.shutdown_request(self, request)

    @override
    def server_close(self) -> None:
        # Connections are persistent: wake up and close the handlers waiting for a new request.
        with self.active_requests_lock:
            requests = list(self.active_requests)
        for request in cast(List[socket.socket], requests):
            with contextlib.suppress(Exception):
                request.shutdown(socket.SHUT_RDWR)

        if hasattr(ThreadingMixIn, "server_close"):
            ThreadingMixIn.server_close(self)
        else:
            # TODO(XCPNG-3919): Workaround for old python versions. Remove me later.
            # `server_close` is not available for python 3.6.
            HTTPServer.server_close(self)

    @override
    def serve_forever(self, poll_interval: float = 0.5) -> None:
        self.ready_event.set()
        HTTPServer.serve_forever(self, poll_interval)

    def wait_startup(self) -> None:
        self.ready_event.wait()

# ------------------------------------------------------------------------------

def run_server(disk: str, ip: str, port: int, client_timeout: float) -> None:  # noqa: C901
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
    starting_server = True

    def emit_server_ready() -> None:
        nonlocal starting_server
        if starting_server:
            eprint("Server ready!")
            starting_server = False

    httpd: Optional[HttpDiskServer] = None
    httpd_thread: Optional[threading.Thread] = None
    disk_fd: Optional[int] = None
    while True:
        if SIGTERM_EVENT.is_set():
            eprint("SIGTERM received. Exiting server...")
            break

        try:
            if starting_server:
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

            if SIGTERM_EVENT.is_set() or disk_fd is None:
                break

            is_block_device = stat.S_ISBLK(os.fstat(disk_fd).st_mode)

            httpd = HttpDiskServer(
                (ip or "", port),
                make_request_handler(disk_fd, is_block_device=is_block_device, client_timeout=client_timeout)
            )
            httpd_thread = threading.Thread(target=httpd.serve_forever)
            httpd_thread.start()

            if starting_server:
                httpd.wait_startup()
                # We emit only after effective startup.
                emit_server_ready()

            while not SIGTERM_EVENT.is_set():
                signal.pause()
        except KeyboardInterrupt:
            eprint("Exiting server...")
            break
        except Exception as e:
            eprint(f"Unhandled exception: `{e}`.")
            eprint(traceback.format_exc())
            eprint("Restarting server...")
            if not starting_server:
                time.sleep(1)
        finally:
            try:
                if httpd_thread:
                    assert httpd
                    httpd.shutdown()
                    httpd_thread.join()
                    httpd_thread = None
                if httpd:
                    httpd.server_close()
                    httpd = None
            except Exception as e:
                eprint(f"Failed to close server: {e}.")
            finally:
                close_device(disk_fd)

                # Make sure we notify for server startup if the device cannot be opened.
                # Or in case of exception during the first open call. It can be triggered
                # if we failed to open the volume due to concurrent DRBD calls.
                emit_server_ready()

# ==============================================================================

def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--disk", action="store", dest="disk", default=None, required=True,
        help="Device to share"
    )
    parser.add_argument(
        "--ip", action="store", dest="ip", type=str, default="", required=False,
        help="IP to use"
    )
    parser.add_argument(
        "--port", action="store", dest="port", type=int, default=8000, required=False,
        help="Port to use"
    )
    parser.add_argument(
        "--client-timeout", action="store", dest="client_timeout", type=float, default=DEFAULT_CLIENT_TIMEOUT,
        required=False,
        help="Close a client connection after this delay (in seconds) without received data"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", dest="verbose", default=False, required=False,
        help="Enable verbose logging"
    )

    args = parser.parse_args()
    LOG_CONFIG.prefix = "[" + Path(args.disk).resolve().name + "] "
    LOG_CONFIG.verbose = args.verbose
    try:
        signal.signal(signal.SIGTERM, handle_sigterm)
        run_server(args.disk, args.ip, args.port, args.client_timeout)
    except Exception as e:
        eprint(f"Got exception: `{e}`.")
        eprint(traceback.format_exc())
        exit(1)
