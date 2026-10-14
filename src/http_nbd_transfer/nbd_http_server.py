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
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import traceback
from types import FrameType

from http_nbd_transfer.platform import EXEC_PATH_MODPROBE, EXEC_PATH_NBD_CLIENT, EXEC_PATH_NBDKIT
import http_nbd_transfer.process as process
from http_nbd_transfer.process import run_command

from http_nbd_transfer.typing import Callable, Iterator, List, NoReturn, Optional

# ==============================================================================

WORKING_DIR = Path(sys.argv[0]).absolute().parent
NBDKIT_PLUGIN = WORKING_DIR / ".." / "lib64" / "nbdkit" / "plugins" / "nbdkit-multi-http-plugin.so"

SIGTERM_EVENT = threading.Event()

def handle_sigterm(*_args: object) -> None:
    SIGTERM_EVENT.set()

# ------------------------------------------------------------------------------

def pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True

# ------------------------------------------------------------------------------

def remove_file(path: str) -> None:
    try:
        Path(path).unlink()
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise e

def run_or_ignore(fun: Callable[[], object]) -> None:
    with contextlib.suppress(Exception):
        fun()

# ------------------------------------------------------------------------------

THREAD_PRINT_LOCK = threading.Lock()

class LogConfig:
    prefix = ""
    verbose = False

LOG_CONFIG = LogConfig()

def thread_print(message: str) -> None:
    with THREAD_PRINT_LOCK:
        print(message)  # noqa: T201

def eprint(message: str) -> None:
    thread_print(LOG_CONFIG.prefix + message)

def dprint(message: str) -> None:
    if LOG_CONFIG.verbose:
        eprint(message)

# ==============================================================================

class SignalTimeoutError(Exception):
    def __init__(self) -> None:
        super().__init__("timeout")

@contextlib.contextmanager
def timeout(seconds: int) -> Iterator[None]:
    def handler(_signum: int, _frame: Optional[FrameType]) -> NoReturn:
        raise SignalTimeoutError

    old_handler = signal.signal(signal.SIGALRM, handler)

    try:
        signal.alarm(seconds)
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

# ==============================================================================

def get_nbd_pid(nbd_path: str) -> Optional[int]:
    stdout, _stderr, ret_code = run_command([EXEC_PATH_NBD_CLIENT, "-c", nbd_path], simple=False)
    if ret_code == 1:
        return None # Not connected.
    try:
        return int(stdout)
    except ValueError:
        return -1

def disconnect_nbd(nbd_path: str) -> None:
    run_command([EXEC_PATH_NBD_CLIENT, "-d", nbd_path], expected_ret_code=0)

class Nbd:
    __slots__ = ("name", "nbd")

    def __init__(self, nbd: str, name: str) -> None:
        self.nbd = nbd
        self.name = name

    def disconnect(self) -> None:
        try:
            disconnect_nbd("/dev/" + self.nbd)
        except Exception as e:
            eprint(f"Failed to disconnect NBD {self.nbd}: `{e}`.")

def attach_nbd(socket_path: str, nbd_name: str, pid_path: str) -> Nbd:  # noqa: C901
    def get_nbds() -> List[str]:
        return [path.name for path in Path("/dev").iterdir() if path.name.startswith("nbd")]

    nbds = get_nbds()
    if not nbds:
        run_command([EXEC_PATH_MODPROBE, "nbd"], expected_ret_code=0)
        nbds = get_nbds()
        if not nbds:
            raise Exception("No NBD available.")

    for nbd in nbds:
        nbd_path = "/dev/" + nbd

        # Open to check if the device is not mounted.
        try:
            fd = os.open(nbd_path, os.O_EXCL)
            os.close(fd)
        except Exception:
            continue

        # Ensure device is free.
        # Also we must do that, otherwise this error can be produced during the attach:
        # "Ioctl NBD_SET_SOCK failed: Device or resource busy"
        # And of course, this error kills our server.
        pid = get_nbd_pid(nbd_path)
        if pid is not None:
            if not pid_exists(pid):
                eprint(f"Potential leaked NBD device detected: `{nbd_path}` used by dead process {pid}.")
            continue

        # Use free device.
        try:
            # Use an extreme timeout here, should never be triggered.
            with timeout(30):
                run_command([EXEC_PATH_NBD_CLIENT, "-unix", socket_path, nbd_path, "-b", "512"], expected_ret_code=0)
        except Exception as e:
            # We guess we have to try another device after that: this exception is probably
            # caused by a concurrent attach and not with our nbdkit plugin.
            eprint(f"Failed to attach socket `{socket_path}` to {nbd_path}: `{e}`.")

            # Ensure the device is still free after failed command.
            # Note: a race condition exists when we try to release this device,
            # if the targeted pid is invalid. It can be used by another process.
            pid = None
            try:
                with Path(pid_path).open() as f:
                    pid = int(f.readline().strip("\n"))
            except Exception:
                continue
            finally:
                remove_file(pid_path)

            targeted_pid = get_nbd_pid(nbd_path)
            if (pid is not None and pid == targeted_pid) or (targeted_pid is not None and targeted_pid < 0):
                run_or_ignore(lambda: disconnect_nbd(nbd_path))

            continue

        # NBD is now attached, try to modify scheduler + return NBD object.
        eprint(f"NBD `{nbd_path}` is now attached.")
        try:
            (Path("/sys/block") / nbd / "queue" / "scheduler").write_text("none")
        except Exception as e:
            eprint(f"Failed to modify scheduler of {nbd_path}: `{e}`.")

        return Nbd(nbd, nbd_name)

    raise Exception(f"Cannot attach `{socket_path}` to NBD.")

def run_nbd_server(socket_path: str, nbd_name: str, urls: str, device_size: Optional[int]) -> None:  # noqa: C901
    pid_path = f"/var/run/nbd-{nbd_name}.pid"

    def clean_paths() -> None:
        remove_file(socket_path)
        remove_file(pid_path)

    clean_paths()

    arguments = [
        EXEC_PATH_NBDKIT,
        "--verbose",
        "--foreground",
        "-U", socket_path,
        "-e", nbd_name,
        "-P", pid_path,
        str(NBDKIT_PLUGIN),
        "urls=" + urls
    ]
    if device_size is not None:
        arguments.append("device-size=" + str(device_size))

    # Start nbdkit process.
    server = subprocess.Popen(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        env=dict(os.environ, PYTHONUNBUFFERED="1")
    )
    server_stdout = server.stdout
    assert server_stdout is not None

    # Wait for init.
    try:
        with timeout(10):
            while server.poll() is None:
                line = server_stdout.readline().rstrip("\n")
                if not line:
                    continue
                print(line)  # noqa: T201
                if "written pidfile" in line:
                    break
    except Exception as e:
        raise Exception(f"Failed to start nbdkit server: {e}.")

    # Continue to log server messages in stdout.
    def log_server_messages() -> None:
        nbdkit_log_prefix = r"nbdkit: multihttp\[\d+\]: debug: "
        verbose_keywords = (
            "pread",
            "pwrite"
        )
        verbose_pattern = re.compile(r"{}({})".format(nbdkit_log_prefix, "|".join(verbose_keywords)))

        while server.poll() is None:
            line = server_stdout.readline().rstrip("\n")
            if line:
                if verbose_pattern.match(line):
                    dprint(line)
                else:
                    thread_print(line)

    server_stdout_thread = threading.Thread(target=log_server_messages)
    server_stdout_thread.start()

    nbd = None

    try:
        nbd = attach_nbd(socket_path, nbd_name, pid_path)
        while True:
            try:
                if SIGTERM_EVENT.is_set():
                    eprint("SIGTERM received. Exiting server...")
                    break
                signal.pause()
            except KeyboardInterrupt:
                eprint("Exiting server...")
                break
    finally:
        if nbd:
            nbd.disconnect()
        server.send_signal(signal.SIGQUIT)
        server.wait()
        server_stdout_thread.join()
        clean_paths()

# ==============================================================================

def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--socket-path", action="store", dest="socket_path", default=None, required=True,
        help="UNIX socket path to use"
    )
    parser.add_argument(
        "--nbd-name", action="store", dest="nbd_name", default=None, required=True,
        help="NBD export name"
    )
    parser.add_argument(
        "--urls", action="store", dest="urls", default=None, required=True,
        help="URLS to read/write data"
    )
    parser.add_argument(
        "--device-size", action="store", dest="device_size", default=None, required=False, type=int,
        help="Force the device size, instead of using an HTTP server to get it"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", dest="verbose", default=False, required=False,
        help="Enable verbose logging"
    )

    args = parser.parse_args()
    LOG_CONFIG.prefix = "[" + args.nbd_name + "] "
    LOG_CONFIG.verbose = args.verbose
    process.LOG_FUNCTION = eprint
    try:
        signal.signal(signal.SIGTERM, handle_sigterm)
        run_nbd_server(args.socket_path, args.nbd_name, args.urls, args.device_size)
    except Exception as e:
        eprint(f"Got exception: `{e}`.")
        eprint(traceback.format_exc())
        exit(1)
