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

from contextlib import contextmanager
import argparse
import errno
import os
import signal
import subprocess
import sys
import threading

WORKING_DIR = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), '')
NBDKIT_PLUGIN = WORKING_DIR + '../lib64/nbdkit/plugins/nbdkit-multi-http-plugin.so'

# ==============================================================================

OUTPUT_PREFIX = ''

SIGTERM_RECEIVED = False

def handle_sigterm(*args):
    global SIGTERM_RECEIVED
    SIGTERM_RECEIVED = True

# -----------------------------------------------------------------------------

def pid_exists(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True

# -----------------------------------------------------------------------------

def remove_file(path):
    try:
        os.remove(path)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise e

def run_or_ignore(fun):
    try:
        fun()
    except Exception:
        pass

# -----------------------------------------------------------------------------

THREAD_PRINT_LOCK = threading.Lock()

VERBOSE = False

def thread_print(str):
    with THREAD_PRINT_LOCK:
        print(str)

def eprint(str):
    thread_print(OUTPUT_PREFIX + str)

def dprint(str):
    if VERBOSE:
        print(OUTPUT_PREFIX + str, file=sys.stderr)

# -----------------------------------------------------------------------------

class CommandException(Exception):
    def __init__(self, code, cmd, stdout, stderr):
        self.code = code
        self.cmd = cmd
        self.stdout = stdout
        self.stderr = stderr
        Exception.__init__(self, os.strerror(abs(code)))

    def __str__(self):
        return 'Command exception: `{}` (code: `{}`, reason: `{}`)'.format(
            self.cmd, self.code, self.stderr
        )

def call(cmd, expected_returncode=0):
    dprint('Call command: {}'.format(cmd))
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        universal_newlines=True
    )

    stdout, stderr = p.communicate()

    if p.returncode != expected_returncode:
        raise CommandException(p.returncode, str(cmd), stdout.strip(), stderr.strip())
    return stdout

# ==============================================================================

class TimeoutException(Exception):
    def __init__(self):
        super(Exception, self).__init__('timeout')

@contextmanager
def timeout(seconds):
    def handler(signum, frame):
        raise TimeoutException

    old_handler = signal.signal(signal.SIGALRM, handler)

    try:
        signal.alarm(seconds)
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

# ==============================================================================

def get_nbd_pid(nbd_path):
    try:
        call(['nbd-client', '-c', nbd_path], expected_returncode=1)
    except CommandException as e:
        try:
            return int(e.stdout)
        except ValueError:
            return -1
    return None

def disconnect_nbd(nbd_path):
    call(['nbd-client', '-d', nbd_path])

class Nbd:
    __slots__ = ('name', 'nbd')

    def __init__(self, nbd, name):
        self.nbd = nbd
        self.name = name

    def disconnect(self):
        try:
            disconnect_nbd('/dev/' + self.nbd)
        except Exception as e:
            eprint('Failed to disconnect NBD {}: `{}`.'.format(self.nbd, e))

def attach_nbd(socket_path, nbd_name, pid_path):
    def get_nbds():
        return list(filter(lambda nbd: nbd.startswith('nbd'), os.listdir('/dev')))

    nbds = get_nbds()
    if not nbds:
        call(['modprobe', 'nbd'])
        nbds = get_nbds()
        if not nbds:
            raise Exception('No NBD available.')

    for nbd in nbds:
        nbd_path = '/dev/' + nbd

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
                eprint(
                    'Potential leaked NBD device detected: `{}` used by dead process {}'
                    .format(nbd_path, pid)
                )
            continue

        # Use free device.
        try:
            # Use an extreme timeout here, should never be triggered.
            with timeout(30):
                call(['nbd-client', '-unix', socket_path, nbd_path, '-b', '512'])
        except Exception as e:
            # We guess we have to try another device after that: this exception is probably
            # caused by a concurrent attach and not with our nbdkit plugin.
            eprint('Failed to attach socket `{}` to {}: {}.'.format(socket_path, nbd_path, e))

            # Ensure the device is still free after failed command.
            # Note: a race condition exists when we try to release this device,
            # if the targeted pid is invalid. It can be used by another process.
            pid = None
            try:
                with open(pid_path) as f:
                    pid = int(f.readline().strip('\n'))
            except Exception:
                continue
            finally:
                remove_file(pid_path)

            targeted_pid = get_nbd_pid(nbd_path)
            if (pid is not None and pid == targeted_pid) or (targeted_pid is not None and targeted_pid < 0):
                run_or_ignore(lambda: disconnect_nbd(nbd_path))

            continue

        # NBD is now attached, try to modify scheduler + return NBD object.
        dprint('NBD `{}` is now attached.'.format(nbd_path))
        try:
            with open('/sys/block/' + nbd + '/queue/scheduler', 'w') as fd:
                fd.write('none')
        except Exception as e:
            eprint('Failed to modify scheduler of {}: `{}`.'.format(nbd_path, e))

        return Nbd(nbd, nbd_name)

    raise Exception('Cannot attach `{}` to NBD.'.format(socket_path))

def run_nbd_server(socket_path, nbd_name, urls, device_size):
    pid_path = '/var/run/nbd-{}.pid'.format(nbd_name)

    def clean_paths():
        remove_file(socket_path)
        remove_file(pid_path)

    clean_paths()

    arguments = [
        'nbdkit',
        '--verbose',
        '--foreground',
        '-U', socket_path,
        '-e', nbd_name,
        '-P', pid_path,
        NBDKIT_PLUGIN,
        'urls=' + urls
    ]
    if device_size is not None:
        arguments.append('device-size=' + str(device_size))

    # Start nbdkit process.
    server = subprocess.Popen(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        env=dict(os.environ, PYTHONUNBUFFERED='1')
    )

    # Wait for init.
    try:
        with timeout(10):
            while server.poll() is None:
                line = server.stdout.readline().rstrip('\n')
                if not line:
                    continue
                print(line)
                if 'written pidfile' in line:
                    break
    except Exception as e:
        raise Exception('Failed to start nbdkit server: {}.'.format(e))

    # Continue to log server messages in stdout.
    def log_server_messages():
        while server.poll() is None:
            line = server.stdout.readline().rstrip('\n')
            if line:
                thread_print(line)

    server_stdout_thread = threading.Thread(target=log_server_messages)
    server_stdout_thread.start()

    nbd = None

    try:
        nbd = attach_nbd(socket_path, nbd_name, pid_path)
        while True:
            try:
                if SIGTERM_RECEIVED:
                    dprint('SIGTERM received. Exiting server...')
                    break
                signal.pause()
            except KeyboardInterrupt:
                dprint('Exiting server...')
                break
    finally:
        if nbd:
            nbd.disconnect()
        server.send_signal(signal.SIGQUIT)
        server.wait()
        server_stdout_thread.join()
        clean_paths()

# ==============================================================================

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--socket-path', action='store', dest='socket_path', default=None, required=True,
        help='UNIX socket path to use'
    )
    parser.add_argument(
        '--nbd-name', action='store', dest='nbd_name', default=None, required=True,
        help='NBD export name'
    )
    parser.add_argument(
        '--urls', action='store', dest='urls', default=None, required=True,
        help='URLS to read/write data'
    )
    parser.add_argument(
        '--device-size', action='store', dest='device_size', default=None, required=False, type=int,
        help='Force the device size, instead of using an HTTP server to get it'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true', dest='verbose', type=bool, default=False, required=False,
        help='Enable verbose logging'
    )

    args = parser.parse_args()
    global OUTPUT_PREFIX
    OUTPUT_PREFIX = '[' + args.nbd_name + '] '
    global VERBOSE
    VERBOSE = args.verbose
    try:
        signal.signal(signal.SIGTERM, handle_sigterm)
        run_nbd_server(args.socket_path, args.nbd_name, args.urls, args.device_size)
    except Exception as e:
        eprint('Got exception: `{}`.'.format(e))
        exit(1)

if __name__ == '__main__':
    main()
