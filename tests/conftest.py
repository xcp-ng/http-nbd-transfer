import os
import re
import signal
import socket
import subprocess
import sys

import pytest

# ==============================================================================

WORKING_DIR = os.path.dirname(os.path.abspath(__file__)) + '/'

REG_NBD_PATH = re.compile("^NBD `(/dev/nbd[0-9]+)` is now attached.$")

HTTP_PORT = '8080'

# ==============================================================================
# Helpers.
# ==============================================================================

class TimeoutException(Exception):
    pass

def timeout_call(timeoutseconds, function, *arguments):
    def handler(signum, frame):
        raise TimeoutException()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeoutseconds)
    try:
        return function(*arguments)
    finally:
        signal.alarm(0)

# ------------------------------------------------------------------------------

def call_ignore(fun):
    try:
        fun()
    except Exception:
        pass

# ------------------------------------------------------------------------------

def generate_random_buffer(size_kib):
    random_buffer = bytearray()
    for i in range(size_kib):
        chunk = os.urandom(1024)
        random_buffer.extend(chunk)
    return random_buffer

# ------------------------------------------------------------------------------

def kill_server(server):
    if server:
        try:
            os.killpg(os.getpgid(server.pid), signal.SIGTERM)
        except Exception as e:
            print('Failed to kill: `{}`.'.format(e))

# ------------------------------------------------------------------------------

def start_http_server(backing_path):
    arguments = [
        WORKING_DIR + 'bin/http-disk-server',
        '--disk',
        backing_path,
        '--port',
        HTTP_PORT
    ]

    return subprocess.Popen(
        arguments,
        stdout=sys.stdout,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid
    )

# ------------------------------------------------------------------------------

def start_nbd_server(volume_name):
    arguments = [
        WORKING_DIR + 'bin/nbd-http-server',
        '--socket-path',
        '/{}/{}.socket'.format(WORKING_DIR, volume_name),
        '--nbd-name',
        volume_name,
        '--urls',
        'http://{}:{}'.format(socket.gethostname(), HTTP_PORT)
    ]

    nbd_server = subprocess.Popen(
        arguments,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        preexec_fn=os.setsid
    )

    try:
        def get_nbd_path():
            while nbd_server.poll() is None:
                line = nbd_server.stdout.readline()
                match = REG_NBD_PATH.match(line)
                if match:
                    return match.group(1)
        nbd_path = timeout_call(10, get_nbd_path)
        if nbd_path is None:
            raise Exception('NBD path is empty!')
    except Exception:
        kill_server(nbd_server)
        raise

    print('Used NBD path: `{}`.'.format(nbd_path))
    return (nbd_server, nbd_path)

# ==============================================================================
# Fixtures.
# ==============================================================================

class Device(object):
    __slots__ = ('_buffer', '_fd', '_capacity')

    def __init__(self, buffer, fd):
        self._buffer = buffer
        self._fd = fd
        self._capacity = len(self._buffer)

    @property
    def capacity(self):
        return self._capacity

    def check_read(self, count, offset):
        offset = self._seek(offset)
        max_count = self._capacity - offset
        if count > max_count:
            count = max_count
        print('Device: Read {}B at {}.'.format(count, offset))
        chunk = os.read(self._fd, count)
        expected_chunk = buffer(self._buffer, offset, count)
        assert buffer(chunk, 0, len(chunk)) == expected_chunk

    def check_read_all(self):
        self.check_read(len(self._buffer), 0)

    def check_write(self, chunk, offset):
        offset = self._seek(offset)
        count = len(chunk)
        max_count = self._capacity - offset
        if count > max_count:
            count = max_count
            chunk = buffer(chunk, 0, count)
        print('Device: Write {}B at {}.'.format(count, offset))
        self._buffer[offset:offset + count] = chunk
        os.write(self._fd, chunk)

    def _seek(self, offset):
        if offset > self._capacity:
            offset = self._capacity
        os.lseek(self._fd, offset, os.SEEK_SET)
        return offset

# ------------------------------------------------------------------------------

@pytest.fixture(scope='class')
def random_backing_file(request):
    random_buffer = generate_random_buffer(size_kib=16 * 1024)

    http_server = None
    nbd_server = None
    fd = None
    backing_path = WORKING_DIR + 'image.bin'

    def clean():
        kill_server(nbd_server)
        kill_server(http_server)

        call_ignore(lambda: os.close(fd))
        call_ignore(lambda: os.remove(backing_path))

    try:
        with open(backing_path, 'wb') as f:
            f.write(random_buffer)

        http_server = start_http_server(backing_path)
        (nbd_server, nbd_path) = start_nbd_server('disk-test')

        fd = os.open(nbd_path, os.O_RDWR | os.O_SYNC)
    except Exception:
        clean()
        raise

    device = Device(random_buffer, fd)
    request.addfinalizer(clean)
    return device
