import ctypes
import io
import os
import random
import re
import signal
import socket
import string
import subprocess
import sys

import pytest

from tests import buffer

# ==============================================================================

WORKING_DIR = os.path.dirname(os.path.abspath(__file__)) + '/'

REG_NBD_PATH = re.compile("NBD `(/dev/nbd[0-9]+)` is now attached.$")

HTTP_PORT = '8080'

SECTOR_SIZE = 512
SECTOR_MASK = SECTOR_SIZE - 1

RANDOM_BUFFER_SIZE_KIB = 16 * 1024

# ==============================================================================
# Helpers.
# ==============================================================================

def generate_random_string(length):
    return ''.join(random.choice(string.ascii_letters) for i in range(length))

# ------------------------------------------------------------------------------

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
    assert isinstance(size_kib, int)

    random_buffer = bytearray()
    for i in range(size_kib):
        chunk = os.urandom(1024)
        random_buffer.extend(chunk)
    return random_buffer

def generate_aligned_buffer(size, alignment):
    assert isinstance(size, int)
    assert isinstance(alignment, int)

    buffer_size = size + (alignment - 1)
    buffer = bytearray(buffer_size)

    ctypes_buffer = (ctypes.c_char * buffer_size).from_buffer(buffer)
    buffer_address = ctypes.addressof(ctypes_buffer)

    offset = (alignment - buffer_address % alignment) % alignment

    aligned_buffer = (ctypes.c_char * (buffer_size - offset)).from_buffer(buffer, offset)
    assert ctypes.addressof(aligned_buffer) % alignment == 0
    return aligned_buffer

def generate_aligned_random_buffer(size_kib, alignment_b):
    random_buffer = generate_aligned_buffer(size_kib * 1024, alignment_b)
    for i in range(size_kib):
        random_buffer[i * 1024:(i + 1) * 1024] = os.urandom(1024)
    return random_buffer

# ------------------------------------------------------------------------------

def get_dmesg_output():
    p = subprocess.Popen(
        ['dmesg'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        universal_newlines=True
    )

    limit = 30
    lines = []
    while True:
        line = p.stdout.readline()
        if not line:
            break
        if len(lines) == limit:
            lines.pop(0)
        lines.append(line)

    return '\n'.join(lines)

# ------------------------------------------------------------------------------

def kill_server(server):
    if server:
        try:
            os.killpg(os.getpgid(server.pid), signal.SIGTERM)
            os.waitpid(server.pid, 0)
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
        preexec_fn=os.setsid,
        env=dict(os.environ, PYTHONUNBUFFERED='1')
    )

# ------------------------------------------------------------------------------

def start_nbd_server(volume_name, device_size):
    arguments = [
        WORKING_DIR + 'bin/nbd-http-server',
        '--socket-path',
        '/{}/{}.socket'.format(WORKING_DIR, volume_name),
        '--nbd-name',
        volume_name,
        '--urls',
        'http://{}:{}'.format(socket.gethostname(), HTTP_PORT),
        '--device-size',
        str(device_size)
    ]

    nbd_server = subprocess.Popen(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
        universal_newlines=True,
        env=dict(os.environ, PYTHONUNBUFFERED='1')
    )

    try:
        def get_nbd_path():
            while nbd_server.poll() is None:
                line = nbd_server.stdout.readline()
                match = REG_NBD_PATH.search(line)
                if match:
                    return match.group(1)
        nbd_path = timeout_call(30, get_nbd_path)
        if nbd_path is None:
            raise Exception('NBD path is empty!')
    except Exception:
        kill_server(nbd_server)
        print('Failed to get NBD path (dmesg): {}'.format(get_dmesg_output()))
        raise

    print('Used NBD path: `{}`.'.format(nbd_path))
    return (nbd_server, nbd_path)

# ==============================================================================
# Fixtures.
# ==============================================================================

class Device(object):
    __slots__ = ('_buffer', '_read_buffer', '_fd', '_capacity')

    def __init__(self, buffer, fd):
        self._buffer = buffer
        self._read_buffer = generate_aligned_random_buffer(len(buffer) // 1024, SECTOR_SIZE)
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
        expected_chunk = buffer(self._buffer, offset, count)
        self._check_read_unsafe(count, expected_chunk)

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

    def check_read_all(self):
        self.check_read(len(self._buffer), 0)

    def _check_read_unsafe(self, count, expected_chunk):
        buffer_view = self._get_read_buffer_view(count)
        read_count = self._read(self._fd, buffer_view)
        assert buffer(buffer_view, 0, read_count) == expected_chunk

    def _seek(self, offset):
        if offset > self._capacity:
            offset = self._capacity
        self._seek_unsafe(offset)
        return offset

    def _seek_unsafe(self, offset):
        os.lseek(self._fd, offset, os.SEEK_SET)

    def _get_read_buffer_view(self, count):
        return (ctypes.c_char * count).from_buffer(self._read_buffer)

    @staticmethod
    def _read(fd, buffer):
        with io.FileIO(fd, closefd=False) as fio:
            return fio.readinto(buffer)

class MirrorDevice(Device):
    __slots__ = ('_fd_mirror', )

    def __init__(self, device, fd_mirror):
        super(MirrorDevice, self).__init__(device._buffer, device._fd)
        self._fd_mirror = fd_mirror

    # Because O_DIRECT is used in mirroring mode, we must ensure buffer addrs,
    # sizes and offsets are correctly aligned.
    def check_read(self, count, offset):
        assert count & SECTOR_MASK == 0
        assert offset & SECTOR_MASK == 0
        super(MirrorDevice, self).check_read(count, offset)

    def check_write(self, chunk, offset):
        # Note: Assume chunk addr is correctly aligned.
        assert len(chunk) & SECTOR_MASK == 0
        assert offset & SECTOR_MASK == 0
        super(MirrorDevice, self).check_write(chunk, offset)

    def _check_read_unsafe(self, count, expected_chunk):
        assert count & SECTOR_MASK == 0
        buffer_view = self._get_read_buffer_view(count)
        assert ctypes.addressof(buffer_view) & SECTOR_MASK == 0

        read_count = self._read(self._fd, buffer_view)
        assert buffer(buffer_view, 0, read_count) == expected_chunk

        read_count = self._read(self._fd_mirror, buffer_view)
        assert buffer(buffer_view, 0, read_count) == expected_chunk

    def _seek_unsafe(self, offset):
        os.lseek(self._fd, offset, os.SEEK_SET)
        os.lseek(self._fd_mirror, offset, os.SEEK_SET)

# ------------------------------------------------------------------------------

def create_random_backing_file(request, open_flags):
    random_buffer = generate_random_buffer(size_kib=RANDOM_BUFFER_SIZE_KIB)

    http_server = None
    nbd_server = None
    fd = None
    backing_path = WORKING_DIR + 'image-' + generate_random_string(32) + '.bin'

    def clean():
        kill_server(nbd_server)
        kill_server(http_server)

        call_ignore(lambda: os.close(fd))
        call_ignore(lambda: os.remove(backing_path))

    try:
        with open(backing_path, 'wb') as f:
            f.write(random_buffer)

        http_server = start_http_server(backing_path)
        (nbd_server, nbd_path) = start_nbd_server('disk-test', RANDOM_BUFFER_SIZE_KIB * 1024)

        fd = os.open(nbd_path, open_flags)
    except Exception:
        clean()
        raise

    device = Device(random_buffer, fd)
    request.addfinalizer(clean)
    return device

@pytest.fixture(scope='class')
def random_backing_file(request):
    return create_random_backing_file(request, os.O_RDWR)

@pytest.fixture(scope='class')
def random_backing_file_with_o_direct(request):
    return create_random_backing_file(request, os.O_RDWR | os.O_DIRECT)

@pytest.fixture(scope='class')
def backing_file_mirror(request, random_backing_file_with_o_direct):
    nbd_server = None

    def clean():
        kill_server(nbd_server)

    try:
        (nbd_server, nbd_path) = start_nbd_server('disk-test-mirror', RANDOM_BUFFER_SIZE_KIB * 1024)
        fd = os.open(nbd_path, os.O_RDWR | os.O_DIRECT)
    except Exception:
        clean()
        raise

    device = MirrorDevice(random_backing_file_with_o_direct, fd)
    request.addfinalizer(clean)
    return device

@pytest.fixture(scope='class')
def aligned_buffer():
    return generate_aligned_buffer(RANDOM_BUFFER_SIZE_KIB * 1024, SECTOR_SIZE)
