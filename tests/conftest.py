from collections import namedtuple
import ctypes
import io
import os
from pathlib import Path
import random
import re
import shutil
import signal
import socket
import string
import subprocess
import sys
import tempfile
from types import FrameType

import pytest

from tests import buffer

from http_nbd_transfer.typing import Callable, List, NoReturn, Optional, override, Tuple, TypeVar, Union

T = TypeVar('T')

# ==============================================================================

REG_NBD_PATH = re.compile("NBD `(/dev/nbd[0-9]+)` is now attached.$")

SECTOR_SIZE = 512
SECTOR_MASK = SECTOR_SIZE - 1

RANDOM_BUFFER_SIZE_KIB = 16 * 1024

# ==============================================================================
# Helpers.
# ==============================================================================

def generate_random_string(length: int) -> str:
    return ''.join(random.choice(string.ascii_letters) for i in range(length))

# ------------------------------------------------------------------------------

class TimeoutException(Exception):
    pass

def timeout_call(timeoutseconds: int, function: Callable[..., T], *arguments: object) -> T:
    def handler(signum: int, frame: Optional[FrameType]) -> NoReturn:
        raise TimeoutException()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeoutseconds)
    try:
        return function(*arguments)
    finally:
        signal.alarm(0)

# ------------------------------------------------------------------------------

def call_ignore(fun: Callable[[], object]) -> None:
    try:
        fun()
    except Exception:
        pass

# ------------------------------------------------------------------------------

def generate_random_buffer(size_kib: int) -> bytearray:
    assert isinstance(size_kib, int)

    random_buffer = bytearray()
    for i in range(size_kib):
        chunk = os.urandom(1024)
        random_buffer.extend(chunk)
    return random_buffer

def generate_aligned_buffer(size: int, alignment: int) -> 'ctypes.Array[ctypes.c_char]':
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

def generate_aligned_random_buffer(size_kib: int, alignment_b: int) -> 'ctypes.Array[ctypes.c_char]':
    random_buffer = generate_aligned_buffer(size_kib * 1024, alignment_b)
    for i in range(size_kib):
        buffer(random_buffer, i * 1024, 1024)[:] = os.urandom(1024)
    return random_buffer

# ------------------------------------------------------------------------------

def get_dmesg_output() -> str:
    p = subprocess.Popen(
        ['dmesg'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        universal_newlines=True
    )
    assert p.stdout is not None

    limit = 30
    lines: List[str] = []
    while True:
        line = p.stdout.readline()
        if not line:
            break
        if len(lines) == limit:
            lines.pop(0)
        lines.append(line)

    return '\n'.join(lines)

# ------------------------------------------------------------------------------

def kill_server(server: Optional[subprocess.Popen]) -> None:
    if server:
        try:
            os.killpg(os.getpgid(server.pid), signal.SIGTERM)
            os.waitpid(server.pid, 0)
        except Exception as e:
            print('Failed to kill: `{}`.'.format(e))

# ------------------------------------------------------------------------------

def start_http_server(env: 'Env', backing_path: Path) -> subprocess.Popen:
    arguments = [
        env.bin_dir / 'http-disk-server',
        '--disk',
        backing_path,
        '--port',
        env.http_port
    ]

    return subprocess.Popen(
        arguments,
        stdout=sys.stdout,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
        env=dict(os.environ, PYTHONUNBUFFERED='1')
    )

# ------------------------------------------------------------------------------

def start_nbd_server(env: 'Env', volume_name: str, device_size: int) -> Tuple[subprocess.Popen, str]:
    arguments = [
        env.bin_dir / 'nbd-http-server',
        '--socket-path',
        env.work_dir / (volume_name + '.socket'),
        '--nbd-name',
        volume_name,
        '--urls',
        'http://{}:{}'.format(socket.gethostname(), env.http_port),
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
    nbd_server_stdout = nbd_server.stdout
    assert nbd_server_stdout is not None

    try:
        def get_nbd_path() -> Optional[str]:
            while nbd_server.poll() is None:
                line = nbd_server_stdout.readline()
                match = REG_NBD_PATH.search(line)
                if match:
                    return match.group(1)
            return None
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

Env = namedtuple('Env', ['bin_dir', 'http_port', 'work_dir'])

def pytest_addoption(parser: 'pytest.Parser') -> None:
    parser.addoption(
        '--bin-dir',
        default=None,
        help=(
            'directory of http-disk-server and nbd-http-server '
            '(default: `bin_dir` of pytest.ini)'
        )
    )
    parser.addoption(
        '--http-port',
        default=None,
        help='port of the HTTP server (default: `http_port` of pytest.ini)'
    )
    parser.addini(
        'bin_dir',
        'directory of http-disk-server and nbd-http-server, relative to pytest.ini'
    )
    parser.addini(
        'http_port',
        'port of the HTTP server',
        default='8080'
    )

def get_bin_dir(config: 'pytest.Config') -> Path:
    bin_dir = config.getoption('--bin-dir')
    if bin_dir:
        return Path(bin_dir)

    bin_dir = config.getini('bin_dir')
    if not bin_dir:
        raise pytest.UsageError('`bin_dir` is not set in pytest.ini, use --bin-dir')

    # The rootdir is the directory of pytest.ini. An absolute `bin_dir` is kept as is.
    return Path(str(config.rootdir)) / bin_dir

@pytest.fixture(scope='session')
def env(request: 'pytest.FixtureRequest') -> Env:
    # Private directory for the sockets and disk images, nothing is written next to the tests.
    work_dir = Path(tempfile.mkdtemp(prefix='http-nbd-transfer-'))
    request.addfinalizer(lambda: shutil.rmtree(work_dir, ignore_errors=True))

    return Env(
        bin_dir=get_bin_dir(request.config),
        http_port=request.config.getoption('--http-port') or request.config.getini('http_port'),
        work_dir=work_dir
    )

# ------------------------------------------------------------------------------

class Device:
    __slots__ = ('_buffer', '_read_buffer', '_fd', '_capacity')

    def __init__(self, buffer: bytearray, fd: int) -> None:
        self._buffer = buffer
        self._read_buffer = generate_aligned_random_buffer(len(buffer) // 1024, SECTOR_SIZE)
        self._fd = fd
        self._capacity = len(self._buffer)

    @property
    def capacity(self) -> int:
        return self._capacity

    def check_read(self, count: int, offset: int) -> None:
        offset = self._seek(offset)
        max_count = self._capacity - offset
        if count > max_count:
            count = max_count
        print('Device: Read {}B at {}.'.format(count, offset))
        expected_chunk = buffer(self._buffer, offset, count)
        self._check_read_unsafe(count, expected_chunk)

    def check_write(self, chunk: Union[bytes, memoryview], offset: int) -> None:
        offset = self._seek(offset)
        count = len(chunk)
        max_count = self._capacity - offset
        if count > max_count:
            count = max_count
            chunk = buffer(chunk, 0, count)
        print('Device: Write {}B at {}.'.format(count, offset))
        self._buffer[offset:offset + count] = chunk
        os.write(self._fd, chunk)

    def check_read_all(self) -> None:
        self.check_read(len(self._buffer), 0)

    def _check_read_unsafe(self, count: int, expected_chunk: memoryview) -> None:
        buffer_view = self._get_read_buffer_view(count)
        read_count = self._read(self._fd, buffer_view)
        assert buffer(buffer_view, 0, read_count) == expected_chunk

    def _seek(self, offset: int) -> int:
        if offset > self._capacity:
            offset = self._capacity
        self._seek_unsafe(offset)
        return offset

    def _seek_unsafe(self, offset: int) -> None:
        os.lseek(self._fd, offset, os.SEEK_SET)

    def _get_read_buffer_view(self, count: int) -> 'ctypes.Array[ctypes.c_char]':
        return (ctypes.c_char * count).from_buffer(self._read_buffer)

    @staticmethod
    def _read(fd: int, buffer: 'ctypes.Array[ctypes.c_char]') -> int:
        with io.FileIO(fd, closefd=False) as fio:
            return fio.readinto(buffer)

class MirrorDevice(Device):
    __slots__ = ('_fd_mirror', )

    def __init__(self, device: Device, fd_mirror: int) -> None:
        super().__init__(device._buffer, device._fd)
        self._fd_mirror = fd_mirror

    # Because O_DIRECT is used in mirroring mode, we must ensure buffer addrs,
    # sizes and offsets are correctly aligned.
    @override
    def check_read(self, count: int, offset: int) -> None:
        assert count & SECTOR_MASK == 0
        assert offset & SECTOR_MASK == 0
        super().check_read(count, offset)

    @override
    def check_write(self, chunk: Union[bytes, memoryview], offset: int) -> None:
        # Note: Assume chunk addr is correctly aligned.
        assert len(chunk) & SECTOR_MASK == 0
        assert offset & SECTOR_MASK == 0
        super().check_write(chunk, offset)

    @override
    def _check_read_unsafe(self, count: int, expected_chunk: memoryview) -> None:
        assert count & SECTOR_MASK == 0
        buffer_view = self._get_read_buffer_view(count)
        assert ctypes.addressof(buffer_view) & SECTOR_MASK == 0

        read_count = self._read(self._fd, buffer_view)
        assert buffer(buffer_view, 0, read_count) == expected_chunk

        read_count = self._read(self._fd_mirror, buffer_view)
        assert buffer(buffer_view, 0, read_count) == expected_chunk

    @override
    def _seek_unsafe(self, offset: int) -> None:
        os.lseek(self._fd, offset, os.SEEK_SET)
        os.lseek(self._fd_mirror, offset, os.SEEK_SET)

# ------------------------------------------------------------------------------

def create_random_backing_file(request: 'pytest.FixtureRequest', env: Env, open_flags: int) -> Device:
    random_buffer = generate_random_buffer(size_kib=RANDOM_BUFFER_SIZE_KIB)

    http_server = None
    nbd_server = None
    fd = None
    backing_path = env.work_dir / ('image-' + generate_random_string(32) + '.bin')

    def clean() -> None:
        kill_server(nbd_server)
        kill_server(http_server)

        if fd is not None:
            call_ignore(lambda: os.close(fd))
        call_ignore(lambda: backing_path.unlink())

    try:
        with open(backing_path, 'wb') as f:
            f.write(random_buffer)

        http_server = start_http_server(env, backing_path)
        (nbd_server, nbd_path) = start_nbd_server(env, 'disk-test', RANDOM_BUFFER_SIZE_KIB * 1024)

        fd = os.open(nbd_path, open_flags)
    except Exception:
        clean()
        raise

    device = Device(random_buffer, fd)
    request.addfinalizer(clean)
    return device

# ------------------------------------------------------------------------------

@pytest.fixture(scope='class')
def random_backing_file(request: 'pytest.FixtureRequest', env: Env) -> Device:
    return create_random_backing_file(request, env, os.O_RDWR)

@pytest.fixture(scope='class')
def random_backing_file_with_o_direct(request: 'pytest.FixtureRequest', env: Env) -> Device:
    return create_random_backing_file(request, env, os.O_RDWR | os.O_DIRECT)

@pytest.fixture(scope='class')
def backing_file_mirror(
    request: 'pytest.FixtureRequest', env: Env, random_backing_file_with_o_direct: Device
) -> 'MirrorDevice':
    nbd_server = None

    def clean() -> None:
        kill_server(nbd_server)

    try:
        (nbd_server, nbd_path) = start_nbd_server(env, 'disk-test-mirror', RANDOM_BUFFER_SIZE_KIB * 1024)
        fd = os.open(nbd_path, os.O_RDWR | os.O_DIRECT)
    except Exception:
        clean()
        raise

    device = MirrorDevice(random_backing_file_with_o_direct, fd)
    request.addfinalizer(clean)
    return device

@pytest.fixture(scope='class')
def aligned_buffer() -> 'ctypes.Array[ctypes.c_char]':
    return generate_aligned_buffer(RANDOM_BUFFER_SIZE_KIB * 1024, SECTOR_SIZE)
